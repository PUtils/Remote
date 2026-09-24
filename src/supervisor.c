#define __STDC_WANT_LIB_EXT1__ 1
#include "rt.h"
#include "web.h"

#include <CommonCrypto/CommonDigest.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define MAX_WEB 16
#define MAX_TOKENS 8
#define MAX_GROUPS 16
#define TOKEN_TTL (12 * 3600)

struct conn {
    pid_t pid;
    int sup;
    int authed;
    int killing;
    time_t start, kill_at;
    char info[100];
    int web;
    unsigned char sid[16];
    pid_t groups[MAX_GROUPS];
    int ngroups;
};

struct web {
    int fd;
    size_t len;
    time_t start;
    char buf[8192];
};

struct token {
    unsigned char v[32];
    time_t exp;
};

enum tunnel_kind { T_RELAY, T_CF_SSH, T_PANEL };

struct tunnel {
    enum tunnel_kind kind;
    char url_arg[64];
    pid_t pid, probe;
    int fd;
    size_t len;
    time_t restart_at;
    int fails, warned;
    char buf[4096];
    char url[256];
};

static struct config *cfg;
static struct pwhash *pw;
static struct conn conns[RT_MAX_CONNS];
static struct web webs[MAX_WEB];
static struct token tokens[MAX_TOKENS];
static struct tunnel tunnels[3];
static int ntunnels;
static char join_plain[256], join_cf[256];

static void probe_start(struct tunnel *t);
static int hib, fails;
static time_t next_try, locked_until;
static int sigp[2];
static volatile sig_atomic_t stopping;

void logmsg(const char *fmt, ...)
{
    char ts[16];
    time_t now = time(NULL);
    strftime(ts, sizeof ts, "%H:%M:%S", localtime(&now));
    fprintf(stderr, "rt %s  ", ts);
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

static void cloexec(int fd)
{
    fcntl(fd, F_SETFD, FD_CLOEXEC);
}

static void on_signal(int sig)
{
    int e = errno;
    if (sig != SIGCHLD)
        stopping = 1;
    write(sigp[1], "s", 1);
    errno = e;
}

enum { AUTH_OK, AUTH_BAD, AUTH_WAIT };

static long wait_left(void)
{
    time_t now = time(NULL), until = locked_until > next_try ? locked_until : next_try;
    return until > now ? (long)(until - now) : 0;
}

static int check_password(const char *p, size_t len, const char *via)
{
    if (wait_left() > 0)
        return AUTH_WAIT;
    char tmp[1025];
    if (len >= sizeof tmp)
        len = sizeof tmp - 1;
    memcpy(tmp, p, len);
    tmp[len] = '\0';
    int ok = pw_check(pw, tmp);
    memset_s(tmp, sizeof tmp, 0, sizeof tmp);

    time_t now = time(NULL);
    if (ok) {
        if (fails)
            logmsg("%s login (after %d wrong password%s)", via, fails, fails == 1 ? "" : "s");
        else
            logmsg("%s login", via);
        fails = 0;
        next_try = locked_until = 0;
        return AUTH_OK;
    }
    fails++;
    if (fails >= 10) {
        locked_until = now + 15 * 60;
        logmsg("%s: wrong password (%d in a row), locked for 15 minutes", via, fails);
    } else {
        if (fails >= 3)
            next_try = now + (fails - 3 < 6 ? 1 << (fails - 3) : 60);
        logmsg("%s: wrong password (%d in a row)", via, fails);
    }
    return AUTH_BAD;
}

/* ---- connections ---- */

static void kill_conn(struct conn *c)
{
    if (c->pid <= 0 || c->killing)
        return;
    kill(c->pid, SIGTERM);
    for (int i = 0; i < c->ngroups; i++)
        killpg(c->groups[i], SIGHUP);
    c->killing = 1;
    c->kill_at = time(NULL) + 3;
}

static void kill_all(void)
{
    for (int i = 0; i < RT_MAX_CONNS; i++)
        kill_conn(&conns[i]);
}

static void accept_ssh(int lfd)
{
    int fd = accept(lfd, NULL, NULL);
    if (fd < 0)
        return;
    cloexec(fd);
    struct conn *c = NULL;
    for (int i = 0; i < RT_MAX_CONNS && !c; i++)
        if (conns[i].pid == 0)
            c = &conns[i];
    int sp[2];
    if (hib || !c || socketpair(AF_UNIX, SOCK_DGRAM, 0, sp) != 0) {
        close(fd);
        return;
    }
    cloexec(sp[0]);
    cloexec(sp[1]);
    pid_t pid = fork();
    if (pid == 0) {
        setsid();
        int a = fcntl(fd, F_DUPFD, 10), b = fcntl(sp[1], F_DUPFD, 10);
        dup2(a, 3);
        dup2(b, 4);
        char *argv[] = {"rt", "--conn", cfg->hostkey, cfg->keys[0] ? cfg->keys : "-",
                        cfg->sbhome, cfg->state, NULL};
        execv(cfg->self, argv);
        _exit(127);
    }
    close(fd);
    close(sp[1]);
    if (pid < 0) {
        close(sp[0]);
        return;
    }
    fcntl(sp[0], F_SETFL, O_NONBLOCK);
    memset(c, 0, sizeof *c);
    c->pid = pid;
    c->sup = sp[0];
    c->start = time(NULL);
    strlcpy(c->info, "logging in", sizeof c->info);
}

static void conn_message(struct conn *c)
{
    char m[1200];
    ssize_t n = recv(c->sup, m, sizeof m - 1, 0);
    if (n <= 0)
        return;
    m[n] = '\0';
    switch (m[0]) {
    case 'P': {
        char r[PATH_MAX + 8];
        int res = hib ? AUTH_BAD : check_password(m + 1, (size_t)n - 1, "ssh");
        size_t rl;
        if (hib) {
            rl = strlcpy(r, "H", sizeof r);
        } else if (res == AUTH_OK) {
            c->authed = 1;
            strlcpy(c->info, "connected", sizeof c->info);
            rl = (size_t)snprintf(r, sizeof r, "O%c%s", cfg->sandbox ? '1' : '0', cfg->dir);
        } else {
            rl = strlcpy(r, res == AUTH_WAIT ? "W" : "N", sizeof r);
        }
        send(c->sup, r, rl, 0);
        break;
    }
    case 'I': {
        size_t j = 0;
        for (size_t i = 1; m[i] && j < sizeof c->info - 1; i++)
            c->info[j++] = (m[i] >= 0x20 && m[i] < 0x7f) ? m[i] : '?';
        c->info[j] = '\0';
        break;
    }
    case 'G':
        if (c->ngroups < MAX_GROUPS)
            c->groups[c->ngroups++] = (pid_t)atoi(m + 1);
        break;
    case 'g': {
        pid_t g = (pid_t)atoi(m + 1);
        for (int i = 0; i < c->ngroups; i++)
            if (c->groups[i] == g)
                c->groups[i] = c->groups[--c->ngroups];
        break;
    }
    }
    memset_s(m, sizeof m, 0, sizeof m);
}

static void hibernate(int on, const char *via)
{
    if (hib == on)
        return;
    hib = on;
    if (on)
        kill_all();
    logmsg("%s via %s", on ? "hibernating, sessions closed" : "awake", via);
}

/* ---- tunnels ---- */

#define RELAY_HOST "ssh-j.com"
#define RELAY_TARGET "mac"

static void relay_opts(char **a, int *n, char *kh)
{
    static char khopt[PATH_MAX + 32];
    snprintf(khopt, sizeof khopt, "UserKnownHostsFile=%s", kh);
    const char *opts[] = {"BatchMode=yes", "ExitOnForwardFailure=yes", "ServerAliveInterval=30",
                          "ServerAliveCountMax=3", "ConnectTimeout=20",
                          "StrictHostKeyChecking=accept-new", khopt, "IdentityAgent=none",
                          "PubkeyAuthentication=no", "LogLevel=ERROR", NULL};
    a[(*n)++] = "/usr/bin/ssh";
    a[(*n)++] = "-F";
    a[(*n)++] = "/dev/null";
    for (int i = 0; opts[i]; i++) {
        a[(*n)++] = "-o";
        a[(*n)++] = (char *)opts[i];
    }
}

static void tunnel_start(struct tunnel *t)
{
    int p[2];
    if (pipe(p) != 0)
        return;
    cloexec(p[0]);
    pid_t pid = fork();
    if (pid == 0) {
        setsid();
        dup2(p[1], 1);
        dup2(p[1], 2);
        int null = open("/dev/null", O_RDONLY);
        dup2(null, 0);
        if (t->kind == T_RELAY) {
            char *a[40], fwd[128], dest[128];
            int n = 0;
            relay_opts(a, &n, cfg->relay_kh);
            snprintf(fwd, sizeof fwd, RELAY_TARGET ":22:%s", t->url_arg);
            snprintf(dest, sizeof dest, "%s@" RELAY_HOST, cfg->relay);
            a[n++] = "-N";
            a[n++] = "-R";
            a[n++] = fwd;
            a[n++] = dest;
            a[n] = NULL;
            execv(a[0], a);
        } else {
            execlp("cloudflared", "cloudflared", "tunnel", "--no-autoupdate", "--url",
                   t->url_arg, (char *)NULL);
        }
        _exit(127);
    }
    close(p[1]);
    if (pid < 0) {
        close(p[0]);
        return;
    }
    fcntl(p[0], F_SETFL, O_NONBLOCK);
    t->pid = pid;
    t->fd = p[0];
    t->len = 0;
    t->buf[0] = '\0';
    t->url[0] = '\0';
    if (t->kind == T_RELAY) {
        /* The relay address is fixed, so there is nothing to wait for in the output. */
        snprintf(t->url, sizeof t->url, "%s", cfg->relay);
        probe_start(t);
    }
}

/* Runs argv and reports whether its output contains want within secs. */
static int run_expect(char *const argv[], const char *want, int secs)
{
    int in[2], out[2];
    if (pipe(in) != 0)
        return 0;
    if (pipe(out) != 0) {
        close(in[0]);
        close(in[1]);
        return 0;
    }
    pid_t pid = fork();
    if (pid == 0) {
        dup2(in[0], 0);
        dup2(out[1], 1);
        dup2(out[1], 2);
        for (int fd = 3, max = getdtablesize(); fd < max; fd++)
            close(fd);
        execvp(argv[0], argv);
        _exit(127);
    }
    close(in[0]);
    close(out[1]);
    char buf[4096];
    size_t len = 0;
    int found = 0;
    time_t end = time(NULL) + secs;
    while (pid > 0 && !found && time(NULL) < end) {
        struct pollfd p = {out[0], POLLIN, 0};
        if (poll(&p, 1, 500) <= 0)
            continue;
        ssize_t n = read(out[0], buf + len, sizeof buf - 1 - len);
        if (n <= 0)
            break;
        len += (size_t)n;
        buf[len] = '\0';
        found = strstr(buf, want) != NULL;
        if (len > sizeof buf - 512) {
            memmove(buf, buf + len - 64, 64);
            len = 64;
        }
    }
    if (pid > 0) {
        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
    }
    close(in[1]);
    close(out[0]);
    return found;
}

/*
 * Checks a tunnel end to end before its address is shown. A quick tunnel's
 * name also reaches public DNS a few seconds after cloudflared prints it, and
 * a client that looks it up too early caches the miss.
 */
static int probe(const struct tunnel *t)
{
    char *check[40];
    const char *want = "SSH-2.0";
    if (t->kind == T_RELAY) {
        static char target[128], dest[128];
        int n = 0;
        relay_opts(check, &n, cfg->relay_kh);
        snprintf(target, sizeof target, RELAY_TARGET ":22");
        snprintf(dest, sizeof dest, "%s@" RELAY_HOST, cfg->relay);
        check[n++] = "-W";
        check[n++] = target;
        check[n++] = dest;
        check[n] = NULL;
    } else {
        char *host = (char *)t->url + strlen("https://");
        char *dig[] = {"dig", "+short", "+time=2", "+tries=1", host, "@1.1.1.1", "A", NULL};
        int resolved = 0;
        for (int i = 0; i < 45 && !resolved; i++)
            if (!(resolved = run_expect(dig, ".", 5)))
                sleep(2);
        if (!resolved)
            return 2;
        char *ssh[] = {"cloudflared", "access", "ssh", "--hostname", host, NULL};
        char *web[] = {"curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "10",
                       (char *)t->url, NULL};
        char **src = t->kind == T_CF_SSH ? ssh : web;
        int i = 0;
        do
            check[i] = src[i];
        while (src[i++]);
        if (t->kind == T_PANEL)
            want = "200";
    }
    for (int i = 0; i < 8; i++) {
        if (run_expect(check, want, 12))
            return 0;
        sleep(3);
    }
    return 3;
}

static void probe_start(struct tunnel *t)
{
    pid_t pid = fork();
    if (pid == 0) {
        setsid();
        for (int sig = 1; sig < NSIG; sig++)
            signal(sig, SIG_DFL);
        _exit(probe(t));
    }
    t->probe = pid > 0 ? pid : 0;
}

static void announce(struct tunnel *t, int ok)
{
    const char *state = ok ? "ready" : "not confirmed yet (it may need a minute)";
    if (t->kind == T_PANEL) {
        logmsg("phone panel %s: %s", state, t->url);
        return;
    }
    if (t->kind == T_CF_SSH) {
        snprintf(join_cf, sizeof join_cf,
                 "ssh -o \"ProxyCommand=cloudflared access ssh --hostname %%h\" %s",
                 t->url + strlen("https://"));
        logmsg("cloudflare route %s, for computers with cloudflared:\n\n    %s\n", state, join_cf);
        return;
    }
    if (ok)
        t->fails = t->warned = 0;
    snprintf(join_plain, sizeof join_plain, "ssh -J %s@" RELAY_HOST " " RELAY_TARGET, cfg->relay);
    logmsg("%s. Join from any computer with plain ssh:", state);
    fprintf(stderr,
            "\n    %s\n\n"
            "    The first time, ssh asks to trust two keys: " RELAY_HOST "'s (the public relay)\n"
            "    and this Mac's, which must be %s\n"
            "    \"administratively prohibited\" means the name %s was mistyped or rt is not running.\n\n"
            "    To let agents reuse one login, put this in ~/.ssh/config and run `ssh mac`:\n"
            "      Host mac\n"
            "        HostName " RELAY_TARGET "\n"
            "        ProxyJump %s@" RELAY_HOST "\n"
            "        ControlMaster auto\n"
            "        ControlPath ~/.ssh/cm-%%C\n"
            "        ControlPersist 4h\n\n",
            join_plain, cfg->fingerprint, cfg->relay, cfg->relay);
}

static void tunnel_read(struct tunnel *t)
{
    ssize_t n = read(t->fd, t->buf + t->len, sizeof t->buf - 1 - t->len);
    if (n <= 0) {
        if (n == 0 || errno != EAGAIN) {
            close(t->fd);
            t->fd = -1;
        }
        return;
    }
    /* Keep the relay's own messages so a failure can be explained. */
    if (t->url[0] && t->kind != T_RELAY) {
        t->len = 0;
        return;
    }
    t->len += (size_t)n;
    t->buf[t->len] = '\0';
    char *e = strstr(t->buf, ".trycloudflare.com"), *s = e;
    while (s && s > t->buf && (isalnum((unsigned char)s[-1]) || s[-1] == '-'))
        s--;
    if (e && s - t->buf >= 8 && strncmp(s - 8, "https://", 8) == 0 && s < e) {
        s -= 8;
        e += strlen(".trycloudflare.com");
        snprintf(t->url, sizeof t->url, "%.*s", (int)(e - s), s);
        probe_start(t);
        t->len = 0;
    } else if (t->len > sizeof t->buf / 2) {
        memmove(t->buf, t->buf + t->len - 256, 256);
        t->len = 256;
    }
}

/* ---- web panel ---- */

static const char sec_headers[] =
    "X-Content-Type-Options: nosniff\r\n"
    "Referrer-Policy: no-referrer\r\n"
    "Connection: close\r\n";

/* The Host of the request being answered, when it is safe to echo into CSP. */
static char req_host[256];

static void send_all(int fd, const char *p, size_t len)
{
    while (len > 0) {
        ssize_t n = write(fd, p, len);
        if (n <= 0)
            return;
        p += n;
        len -= (size_t)n;
    }
}

static void respond_ex(int fd, int code, const char *type, const char *extra,
                       const void *body, size_t blen, const char *style_src)
{
    char csp[768];
    snprintf(csp, sizeof csp,
             "Content-Security-Policy: default-src 'none'; script-src 'self'; style-src %s; "
             "connect-src 'self'%s%s%s%s; img-src 'self' data:; font-src 'self'; "
             "frame-ancestors 'none'; base-uri 'none'; form-action 'none'\r\n",
             style_src, req_host[0] ? " wss://" : "", req_host, req_host[0] ? " ws://" : "",
             req_host);
    const char *reason = code == 200 ? "OK" : code == 400 ? "Bad Request" : code == 401 ? "Unauthorized"
                       : code == 403 ? "Forbidden" : code == 404 ? "Not Found"
                       : code == 409 ? "Conflict" : code == 413 ? "Payload Too Large"
                       : code == 429 ? "Too Many Requests" : code == 503 ? "Service Unavailable" : "Error";
    char head[2048];
    int hl = snprintf(head, sizeof head,
                      "HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %zu\r\n%s%s%s%s\r\n",
                      code, reason, type, blen, csp, sec_headers,
                      strncmp(type, "font/", 5) == 0 ? "Cache-Control: public, max-age=604800\r\n"
                                                     : "Cache-Control: no-store\r\n",
                      extra ? extra : "");
    int flags = fcntl(fd, F_GETFL);
    fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
    struct timeval tv = {5, 0};
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    send_all(fd, head, (size_t)hl);
    send_all(fd, body, blen);
}

static void respond(int fd, int code, const char *type, const char *extra,
                    const void *body, size_t blen)
{
    respond_ex(fd, code, type, extra, body, blen, "'self'");
}

static void respond_json(int fd, int code, const char *extra, const char *json)
{
    respond(fd, code, "application/json", extra, json, strlen(json));
}

static size_t json_str(char *out, size_t cap, const char *s)
{
    size_t n = 0;
    if (n < cap)
        out[n++] = '"';
    for (; *s && n + 7 < cap; s++) {
        unsigned char ch = (unsigned char)*s;
        if (ch == '"' || ch == '\\') {
            out[n++] = '\\';
            out[n++] = (char)ch;
        } else if (ch < 0x20 || ch == '<' || ch == '>' || ch == '&') {
            n += (size_t)snprintf(out + n, cap - n, "\\u%04x", ch);
        } else {
            out[n++] = (char)ch;
        }
    }
    if (n < cap)
        out[n++] = '"';
    out[n < cap ? n : cap - 1] = '\0';
    return n;
}

static void state_json(char *out, size_t cap)
{
    time_t now = time(NULL);
    size_t n = (size_t)snprintf(out, cap, "{\"hibernating\":%s,\"sandbox\":%s,\"dir\":",
                                hib ? "true" : "false", cfg->sandbox ? "true" : "false");
    n += json_str(out + n, cap - n, cfg->dir);
    n += (size_t)snprintf(out + n, cap - n, ",\"join\":");
    n += join_plain[0] ? json_str(out + n, cap - n, join_plain) : (size_t)snprintf(out + n, cap - n, "null");
    n += (size_t)snprintf(out + n, cap - n, ",\"join_cf\":");
    n += join_cf[0] ? json_str(out + n, cap - n, join_cf) : (size_t)snprintf(out + n, cap - n, "null");
    n += (size_t)snprintf(out + n, cap - n, ",\"sessions\":[");
    int first = 1;
    for (int i = 0; i < RT_MAX_CONNS && n < cap - 256; i++) {
        struct conn *c = &conns[i];
        if (c->pid <= 0)
            continue;
        n += (size_t)snprintf(out + n, cap - n, "%s{\"id\":%d,\"age\":%ld,\"closing\":%s,\"info\":",
                              first ? "" : ",", (int)c->pid, (long)(now - c->start),
                              c->killing ? "true" : "false");
        n += json_str(out + n, cap - n, c->info);
        n += (size_t)snprintf(out + n, cap - n, "}");
        first = 0;
    }
    snprintf(out + n, cap - n, "]}");
}

static int hexval(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Finds key in an x-www-form-urlencoded body and decodes its value. */
static int form_get(const char *body, size_t blen, const char *key, char *out, size_t cap)
{
    size_t kl = strlen(key);
    const char *p = body, *end = body + blen;
    while (p < end) {
        const char *amp = memchr(p, '&', (size_t)(end - p));
        const char *pe = amp ? amp : end;
        if ((size_t)(pe - p) > kl && strncmp(p, key, kl) == 0 && p[kl] == '=') {
            size_t n = 0;
            for (const char *q = p + kl + 1; q < pe; q++) {
                if (n + 1 >= cap)
                    return -1;
                if (*q == '+') {
                    out[n++] = ' ';
                } else if (*q == '%' && pe - q > 2 && hexval(q[1]) >= 0 && hexval(q[2]) >= 0) {
                    out[n++] = (char)(hexval(q[1]) * 16 + hexval(q[2]));
                    q += 2;
                } else {
                    out[n++] = *q;
                }
            }
            out[n] = '\0';
            return (int)n;
        }
        p = pe + 1;
    }
    return -1;
}

static struct token *find_token(const char *cookie)
{
    const char *p = cookie;
    while (p && (p = strstr(p, "rt=")) != NULL) {
        if (p == cookie || p[-1] == ' ' || p[-1] == ';')
            break;
        p += 3;
    }
    if (!p)
        return NULL;
    p += 3;
    unsigned char v[32];
    for (int i = 0; i < 32; i++) {
        int hi = hexval(p[2 * i]), lo = hi < 0 ? -1 : hexval(p[2 * i + 1]);
        if (hi < 0 || lo < 0)
            return NULL;
        v[i] = (unsigned char)(hi * 16 + lo);
    }
    time_t now = time(NULL);
    for (int i = 0; i < MAX_TOKENS; i++)
        if (tokens[i].exp > now && timingsafe_bcmp(tokens[i].v, v, 32) == 0)
            return &tokens[i];
    return NULL;
}

static struct conn *spawn_web(void)
{
    struct conn *c = NULL;
    for (int i = 0; i < RT_MAX_CONNS && !c; i++)
        if (conns[i].pid == 0)
            c = &conns[i];
    int sp[2];
    if (!c || socketpair(AF_UNIX, SOCK_DGRAM, 0, sp) != 0)
        return NULL;
    cloexec(sp[0]);
    cloexec(sp[1]);
    pid_t pid = fork();
    if (pid == 0) {
        setsid();
        dup2(fcntl(sp[1], F_DUPFD, 10), 4);
        char *argv[] = {"rt", "--web", cfg->sbhome, cfg->state, NULL};
        execv(cfg->self, argv);
        _exit(127);
    }
    close(sp[1]);
    if (pid < 0) {
        close(sp[0]);
        return NULL;
    }
    char m[PATH_MAX + 8];
    int ml = snprintf(m, sizeof m, "C%c%s", cfg->sandbox ? '1' : '0', cfg->dir);
    send(sp[0], m, (size_t)ml, 0);
    fcntl(sp[0], F_SETFL, O_NONBLOCK);
    memset(c, 0, sizeof *c);
    c->pid = pid;
    c->sup = sp[0];
    c->start = time(NULL);
    c->authed = 1;
    c->web = 1;
    arc4random_buf(c->sid, sizeof c->sid);
    strlcpy(c->info, "browser terminal (starting)", sizeof c->info);
    logmsg("browser terminal started");
    return c;
}

static void ws_accept_key(const char *key, char out[29])
{
    static const char guid[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    char buf[128];
    unsigned char d[CC_SHA1_DIGEST_LENGTH];
    int n = snprintf(buf, sizeof buf, "%s%s", key, guid);
    CC_SHA1(buf, (CC_LONG)n, d);
    int o = 0;
    for (int i = 0; i < 20; i += 3) {
        unsigned v = (unsigned)d[i] << 16 | (i + 1 < 20 ? (unsigned)d[i + 1] << 8 : 0) |
                     (i + 2 < 20 ? d[i + 2] : 0);
        out[o++] = b64[v >> 18 & 63];
        out[o++] = b64[v >> 12 & 63];
        out[o++] = i + 1 < 20 ? b64[v >> 6 & 63] : '=';
        out[o++] = i + 2 < 20 ? b64[v & 63] : '=';
    }
    out[o] = '\0';
}

static int parse_sid(const char *query, unsigned char sid[16])
{
    const char *p = query ? strstr(query, "s=") : NULL;
    if (!p || (p != query && p[-1] != '&'))
        return -1;
    p += 2;
    for (int i = 0; i < 16; i++) {
        int hi = hexval(p[2 * i]), lo = hi < 0 ? -1 : hexval(p[2 * i + 1]);
        if (hi < 0 || lo < 0)
            return -1;
        sid[i] = (unsigned char)(hi * 16 + lo);
    }
    return 0;
}

/* Upgrades an authenticated request and hands the socket to that terminal's process. */
static void websocket(int fd, const char *query, const char *origin, const char *upgrade,
                      const char *key, const char *version)
{
    char want1[300], want2[300];
    snprintf(want1, sizeof want1, "https://%s", req_host);
    snprintf(want2, sizeof want2, "http://%s", req_host);
    if (!req_host[0] || !origin || (strcmp(origin, want1) != 0 && strcmp(origin, want2) != 0)) {
        respond_json(fd, 403, NULL, "{\"error\":\"Forbidden\"}");
        return;
    }
    if (!upgrade || !strcasestr(upgrade, "websocket") || !key || strlen(key) > 64 || !version ||
        strcmp(version, "13") != 0) {
        respond_json(fd, 400, NULL, "{}");
        return;
    }
    if (hib) {
        respond_json(fd, 503, NULL, "{\"error\":\"Hibernating.\"}");
        return;
    }
    unsigned char sid[16];
    struct conn *c = NULL;
    if (parse_sid(query, sid) == 0)
        for (int i = 0; i < RT_MAX_CONNS && !c; i++)
            if (conns[i].pid > 0 && conns[i].web && !conns[i].killing &&
                timingsafe_bcmp(conns[i].sid, sid, sizeof sid) == 0)
                c = &conns[i];
    if (!c) {
        respond_json(fd, 404, NULL, "{\"error\":\"No such terminal.\"}");
        return;
    }
    char accept[29], head[256];
    ws_accept_key(key, accept);
    int hl = snprintf(head, sizeof head,
                      "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                      "Connection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", accept);
    int flags = fcntl(fd, F_GETFL);
    fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
    send_all(fd, head, (size_t)hl);

    char data = 'A';
    char cbuf[CMSG_SPACE(sizeof(int))];
    memset(cbuf, 0, sizeof cbuf);
    struct iovec iov = {&data, 1};
    struct msghdr mh = {0};
    mh.msg_iov = &iov;
    mh.msg_iovlen = 1;
    mh.msg_control = cbuf;
    mh.msg_controllen = sizeof cbuf;
    struct cmsghdr *cm = CMSG_FIRSTHDR(&mh);
    cm->cmsg_level = SOL_SOCKET;
    cm->cmsg_type = SCM_RIGHTS;
    cm->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cm), &fd, sizeof fd);
    sendmsg(c->sup, &mh, 0);
}

static void web_handle(int fd, char *req, size_t len)
{
    char *hend = strstr(req, "\r\n\r\n");
    char *body = hend + 4;
    size_t blen = len - (size_t)(body - req);
    *hend = '\0';

    for (char *p = req; p < hend; p++)
        if (*p == '\r' || *p == '\n')
            *p = '\0';
    const char *cookie = "", *xrt = NULL, *host = NULL, *origin = NULL, *upgrade = NULL,
               *wskey = NULL, *wsver = NULL;
    for (char *line = req; line < hend; line += strlen(line) + 1) {
        const char **dst = NULL;
        size_t skip = 0;
        static const struct { const char *name; size_t len; } h[] = {
            {"Cookie:", 7}, {"X-RT:", 5}, {"Host:", 5}, {"Origin:", 7}, {"Upgrade:", 8},
            {"Sec-WebSocket-Key:", 18}, {"Sec-WebSocket-Version:", 22}};
        const char **slots[] = {&cookie, &xrt, &host, &origin, &upgrade, &wskey, &wsver};
        for (size_t i = 0; i < sizeof h / sizeof h[0] && !dst; i++)
            if (strncasecmp(line, h[i].name, h[i].len) == 0) {
                dst = slots[i];
                skip = h[i].len;
            }
        if (dst) {
            const char *v = line + skip;
            while (*v == ' ')
                v++;
            *dst = v;
        }
    }
    req_host[0] = '\0';
    if (host && strlen(host) < sizeof req_host && strspn(host, "abcdefghijklmnopqrstuvwxyz"
               "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-:") == strlen(host))
        strlcpy(req_host, host, sizeof req_host);

    char method[8], path[256];
    if (sscanf(req, "%7s %255s", method, path) != 2) {
        respond_json(fd, 400, NULL, "{}");
        return;
    }
    char *q = strchr(path, '?');
    if (q)
        *q++ = '\0';

    int get = strcmp(method, "GET") == 0, post = strcmp(method, "POST") == 0;
    struct token *tok = find_token(cookie);
    static const struct {
        const char *path, *type;
        const unsigned char *body;
        const unsigned *len;
    } files[] = {
        {"/term", "text/html; charset=utf-8", term_html, &term_html_len},
        {"/term.js", "text/javascript; charset=utf-8", term_js, &term_js_len},
        {"/term.css", "text/css; charset=utf-8", term_css, &term_css_len},
        {"/xterm.js", "text/javascript; charset=utf-8", vendor_xterm_js, &vendor_xterm_js_len},
        {"/xterm.css", "text/css; charset=utf-8", vendor_xterm_css, &vendor_xterm_css_len},
        {"/addon-fit.js", "text/javascript; charset=utf-8", vendor_addon_fit_js,
         &vendor_addon_fit_js_len},
        {"/fonts/meslo-regular.woff", "font/woff", vendor_fonts_MesloLGS_NF_Regular_woff,
         &vendor_fonts_MesloLGS_NF_Regular_woff_len},
        {"/fonts/meslo-bold.woff", "font/woff", vendor_fonts_MesloLGS_NF_Bold_woff,
         &vendor_fonts_MesloLGS_NF_Bold_woff_len},
    };
    for (size_t i = 0; get && i < sizeof files / sizeof files[0]; i++)
        if (strcmp(path, files[i].path) == 0) {
            /* xterm.js injects <style> elements; scripts stay restricted. */
            respond_ex(fd, 200, files[i].type, NULL, files[i].body, *files[i].len,
                       "'self' 'unsafe-inline'");
            return;
        }
    if (get && strcmp(path, "/term/ws") == 0) {
        if (!tok)
            respond_json(fd, 401, NULL, "{\"error\":\"Log in first.\"}");
        else
            websocket(fd, q, origin, upgrade, wskey, wsver);
        return;
    }
    if (get && strcmp(path, "/") == 0) {
        respond(fd, 200, "text/html; charset=utf-8", NULL, panel_html, panel_html_len);
        return;
    }
    if (get && strcmp(path, "/panel.js") == 0) {
        respond(fd, 200, "text/javascript; charset=utf-8", NULL, panel_js, panel_js_len);
        return;
    }
    if (get && strcmp(path, "/panel.css") == 0) {
        respond(fd, 200, "text/css; charset=utf-8", NULL, panel_css, panel_css_len);
        return;
    }
    if (strncmp(path, "/api/", 5) != 0 || (!get && !post)) {
        respond_json(fd, 404, NULL, "{\"error\":\"Not found\"}");
        return;
    }
    /* A custom header forces a CORS preflight, which is never granted. */
    while (xrt && *xrt == ' ')
        xrt++;
    if (!xrt || strcmp(xrt, "1") != 0) {
        respond_json(fd, 403, NULL, "{\"error\":\"Forbidden\"}");
        return;
    }

    char out[16384];
    if (post && strcmp(path, "/api/login") == 0) {
        char pass[1025];
        int pl = form_get(body, blen, "password", pass, sizeof pass);
        int res = pl > 0 ? check_password(pass, (size_t)pl, "panel") : AUTH_BAD;
        memset_s(pass, sizeof pass, 0, sizeof pass);
        memset_s(body, blen, 0, blen);
        if (res == AUTH_WAIT) {
            snprintf(out, sizeof out, "{\"error\":\"Too many wrong passwords. Try again in %ld s.\"}",
                     wait_left());
            respond_json(fd, 429, NULL, out);
            return;
        }
        if (res != AUTH_OK) {
            respond_json(fd, 401, NULL, "{\"error\":\"Wrong password.\"}");
            return;
        }
        struct token *t = &tokens[0];
        for (int i = 1; i < MAX_TOKENS; i++)
            if (tokens[i].exp < t->exp)
                t = &tokens[i];
        arc4random_buf(t->v, sizeof t->v);
        t->exp = time(NULL) + TOKEN_TTL;
        char hex[65], hdr[200];
        for (int i = 0; i < 32; i++)
            snprintf(hex + 2 * i, 3, "%02x", t->v[i]);
        snprintf(hdr, sizeof hdr,
                 "Set-Cookie: rt=%s; Path=/; Max-Age=%d; HttpOnly; Secure; SameSite=Strict\r\n",
                 hex, TOKEN_TTL);
        state_json(out, sizeof out);
        respond_json(fd, 200, hdr, out);
        return;
    }

    if (!tok) {
        respond_json(fd, 401, NULL, "{\"error\":\"Log in first.\"}");
        return;
    }

    if (get && strcmp(path, "/api/state") == 0) {
        state_json(out, sizeof out);
        respond_json(fd, 200, NULL, out);
        return;
    }
    if (!post) {
        respond_json(fd, 404, NULL, "{\"error\":\"Not found\"}");
        return;
    }
    if (strcmp(path, "/api/term") == 0) {
        if (hib) {
            respond_json(fd, 409, NULL, "{\"error\":\"Hibernating. Wake rt from the panel first.\"}");
            return;
        }
        struct conn *c = spawn_web();
        if (!c) {
            respond_json(fd, 503, NULL, "{\"error\":\"Could not start a terminal.\"}");
            return;
        }
        char hex[33];
        for (int i = 0; i < 16; i++)
            snprintf(hex + 2 * i, 3, "%02x", c->sid[i]);
        snprintf(out, sizeof out, "{\"sid\":\"%s\"}", hex);
        respond_json(fd, 200, NULL, out);
        return;
    }
    if (strcmp(path, "/api/logout") == 0) {
        memset(tok, 0, sizeof *tok);
        respond_json(fd, 200, "Set-Cookie: rt=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict\r\n",
                     "{}");
        return;
    }
    if (strcmp(path, "/api/hibernate") == 0 || strcmp(path, "/api/wake") == 0) {
        hibernate(path[5] == 'h', "panel");
    } else if (strcmp(path, "/api/kill") == 0) {
        char id[16];
        int pid = form_get(body, blen, "id", id, sizeof id) > 0 ? atoi(id) : 0;
        for (int i = 0; i < RT_MAX_CONNS; i++)
            if (pid > 0 && conns[i].pid == pid) {
                kill_conn(&conns[i]);
                logmsg("session %d closed via panel", pid);
            }
    } else if (strcmp(path, "/api/cd") == 0) {
        char want[PATH_MAX], full[PATH_MAX], real[PATH_MAX];
        struct stat st;
        if (form_get(body, blen, "dir", want, sizeof want) <= 0) {
            respond_json(fd, 400, NULL, "{\"error\":\"Enter a directory.\"}");
            return;
        }
        if (want[0] == '~' && (want[1] == '\0' || want[1] == '/'))
            snprintf(full, sizeof full, "%s%s", getpwuid(getuid())->pw_dir, want + 1);
        else
            strlcpy(full, want, sizeof full);
        if (full[0] != '/' || !realpath(full, real) || stat(real, &st) != 0 || !S_ISDIR(st.st_mode)) {
            respond_json(fd, 400, NULL, "{\"error\":\"That is not an existing directory.\"}");
            return;
        }
        strlcpy(cfg->dir, real, sizeof cfg->dir);
        logmsg("directory changed via panel: %s", real);
    } else {
        respond_json(fd, 404, NULL, "{\"error\":\"Not found\"}");
        return;
    }
    state_json(out, sizeof out);
    respond_json(fd, 200, NULL, out);
}

static void web_close(struct web *w)
{
    close(w->fd);
    memset_s(w->buf, sizeof w->buf, 0, sizeof w->buf);
    w->fd = -1;
    w->len = 0;
}

static void web_read(struct web *w)
{
    ssize_t n = read(w->fd, w->buf + w->len, sizeof w->buf - 1 - w->len);
    if (n <= 0) {
        if (n == 0 || errno != EAGAIN)
            web_close(w);
        return;
    }
    w->len += (size_t)n;
    w->buf[w->len] = '\0';
    char *hend = strstr(w->buf, "\r\n\r\n");
    if (!hend) {
        if (w->len >= sizeof w->buf - 1) {
            respond_json(w->fd, 413, NULL, "{}");
            web_close(w);
        }
        return;
    }
    size_t clen = 0;
    for (char *p = w->buf; p < hend; p++)
        if ((p == w->buf || p[-1] == '\n') && strncasecmp(p, "Content-Length:", 15) == 0)
            clen = strtoul(p + 15, NULL, 10);
    size_t have = w->len - (size_t)(hend + 4 - w->buf);
    if (clen > sizeof w->buf - 1 - (size_t)(hend + 4 - w->buf)) {
        respond_json(w->fd, 413, NULL, "{}");
        web_close(w);
        return;
    }
    if (have < clen)
        return;
    web_handle(w->fd, w->buf, w->len);
    web_close(w);
}

static void accept_web(int lfd)
{
    int fd = accept(lfd, NULL, NULL);
    if (fd < 0)
        return;
    cloexec(fd);
    for (int i = 0; i < MAX_WEB; i++) {
        if (webs[i].fd < 0) {
            fcntl(fd, F_SETFL, O_NONBLOCK);
            webs[i].fd = fd;
            webs[i].len = 0;
            webs[i].start = time(NULL);
            return;
        }
    }
    close(fd);
}

/* ---- main loop ---- */

static void reap(void)
{
    int st;
    pid_t p;
    while ((p = waitpid(-1, &st, WNOHANG)) > 0) {
        for (int i = 0; i < RT_MAX_CONNS; i++) {
            struct conn *c = &conns[i];
            if (c->pid != p)
                continue;
            for (int g = 0; g < c->ngroups; g++) {
                killpg(c->groups[g], SIGHUP);
                killpg(c->groups[g], SIGKILL);
            }
            close(c->sup);
            memset(c, 0, sizeof *c);
        }
        for (int i = 0; i < ntunnels; i++) {
            struct tunnel *t = &tunnels[i];
            if (t->probe == p) {
                t->probe = 0;
                if (!stopping && t->pid > 0)
                    announce(t, WIFEXITED(st) && WEXITSTATUS(st) == 0);
            }
            if (t->pid != p)
                continue;
            t->pid = 0;
            if (t->kind == T_RELAY)
                join_plain[0] = '\0';
            else if (t->kind == T_CF_SSH)
                join_cf[0] = '\0';
            if (t->probe > 0) {
                killpg(t->probe, SIGKILL);
                t->probe = 0;
            }
            if (stopping)
                continue;
            for (int k = 0; k < 16 && t->fd >= 0; k++)
                tunnel_read(t);
            int delay = 5;
            t->fails++;
            if (t->kind == T_RELAY && strstr(t->buf, "forwarding failed")) {
                if (!t->warned)
                    logmsg("relay name %s is already in use, probably by another rt on this Mac; "
                           "retrying every 30 s", cfg->relay);
                t->warned = 1;
                delay = 30;
            } else if (t->kind == T_RELAY) {
                if (t->fails == 1)
                    logmsg("relay connection dropped; reconnecting (same address)");
                delay = t->fails < 5 ? 5 << (t->fails - 1) : 60;
            } else {
                logmsg("%s tunnel stopped; restarting (the address will change)",
                       t->kind == T_PANEL ? "panel" : "cloudflare");
            }
            t->restart_at = time(NULL) + delay;
        }
    }
}

int supervise(struct config *c, struct pwhash *h, int ssh_fd, int ssh_port, int http_fd, int http_port)
{
    cfg = c;
    pw = h;
    for (int i = 0; i < MAX_WEB; i++)
        webs[i].fd = -1;
    if (pipe(sigp) != 0)
        return 1;
    cloexec(sigp[0]);
    cloexec(sigp[1]);
    fcntl(sigp[0], F_SETFL, O_NONBLOCK);
    fcntl(sigp[1], F_SETFL, O_NONBLOCK);
    signal(SIGPIPE, SIG_IGN);
    struct sigaction sa = {0};
    sa.sa_handler = on_signal;
    sa.sa_flags = SA_RESTART;
    sigaction(SIGCHLD, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);

    if (cfg->tunnel) {
        tunnels[ntunnels].kind = T_RELAY;
        snprintf(tunnels[ntunnels++].url_arg, 64, "127.0.0.1:%d", ssh_port);
        if (cfg->cloudflared) {
            tunnels[ntunnels].kind = T_CF_SSH;
            snprintf(tunnels[ntunnels++].url_arg, 64, "tcp://127.0.0.1:%d", ssh_port);
        }
        if (cfg->cloudflared && http_fd >= 0) {
            tunnels[ntunnels].kind = T_PANEL;
            snprintf(tunnels[ntunnels++].url_arg, 64, "http://127.0.0.1:%d", http_port);
        }
        logmsg("connecting to the relay%s, checking each route works...",
               cfg->cloudflared ? " and cloudflare" : "");
        for (int i = 0; i < ntunnels; i++) {
            tunnels[i].fd = -1;
            tunnel_start(&tunnels[i]);
        }
    }

    while (!stopping) {
        struct pollfd pf[3 + RT_MAX_CONNS + MAX_WEB + 2];
        void *who[3 + RT_MAX_CONNS + MAX_WEB + 2];
        char kind[3 + RT_MAX_CONNS + MAX_WEB + 2];
        int n = 0;
#define ADD(fd_, k_, w_) do { pf[n] = (struct pollfd){(fd_), POLLIN, 0}; kind[n] = (k_); who[n] = (w_); n++; } while (0)
        ADD(sigp[0], 's', NULL);
        ADD(ssh_fd, 'S', NULL);
        if (http_fd >= 0)
            ADD(http_fd, 'H', NULL);
        for (int i = 0; i < RT_MAX_CONNS; i++)
            if (conns[i].pid > 0)
                ADD(conns[i].sup, 'c', &conns[i]);
        for (int i = 0; i < MAX_WEB; i++)
            if (webs[i].fd >= 0)
                ADD(webs[i].fd, 'w', &webs[i]);
        for (int i = 0; i < ntunnels; i++)
            if (tunnels[i].fd >= 0)
                ADD(tunnels[i].fd, 't', &tunnels[i]);
#undef ADD
        if (poll(pf, (nfds_t)n, 1000) < 0 && errno != EINTR)
            break;
        for (int i = 0; i < n; i++) {
            if (!(pf[i].revents & (POLLIN | POLLHUP | POLLERR)))
                continue;
            switch (kind[i]) {
            case 's': {
                char b[64];
                while (read(sigp[0], b, sizeof b) > 0)
                    ;
                reap();
                break;
            }
            case 'S': accept_ssh(ssh_fd); break;
            case 'H': accept_web(http_fd); break;
            case 'c': if (((struct conn *)who[i])->pid > 0) conn_message(who[i]); break;
            case 'w': if (((struct web *)who[i])->fd >= 0) web_read(who[i]); break;
            case 't': if (((struct tunnel *)who[i])->fd >= 0) tunnel_read(who[i]); break;
            }
        }

        time_t now = time(NULL);
        for (int i = 0; i < RT_MAX_CONNS; i++) {
            struct conn *k = &conns[i];
            if (k->pid > 0 && k->killing && now >= k->kill_at) {
                kill(k->pid, SIGKILL);
                for (int g = 0; g < k->ngroups; g++)
                    killpg(k->groups[g], SIGKILL);
                k->kill_at = now + 3600;
            }
        }
        for (int i = 0; i < MAX_WEB; i++)
            if (webs[i].fd >= 0 && now - webs[i].start > 10)
                web_close(&webs[i]);
        for (int i = 0; i < ntunnels; i++) {
            struct tunnel *t = &tunnels[i];
            if (t->pid == 0 && t->restart_at && now >= t->restart_at) {
                if (t->fd >= 0) {
                    close(t->fd);
                    t->fd = -1;
                }
                t->restart_at = 0;
                tunnel_start(t);
            }
        }
    }

    logmsg("shutting down");
    kill_all();
    for (int i = 0; i < ntunnels; i++) {
        if (tunnels[i].pid > 0)
            kill(tunnels[i].pid, SIGTERM);
        if (tunnels[i].probe > 0)
            killpg(tunnels[i].probe, SIGKILL);
    }
    for (int t = 0; t < 30; t++) {
        int alive = 0;
        reap();
        for (int i = 0; i < RT_MAX_CONNS; i++)
            alive |= conns[i].pid > 0;
        if (!alive)
            break;
        usleep(100000);
    }
    for (int i = 0; i < RT_MAX_CONNS; i++)
        if (conns[i].pid > 0) {
            kill(conns[i].pid, SIGKILL);
            for (int g = 0; g < conns[i].ngroups; g++)
                killpg(conns[i].groups[g], SIGKILL);
        }
    return 0;
}
