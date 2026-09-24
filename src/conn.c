#define __STDC_WANT_LIB_EXT1__ 1
#include "rt.h"

#include <errno.h>
#include <fcntl.h>
#include <libssh/callbacks.h>
#include <libssh/libssh.h>
#include <libssh/server.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <util.h>

#define MAX_CHANS 8
#define MAX_ENV 16
#define MAX_KEYS 32
#define CLIENT_FD 3
#define SUP_FD 4

struct chan {
    int used;
    ssh_channel ch;
    struct ssh_channel_callbacks_struct cb;
    int master, slave;
    struct winsize ws;
    char term[64];
    char *env[MAX_ENV];
    int nenv;
    pid_t pid;
    int in_fd, out_fd, err_fd;
    int out_eof, err_eof;
    int exited, status, finished, client_closed;
    int cleanup;
};

static struct chan chans[MAX_CHANS];
static ssh_session sess;
static ssh_event ev;
static ssh_key keys[MAX_KEYS];
static int nkeys, key_ok, authed, drop, pw_fails;
static int chld_pipe[2] = {-1, -1};
static volatile sig_atomic_t got_term;
static int cleanup_flag;

static int load_keys(const char *path, ssh_key *out, int max)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return -1;
    char line[16384];
    int n = 0;
    while (n < max && fgets(line, sizeof line, f)) {
        char *save = NULL;
        char *type = strtok_r(line, " \t\r\n", &save);
        char *b64 = type ? strtok_r(NULL, " \t\r\n", &save) : NULL;
        if (!b64 || type[0] == '#')
            continue;
        enum ssh_keytypes_e t = ssh_key_type_from_name(type);
        ssh_key k;
        if (t != SSH_KEYTYPE_UNKNOWN && ssh_pki_import_pubkey_base64(b64, t, &k) == SSH_OK)
            out[n++] = k;
    }
    fclose(f);
    return n;
}

int count_keys(const char *path)
{
    ssh_key tmp[MAX_KEYS];
    int n = load_keys(path, tmp, MAX_KEYS);
    for (int i = 0; i < n; i++)
        ssh_key_free(tmp[i]);
    return n;
}

static int ask(const char *msg, size_t len, char *reply, size_t cap)
{
    if (send(SUP_FD, msg, len, 0) < 0)
        return -1;
    struct pollfd p = {SUP_FD, POLLIN, 0};
    if (poll(&p, 1, 15000) <= 0)
        return -1;
    ssize_t n = recv(SUP_FD, reply, cap - 1, 0);
    if (n <= 0)
        return -1;
    reply[n] = '\0';
    return (int)n;
}

static void tell(char kind, const char *s)
{
    char b[128];
    int n = snprintf(b, sizeof b, "%c%s", kind, s);
    send(SUP_FD, b, n < (int)sizeof b ? (size_t)n : sizeof b - 1, 0);
}

static void tell_pid(char kind, pid_t pid)
{
    char b[16];
    snprintf(b, sizeof b, "%d", (int)pid);
    tell(kind, b);
}

static int auth_password(ssh_session s, const char *user, const char *pw, void *ud)
{
    (void)s; (void)user; (void)ud;
    if (nkeys > 0 && !key_ok)
        return SSH_AUTH_DENIED;
    size_t len = strlen(pw);
    char msg[1100], r[PATH_MAX + 8];
    int n = -1;
    if (len > 0 && len < sizeof msg - 1) {
        msg[0] = 'P';
        memcpy(msg + 1, pw, len);
        n = ask(msg, len + 1, r, sizeof r);
        memset_s(msg, sizeof msg, 0, sizeof msg);
    }
    if (n >= 3 && r[0] == 'O') {
        spawnctx.sandboxed = r[1] == '1';
        strlcpy(spawnctx.dir, r + 2, sizeof spawnctx.dir);
        authed = 1;
        return SSH_AUTH_SUCCESS;
    }
    if (n < 0 || r[0] == 'H' || ++pw_fails >= 3)
        drop = 1;
    return SSH_AUTH_DENIED;
}

static int auth_pubkey(ssh_session s, const char *user, struct ssh_key_struct *pk,
                       char state, void *ud)
{
    (void)user; (void)ud;
    for (int i = 0; i < nkeys; i++) {
        if (ssh_key_cmp(keys[i], pk, SSH_KEY_CMP_PUBLIC) != 0)
            continue;
        if (state == SSH_PUBLICKEY_STATE_NONE)
            return SSH_AUTH_SUCCESS;
        if (state == SSH_PUBLICKEY_STATE_VALID) {
            key_ok = 1;
            ssh_set_auth_methods(s, SSH_AUTH_METHOD_PASSWORD);
            return SSH_AUTH_PARTIAL;
        }
    }
    return SSH_AUTH_DENIED;
}

static struct chan *mine(ssh_channel ch, void *ud)
{
    struct chan *c = ud;
    return c && c->used && c->ch == ch ? c : NULL;
}

static void write_all(int fd, const char *p, size_t len)
{
    while (len > 0) {
        ssize_t n = write(fd, p, len);
        if (n > 0) {
            p += n;
            len -= (size_t)n;
        } else if (n < 0 && (errno == EAGAIN || errno == EINTR)) {
            struct pollfd pf = {fd, POLLOUT, 0};
            poll(&pf, 1, 1000);
        } else {
            return;
        }
    }
}

static int on_data(ssh_session s, ssh_channel ch, void *data, uint32_t len, int is_stderr, void *ud)
{
    (void)s; (void)is_stderr;
    struct chan *c = mine(ch, ud);
    if (c && c->in_fd >= 0)
        write_all(c->in_fd, data, len);
    return (int)len;
}

static void on_eof(ssh_session s, ssh_channel ch, void *ud)
{
    (void)s;
    struct chan *c = mine(ch, ud);
    if (c && c->master < 0 && c->in_fd >= 0) {
        close(c->in_fd);
        c->in_fd = -1;
    }
}

static void on_close(ssh_session s, ssh_channel ch, void *ud)
{
    (void)s;
    struct chan *c = mine(ch, ud);
    if (!c)
        return;
    if (c->cleanup) {
        const char *script = cleanup_script();
        ssh_channel_write(ch, (const unsigned char *)script, strlen(script));
        logmsg("sent cleanup script to client on disconnect");
    }
    c->client_closed = 1;
    if (c->pid > 0 && !c->exited)
        killpg(c->pid, SIGHUP);
}

static int on_pty(ssh_session s, ssh_channel ch, const char *term, int w, int h, int pw, int ph, void *ud)
{
    (void)s;
    struct chan *c = mine(ch, ud);
    if (!c || c->master >= 0 || c->pid > 0)
        return -1;
    c->ws = (struct winsize){(unsigned short)h, (unsigned short)w, (unsigned short)pw, (unsigned short)ph};
    if (openpty(&c->master, &c->slave, NULL, NULL, &c->ws) != 0)
        return -1;
    fcntl(c->master, F_SETFD, FD_CLOEXEC);
    fcntl(c->slave, F_SETFD, FD_CLOEXEC);
    strlcpy(c->term, term, sizeof c->term);
    return 0;
}

static int on_winch(ssh_session s, ssh_channel ch, int w, int h, int pw, int ph, void *ud)
{
    (void)s;
    struct chan *c = mine(ch, ud);
    if (!c || c->master < 0)
        return -1;
    c->ws = (struct winsize){(unsigned short)h, (unsigned short)w, (unsigned short)pw, (unsigned short)ph};
    ioctl(c->master, TIOCSWINSZ, &c->ws);
    return 0;
}

static int env_allowed(const char *name)
{
    static const char *const ok[] = {"LANG", "COLORTERM", "CLAUDE_CODE_OAUTH_TOKEN",
                                     "ANTHROPIC_API_KEY", NULL};
    if (strncmp(name, "LC_", 3) == 0)
        return 1;
    for (int i = 0; ok[i]; i++)
        if (strcmp(name, ok[i]) == 0)
            return 1;
    return 0;
}

static int on_env(ssh_session s, ssh_channel ch, const char *name, const char *value, void *ud)
{
    (void)s;
    struct chan *c = mine(ch, ud);
    if (!c || c->nenv >= MAX_ENV || strchr(name, '=') || !env_allowed(name))
        return -1;
    char *kv;
    if (asprintf(&kv, "%s=%s", name, value) < 0)
        return -1;
    c->env[c->nenv++] = kv;
    return 0;
}

static int on_output(socket_t fd, int revents, void *ud)
{
    (void)revents;
    struct chan *c = ud;
    char buf[16384];
    ssize_t n = read(fd, buf, sizeof buf);
    if (n > 0) {
        if (fd == c->err_fd)
            ssh_channel_write_stderr(c->ch, buf, (uint32_t)n);
        else
            ssh_channel_write(c->ch, buf, (uint32_t)n);
    } else if (n == 0 || (errno != EAGAIN && errno != EINTR)) {
        if (fd == c->err_fd)
            c->err_eof = 1;
        else
            c->out_eof = 1;
    }
    return 0;
}

static int start(struct chan *c, const char *cmd)
{
    if (c->pid > 0)
        return -1;

    char info[100];
    if (cmd)
        snprintf(info, sizeof info, "exec: %.80s", cmd);
    else
        snprintf(info, sizeof info, "%s", c->master >= 0 ? "shell" : "shell (no tty)");
    tell('I', info);

    int inp[2] = {-1, -1}, outp[2] = {-1, -1}, errp[2] = {-1, -1};
    if (c->master < 0 && (pipe(inp) || pipe(outp) || pipe(errp)))
        return -1;
    int child[3] = {inp[0], outp[1], errp[1]};
    pid_t pid = spawn_command(cmd, c->slave, child, c->env, c->nenv, c->term);

    if (pid < 0) {
        int fds[] = {inp[0], inp[1], outp[0], outp[1], errp[0], errp[1]};
        for (int i = 0; i < 6; i++)
            if (fds[i] >= 0)
                close(fds[i]);
        return -1;
    }

    if (c->master >= 0) {
        close(c->slave);
        c->slave = -1;
        c->in_fd = c->out_fd = c->master;
        c->err_eof = 1;
    } else {
        close(inp[0]);
        close(outp[1]);
        close(errp[1]);
        c->in_fd = inp[1];
        c->out_fd = outp[0];
        c->err_fd = errp[0];
        fcntl(c->in_fd, F_SETFD, FD_CLOEXEC);
        fcntl(c->err_fd, F_SETFD, FD_CLOEXEC);
        fcntl(c->err_fd, F_SETFL, O_NONBLOCK);
        ssh_event_add_fd(ev, c->err_fd, POLLIN, on_output, c);
    }
    fcntl(c->out_fd, F_SETFD, FD_CLOEXEC);
    fcntl(c->out_fd, F_SETFL, O_NONBLOCK);
    ssh_event_add_fd(ev, c->out_fd, POLLIN, on_output, c);
    c->pid = pid;
    tell_pid('G', pid);
    return 0;
}

static int on_shell(ssh_session s, ssh_channel ch, void *ud)
{
    (void)s;
    struct chan *c = mine(ch, ud);
    return c ? start(c, NULL) : -1;
}

static int on_exec(ssh_session s, ssh_channel ch, const char *cmd, void *ud)
{
    (void)s;
    struct chan *c = mine(ch, ud);
    return c ? start(c, cmd) : -1;
}

static ssh_channel open_session(ssh_session s, void *ud)
{
    (void)ud;
    for (int i = 0; i < MAX_CHANS; i++) {
        struct chan *c = &chans[i];
        if (c->used)
            continue;
        memset(c, 0, sizeof *c);
        c->ch = ssh_channel_new(s);
        if (!c->ch)
            return NULL;
        c->used = 1;
        c->master = c->slave = c->in_fd = c->out_fd = c->err_fd = -1;
        c->pid = -1;
        c->cleanup = cleanup_flag;
        c->cb.userdata = c;
        c->cb.channel_data_function = on_data;
        c->cb.channel_eof_function = on_eof;
        c->cb.channel_close_function = on_close;
        c->cb.channel_pty_request_function = on_pty;
        c->cb.channel_pty_window_change_function = on_winch;
        c->cb.channel_env_request_function = on_env;
        c->cb.channel_shell_request_function = on_shell;
        c->cb.channel_exec_request_function = on_exec;
        ssh_callbacks_init(&c->cb);
        ssh_set_channel_callbacks(c->ch, &c->cb);
        return c->ch;
    }
    return NULL;
}

static void close_fd(struct chan *c, int *fd)
{
    if (*fd < 0)
        return;
    int old = *fd;
    ssh_event_remove_fd(ev, old);
    close(old);
    if (c->in_fd == old)
        c->in_fd = -1;
    if (c->out_fd == old)
        c->out_fd = -1;
    if (c->err_fd == old)
        c->err_fd = -1;
    if (c->master == old)
        c->master = -1;
    *fd = -1;
}

static void drain(struct chan *c, int fd)
{
    char buf[16384];
    ssize_t n;
    while ((n = read(fd, buf, sizeof buf)) > 0)
        ssh_channel_write(c->ch, buf, (uint32_t)n);
}

static void housekeeping(void)
{
    int st;
    pid_t p;
    while ((p = waitpid(-1, &st, WNOHANG)) > 0) {
        for (int i = 0; i < MAX_CHANS; i++) {
            struct chan *c = &chans[i];
            if (c->used && c->pid == p) {
                c->exited = 1;
                c->status = st;
                tell_pid('g', p);
            }
        }
    }
    for (int i = 0; i < MAX_CHANS; i++) {
        struct chan *c = &chans[i];
        if (!c->used)
            continue;
        if (c->out_eof) {
            int fd = c->out_fd;
            close_fd(c, &fd);
        }
        if (c->err_eof && c->err_fd >= 0) {
            int fd = c->err_fd;
            close_fd(c, &fd);
        }
        /* A pty stays open while background jobs hold it; stop once the shell exits. */
        if (c->exited && c->master >= 0) {
            drain(c, c->master);
            int fd = c->master;
            close_fd(c, &fd);
        }
        if (c->exited && c->out_fd < 0 && c->err_fd < 0 && !c->finished && !c->client_closed) {
            int code = WIFEXITED(c->status) ? WEXITSTATUS(c->status) : 128 + WTERMSIG(c->status);
            ssh_channel_request_send_exit_status(c->ch, code);
            ssh_channel_send_eof(c->ch);
            ssh_channel_close(c->ch);
            c->finished = 1;
        }
        if ((c->finished || c->client_closed) && (c->pid < 0 || c->exited)) {
            int fds[] = {c->in_fd, c->out_fd, c->err_fd, c->master, c->slave};
            for (int k = 0; k < 5; k++) {
                int fd = fds[k];
                close_fd(c, &fd);
            }
            if (c->slave >= 0)
                close(c->slave);
            for (int k = 0; k < c->nenv; k++)
                free(c->env[k]);
            ssh_remove_channel_callbacks(c->ch, &c->cb);
            ssh_channel_free(c->ch);
            c->used = 0;
        }
    }
}

static int on_sigchld_pipe(socket_t fd, int revents, void *ud)
{
    (void)revents; (void)ud;
    char b[64];
    while (read(fd, b, sizeof b) > 0)
        ;
    return 0;
}

static void on_sigchld(int sig)
{
    (void)sig;
    int e = errno;
    write(chld_pipe[1], "c", 1);
    errno = e;
}

static void on_term(int sig)
{
    (void)sig;
    got_term = 1;
}

static void shutdown_children(void)
{
    for (int i = 0; i < MAX_CHANS; i++)
        if (chans[i].used && chans[i].pid > 0 && !chans[i].exited)
            killpg(chans[i].pid, SIGHUP);
    for (int t = 0; t < 20; t++) {
        int alive = 0;
        for (int i = 0; i < MAX_CHANS; i++) {
            struct chan *c = &chans[i];
            if (c->used && c->pid > 0 && !c->exited) {
                if (waitpid(c->pid, NULL, WNOHANG) == c->pid) {
                    c->exited = 1;
                    tell_pid('g', c->pid);
                } else {
                    alive = 1;
                }
            }
        }
        if (!alive)
            return;
        usleep(100000);
    }
    for (int i = 0; i < MAX_CHANS; i++)
        if (chans[i].used && chans[i].pid > 0 && !chans[i].exited)
            killpg(chans[i].pid, SIGKILL);
}

void conn_main(char **argv)
{
    const char *hostkey = argv[2], *keyfile = argv[3];
    spawnctx.sbhome = argv[4];
    spawnctx.statedir = argv[5];
    cleanup_flag = argv[6] ? atoi(argv[6]) : 0;

    signal(SIGPIPE, SIG_IGN);
    signal(SIGTERM, on_term);
    signal(SIGHUP, on_term);
    fcntl(CLIENT_FD, F_SETFD, FD_CLOEXEC);
    fcntl(SUP_FD, F_SETFD, FD_CLOEXEC);

    if (strcmp(keyfile, "-") != 0 && (nkeys = load_keys(keyfile, keys, MAX_KEYS)) <= 0)
        _exit(1);

    ssh_init();
    ssh_bind bind = ssh_bind_new();
    sess = ssh_new();
    long timeout = 30;
    if (!bind || !sess || ssh_bind_options_set(bind, SSH_BIND_OPTIONS_HOSTKEY, hostkey) != SSH_OK)
        _exit(1);
    if (ssh_bind_accept_fd(bind, sess, CLIENT_FD) != SSH_OK)
        _exit(1);
    ssh_options_set(sess, SSH_OPTIONS_TIMEOUT, &timeout);

    struct ssh_server_callbacks_struct scb = {
        .auth_password_function = auth_password,
        .auth_pubkey_function = auth_pubkey,
        .channel_open_request_session_function = open_session,
    };
    ssh_callbacks_init(&scb);
    ssh_set_server_callbacks(sess, &scb);
    ssh_set_auth_methods(sess, nkeys > 0 ? SSH_AUTH_METHOD_PUBLICKEY : SSH_AUTH_METHOD_PASSWORD);

    if (ssh_handle_key_exchange(sess) != SSH_OK)
        _exit(1);

    ev = ssh_event_new();
    ssh_event_add_session(ev, sess);
    time_t t0 = time(NULL);
    while (!authed && !drop && !got_term && time(NULL) - t0 < 60)
        if (ssh_event_dopoll(ev, 1000) == SSH_ERROR)
            break;
    if (!authed) {
        ssh_disconnect(sess);
        _exit(0);
    }

    if (pipe(chld_pipe) == 0) {
        fcntl(chld_pipe[0], F_SETFL, O_NONBLOCK);
        fcntl(chld_pipe[1], F_SETFL, O_NONBLOCK);
        fcntl(chld_pipe[0], F_SETFD, FD_CLOEXEC);
        fcntl(chld_pipe[1], F_SETFD, FD_CLOEXEC);
        ssh_event_add_fd(ev, chld_pipe[0], POLLIN, on_sigchld_pipe, NULL);
        signal(SIGCHLD, on_sigchld);
    }

    while (!got_term) {
        int r = ssh_event_dopoll(ev, 1000);
        housekeeping();
        if (r == SSH_ERROR || !ssh_is_connected(sess))
            break;
    }
    shutdown_children();
    ssh_disconnect(sess);
    _exit(0);
}
