#define __STDC_WANT_LIB_EXT1__ 1
#include "rt.h"

#include <errno.h>
#include <fcntl.h>
#include <libssh/libssh.h>
#include <mach-o/dyld.h>
#include <netinet/in.h>
#include <pwd.h>
#include <readpassphrase.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#define MIN_PASSWORD 12

static const char *prog = "rt";

static void usage(FILE *f)
{
    fprintf(f,
            "usage: %s [-l [dir]] [-h] [-k keyfile] [-n] [-c] [-w [dir]]\n"
            "  -l [dir]   sandbox sessions to dir (default: current directory)\n"
            "  -h         phone panel: hibernate/wake, change directory, close sessions\n"
            "  -k file    also require an SSH key listed in file\n"
            "  -n         no relay or Cloudflare tunnel; listen on localhost only\n"
            "  -c         clean up shell history and SSH config after disconnect\n"
            "  -w [dir]   also append the log to dir/rt.log (default: current directory)\n"
            "rt and remote are the same command. See man rt.\n",
            prog);
}

static int mkdirs(const char *path)
{
    char tmp[PATH_MAX];
    strlcpy(tmp, path, sizeof tmp);
    for (char *p = tmp + 1; *p; p++) {
        if (*p != '/')
            continue;
        *p = '\0';
        if (mkdir(tmp, 0700) != 0 && errno != EEXIST)
            return -1;
        *p = '/';
    }
    if (mkdir(tmp, 0700) != 0 && errno != EEXIST)
        return -1;
    return chmod(tmp, 0700);
}

static int listen_local(int *port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    fcntl(fd, F_SETFD, FD_CLOEXEC);
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t al = sizeof a;
    if (bind(fd, (struct sockaddr *)&a, sizeof a) != 0 || listen(fd, 16) != 0 ||
        getsockname(fd, (struct sockaddr *)&a, &al) != 0) {
        close(fd);
        return -1;
    }
    *port = ntohs(a.sin_port);
    return fd;
}

static int host_key(const char *path, char *fp, size_t cap)
{
    ssh_key key = NULL;
    if (access(path, R_OK) != 0) {
        if (ssh_pki_generate_key(SSH_KEYTYPE_ED25519, NULL, &key) != SSH_OK ||
            ssh_pki_export_privkey_file(key, NULL, NULL, NULL, path) != SSH_OK)
            return -1;
        chmod(path, 0600);
    } else if (ssh_pki_import_privkey_file(path, NULL, NULL, NULL, &key) != SSH_OK) {
        return -1;
    }
    unsigned char *hash = NULL;
    size_t hlen = 0;
    int ok = ssh_get_publickey_hash(key, SSH_PUBLICKEY_HASH_SHA256, &hash, &hlen) == 0;
    if (ok) {
        char *s = ssh_get_fingerprint_hash(SSH_PUBLICKEY_HASH_SHA256, hash, hlen);
        strlcpy(fp, s ? s : "?", cap);
        ssh_string_free_char(s);
        ssh_clean_pubkey_hash(&hash);
    }
    ssh_key_free(key);
    return ok ? 0 : -1;
}

#define RELAY_ALPHABET "abcdefghjkmnpqrstuvwxyz23456789"

/*
 * A random name, kept across runs so the join command stays the same. It is
 * short and avoids look-alike characters because people type it by hand.
 */
static int relay_name(const char *state, char *out, size_t cap)
{
    char path[PATH_MAX];
    snprintf(path, sizeof path, "%s/relay_name", state);
    FILE *f = fopen(path, "r");
    if (f) {
        int ok = fgets(out, (int)cap, f) != NULL;
        fclose(f);
        out[strcspn(out, "\r\n")] = '\0';
        if (ok && strlen(out) == 11 && strncmp(out, "rt-", 3) == 0 &&
            strspn(out + 3, RELAY_ALPHABET) == 8)
            return 0;
    }
    snprintf(out, cap, "rt-");
    for (int i = 0; i < 8; i++)
        out[3 + i] = RELAY_ALPHABET[arc4random_uniform(sizeof RELAY_ALPHABET - 1)];
    out[11] = '\0';
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0)
        return -1;
    dprintf(fd, "%s\n", out);
    close(fd);
    return 0;
}

static int read_password(struct pwhash *h)
{
    char a[1025], b[1025];
    int rc = -1;
    if (!readpassphrase("Set a password for this rt session: ", a, sizeof a, RPP_REQUIRE_TTY)) {
        fprintf(stderr, "rt: a terminal is needed to set the password\n");
        return -1;
    }
    if (strlen(a) < MIN_PASSWORD) {
        fprintf(stderr, "rt: use at least %d characters\n", MIN_PASSWORD);
    } else if (!readpassphrase("Repeat it: ", b, sizeof b, RPP_REQUIRE_TTY) || strcmp(a, b) != 0) {
        fprintf(stderr, "rt: passwords do not match\n");
    } else if (pw_set(h, a) != 0) {
        fprintf(stderr, "rt: could not hash the password\n");
    } else {
        rc = 0;
    }
    memset_s(a, sizeof a, 0, sizeof a);
    memset_s(b, sizeof b, 0, sizeof b);
    return rc;
}

static void keep_awake(void)
{
    char pid[16];
    snprintf(pid, sizeof pid, "%d", (int)getpid());
    pid_t p = fork();
    if (p == 0) {
        setsid();
        int null = open("/dev/null", O_RDWR);
        dup2(null, 0);
        dup2(null, 1);
        dup2(null, 2);
        execl("/usr/bin/caffeinate", "caffeinate", "-i", "-s", "-w", pid, (char *)NULL);
        _exit(127);
    }

    FILE *f = popen("/usr/bin/pmset -g", "r");
    char line[256];
    int disabled = 0;
    while (f && fgets(line, sizeof line, f))
        if (strstr(line, "SleepDisabled"))
            disabled = atoi(line + strcspn(line, "0123456789")) == 1;
    if (f)
        pclose(f);
    if (!disabled)
        fprintf(stderr, "rt: the Mac will still sleep with the lid closed; "
                        "`sudo pmset -a disablesleep 1` prevents that (`0` undoes it)\n");
}

int main(int argc, char **argv)
{
    if (argc == 7 && strcmp(argv[1], "--conn") == 0)
        conn_main(argv);
    if (argc == 4 && strcmp(argv[1], "--web") == 0)
        web_main(argv);

    const char *base = strrchr(argv[0], '/');
    prog = strcmp(base ? base + 1 : argv[0], "remote") == 0 ? "remote" : "rt";

    static struct config cfg;
    const char *dirarg = NULL, *keyarg = NULL, *logarg = NULL;
    cfg.tunnel = 1;
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (strcmp(a, "--help") == 0) {
            usage(stdout);
            return 0;
        }
        if (a[0] != '-' || a[1] == '\0') {
            usage(stderr);
            return 2;
        }
        for (const char *p = a + 1; *p; p++) {
            switch (*p) {
            case 'l':
                cfg.sandbox = 1;
                if (p[1] == '\0' && i + 1 < argc && argv[i + 1][0] != '-')
                    dirarg = argv[++i];
                break;
            case 'h': cfg.panel = 1; break;
            case 'n': cfg.tunnel = 0; break;
            case 'c': cfg.cleanup = 1; break;
            case 'w':
                cfg.logging = 1;
                if (p[1] == '\0' && i + 1 < argc && argv[i + 1][0] != '-')
                    logarg = argv[++i];
                break;
            case 'k':
                if (p[1] != '\0' || i + 1 >= argc) {
                    usage(stderr);
                    return 2;
                }
                keyarg = argv[++i];
                break;
            default:
                usage(stderr);
                return 2;
            }
        }
    }

    uint32_t sl = sizeof cfg.self;
    char exe[PATH_MAX];
    if (_NSGetExecutablePath(exe, &sl) != 0 || !realpath(exe, cfg.self)) {
        fprintf(stderr, "rt: cannot locate own executable\n");
        return 1;
    }
    if (!realpath(dirarg ? dirarg : ".", cfg.dir)) {
        fprintf(stderr, "rt: %s: %s\n", dirarg ? dirarg : ".", strerror(errno));
        return 1;
    }
    struct stat st;
    if (stat(cfg.dir, &st) != 0 || !S_ISDIR(st.st_mode)) {
        fprintf(stderr, "rt: %s is not a directory\n", cfg.dir);
        return 1;
    }
    if (cfg.logging) {
        if (!realpath(logarg ? logarg : ".", cfg.logdir)) {
            fprintf(stderr, "rt: %s: %s\n", logarg ? logarg : ".", strerror(errno));
            return 1;
        }
        if (stat(cfg.logdir, &st) != 0 || !S_ISDIR(st.st_mode)) {
            fprintf(stderr, "rt: %s is not a directory\n", cfg.logdir);
            return 1;
        }
    }
    if (keyarg) {
        if (!realpath(keyarg, cfg.keys) || count_keys(cfg.keys) <= 0) {
            fprintf(stderr, "rt: %s has no usable public keys\n", keyarg);
            return 1;
        }
    }
    cfg.cloudflared = cfg.tunnel && system("command -v cloudflared >/dev/null 2>&1") == 0;
    if (cfg.panel && cfg.tunnel && !cfg.cloudflared) {
        fprintf(stderr, "rt: the phone panel needs cloudflared (brew install cloudflared)\n");
        return 1;
    }

    struct passwd *pwent = getpwuid(getuid());
    snprintf(cfg.state, sizeof cfg.state, "%s/.local/state/rt", pwent->pw_dir);
    snprintf(cfg.hostkey, sizeof cfg.hostkey, "%s/host_ed25519", cfg.state);
    snprintf(cfg.sbhome, sizeof cfg.sbhome, "%s/home", cfg.state);
    char sbtmp[PATH_MAX];
    snprintf(sbtmp, sizeof sbtmp, "%s/.tmp", cfg.sbhome);
    if (mkdirs(cfg.state) != 0 || mkdirs(cfg.sbhome) != 0 || mkdirs(sbtmp) != 0) {
        fprintf(stderr, "rt: cannot create %s\n", cfg.state);
        return 1;
    }

    snprintf(cfg.relay_kh, sizeof cfg.relay_kh, "%s/relay_known_hosts", cfg.state);
    if (relay_name(cfg.state, cfg.relay, sizeof cfg.relay) != 0) {
        fprintf(stderr, "rt: cannot create the relay name in %s\n", cfg.state);
        return 1;
    }

    char *fp = cfg.fingerprint;
    if (host_key(cfg.hostkey, fp, sizeof cfg.fingerprint) != 0) {
        fprintf(stderr, "rt: cannot load or create host key %s\n", cfg.hostkey);
        return 1;
    }

    static struct pwhash pw;
    if (read_password(&pw) != 0)
        return 1;

    int ssh_port, http_port = 0, http_fd = -1;
    int ssh_fd = listen_local(&ssh_port);
    if (ssh_fd < 0 || (cfg.panel && (http_fd = listen_local(&http_port)) < 0)) {
        fprintf(stderr, "rt: cannot listen on localhost\n");
        return 1;
    }

    if (cfg.logging && log_open(cfg.logdir) != 0) {
        fprintf(stderr, "rt: cannot write %s/rt.log\n", cfg.logdir);
        return 1;
    }
    keep_awake();
    logmsg("host key %s", fp);
    logmsg("directory %s (%s)", cfg.dir, cfg.sandbox ? "sandboxed" : "full access");
    logmsg("ssh on 127.0.0.1:%d%s", ssh_port, cfg.keys[0] ? " (key + password)" : "");
    if (cfg.panel)
        logmsg("panel on http://127.0.0.1:%d", http_port);
    else
        logmsg("phone panel is off; start with `rt -h` to hibernate/wake from your phone");
    return supervise(&cfg, &pw, ssh_fd, ssh_port, http_fd, http_port);
}
