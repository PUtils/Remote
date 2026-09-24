#ifndef RT_H
#define RT_H

#include <limits.h>
#include <stddef.h>
#include <sys/types.h>

#define RT_MAX_CONNS 32
#define RT_MAX_TOOLS 16

struct config {
    char self[PATH_MAX];
    char dir[PATH_MAX];
    int sandbox;
    int panel;
    int tunnel;
    int cloudflared;
    int cleanup;
    int bidi;
    int logging;
    char logdir[PATH_MAX];
    char relay[32];
    char relay_kh[PATH_MAX];
    char fingerprint[128];
    char keys[PATH_MAX];
    char state[PATH_MAX];
    char hostkey[PATH_MAX];
    char sbhome[PATH_MAX];
};

struct pwhash {
    unsigned char salt[16];
    unsigned char key[32];
    unsigned rounds;
};

int pw_set(struct pwhash *h, const char *pw);
int pw_check(const struct pwhash *h, const char *pw);

int count_keys(const char *path);
void conn_main(char **argv) __attribute__((noreturn));
void web_main(char **argv) __attribute__((noreturn));

struct spawnctx {
    char dir[PATH_MAX];
    int sandboxed;
    int peer_port;
    const char *sbhome, *statedir;
};
extern struct spawnctx spawnctx;
pid_t spawn_command(const char *cmd, int slave, const int pipes[3], char *const *cenv, int ncenv,
                    const char *term);

int sandbox_tools(const char *home, char tools[][PATH_MAX], int max);
int sandbox_profile(char *out, size_t cap, int ntools);

int supervise(struct config *cfg, struct pwhash *pw, int ssh_fd, int ssh_port,
              int http_fd, int http_port);

const char *cleanup_script(void);

void logmsg(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
int log_open(const char *dir);

#endif
