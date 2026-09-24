#include "rt.h"

#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

struct spawnctx spawnctx;

static const char *user_shell(void)
{
    struct passwd *pw = getpwuid(getuid());
    return pw && pw->pw_shell && pw->pw_shell[0] ? pw->pw_shell : "/bin/zsh";
}

static char **build_env(char *const *cenv, int ncenv, const char *shell, const char *term)
{
    struct passwd *pw = getpwuid(getuid());
    const char *home = spawnctx.sandboxed ? spawnctx.sbhome : pw->pw_dir;
    const char *path = getenv("PATH");
    const char *tmp = getenv("TMPDIR");
    char **e = calloc((size_t)ncenv + 12, sizeof *e);
    int n = 0;
    for (int i = 0; i < ncenv; i++)
        e[n++] = strdup(cenv[i]);
    asprintf(&e[n++], "PATH=%s", path ? path : "/usr/bin:/bin:/usr/sbin:/sbin");
    asprintf(&e[n++], "HOME=%s", home);
    asprintf(&e[n++], "USER=%s", pw->pw_name);
    asprintf(&e[n++], "LOGNAME=%s", pw->pw_name);
    asprintf(&e[n++], "SHELL=%s", shell);
    if (spawnctx.sandboxed)
        asprintf(&e[n++], "TMPDIR=%s/.tmp", spawnctx.sbhome);
    else
        asprintf(&e[n++], "TMPDIR=%s", tmp ? tmp : "/tmp");
    e[n++] = strdup("LANG=en_US.UTF-8");
    if (term)
        asprintf(&e[n++], "TERM=%s", term[0] ? term : "xterm-256color");
    if (spawnctx.sandboxed)
        e[n++] = strdup("RT_SANDBOX=1");
    e[n] = NULL;
    return e;
}

pid_t spawn_command(const char *cmd, int slave, const int pipes[3], char *const *cenv, int ncenv,
                    const char *term)
{
    const char *shell = user_shell();
    struct passwd *pw = getpwuid(getuid());
    static char profile[8192];
    static char tools[RT_MAX_TOOLS][PATH_MAX];
    static char defs[RT_MAX_TOOLS + 4][PATH_MAX + 16];
    char *argv[2 * (RT_MAX_TOOLS + 4) + 8];
    int a = 0;

    if (spawnctx.sandboxed) {
        int nt = sandbox_tools(pw->pw_dir, tools, RT_MAX_TOOLS);
        if (sandbox_profile(profile, sizeof profile, nt) != 0)
            return -1;
        argv[a++] = "/usr/bin/sandbox-exec";
        argv[a++] = "-p";
        argv[a++] = profile;
        int d = 0;
        snprintf(defs[d], sizeof defs[d], "HOME=%s", pw->pw_dir);
        snprintf(defs[++d], sizeof defs[d], "DIR=%s", spawnctx.dir);
        snprintf(defs[++d], sizeof defs[d], "STATE=%s", spawnctx.statedir);
        snprintf(defs[++d], sizeof defs[d], "SBHOME=%s", spawnctx.sbhome);
        for (int i = 0; i < nt; i++)
            snprintf(defs[++d], sizeof defs[d], "T%d=%s", i, tools[i]);
        for (int i = 0; i <= d; i++) {
            argv[a++] = "-D";
            argv[a++] = defs[i];
        }
    }
    argv[a++] = (char *)shell;
    if (cmd) {
        argv[a++] = "-c";
        argv[a++] = (char *)cmd;
    } else {
        argv[a++] = "-l";
    }
    argv[a] = NULL;

    char **envp = build_env(cenv, ncenv, shell, slave >= 0 ? term : NULL);
    pid_t pid = fork();
    if (pid == 0) {
        setsid();
        if (slave >= 0) {
            ioctl(slave, TIOCSCTTY, 0);
            dup2(slave, 0);
            dup2(slave, 1);
            dup2(slave, 2);
        } else {
            dup2(pipes[0], 0);
            dup2(pipes[1], 1);
            dup2(pipes[2], 2);
        }
        for (int fd = 3, max = getdtablesize(); fd < max; fd++)
            close(fd);
        for (int sig = 1; sig < NSIG; sig++)
            signal(sig, SIG_DFL);
        sigset_t none;
        sigemptyset(&none);
        sigprocmask(SIG_SETMASK, &none, NULL);
        if (chdir(spawnctx.dir) != 0) {
            dprintf(2, "rt: cannot enter %s\n", spawnctx.dir);
            _exit(126);
        }
        execve(argv[0], argv, envp);
        dprintf(2, "rt: cannot run %s\n", argv[0]);
        _exit(127);
    }
    for (int i = 0; envp[i]; i++)
        free(envp[i]);
    free(envp);
    return pid;
}
