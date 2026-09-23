#include "sandbox.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <limits.h>
#include <libgen.h>

extern int chroot(const char *path);
extern int chdir(const char *path);

Sandbox* sandbox_init(const char *root_path) {
    Sandbox *sandbox = malloc(sizeof(Sandbox));
    if (!sandbox) return NULL;

    char *resolved = realpath(root_path, NULL);
    if (!resolved) {
        free(sandbox);
        return NULL;
    }

    struct stat sb;
    if (stat(resolved, &sb) != 0 || !S_ISDIR(sb.st_mode)) {
        free(resolved);
        free(sandbox);
        return NULL;
    }

    sandbox->root_path = malloc(PATH_MAX);
    if (!sandbox->root_path) {
        free(resolved);
        free(sandbox);
        return NULL;
    }

    strncpy(sandbox->root_path, resolved, PATH_MAX - 1);
    sandbox->root_path[PATH_MAX - 1] = '\0';

    free(resolved);
    sandbox->enabled = 1;
    return sandbox;
}

int sandbox_is_path_allowed(Sandbox *sandbox, const char *path) {
    if (!sandbox->enabled) return 1;

    char *resolved = realpath(path, NULL);
    if (!resolved) {
        return 0;
    }

    int allowed = 0;
    size_t root_len = strlen(sandbox->root_path);
    if (strncmp(resolved, sandbox->root_path, root_len) == 0) {
        if (resolved[root_len] == '\0' || resolved[root_len] == '/') {
            allowed = 1;
        }
    }

    free(resolved);
    return allowed;
}

int sandbox_enter(Sandbox *sandbox, pid_t pid __attribute__((unused))) {
    if (!sandbox->enabled) return 0;

    if (chroot(sandbox->root_path) != 0) {
        return -1;
    }

    if (chdir("/") != 0) {
        return -1;
    }

    return 0;
}

void sandbox_free(Sandbox *sandbox) {
    if (sandbox) {
        free(sandbox->root_path);
        free(sandbox);
    }
}
