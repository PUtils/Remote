#ifndef SANDBOX_H
#define SANDBOX_H

#include <sys/types.h>

typedef struct {
    char *root_path;
    int enabled;
} Sandbox;

Sandbox* sandbox_init(const char *root_path);
int sandbox_enter(Sandbox *sandbox, pid_t pid);
int sandbox_is_path_allowed(Sandbox *sandbox, const char *path);
void sandbox_free(Sandbox *sandbox);

#endif
