#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <termios.h>
#include <getopt.h>
#include <limits.h>
#include <stdint.h>

#ifdef __APPLE__
#include <util.h>
#else
#include <pty.h>
#endif

#include "auth.h"
#include "session.h"
#include "sandbox.h"

typedef struct {
    AuthContext *auth;
    SessionManager *sessions;
    Sandbox *sandbox;
    int running;
    char socket_path[256];
    int listen_fd;
    pthread_mutex_t shutdown_lock;
} DaemonContext;

DaemonContext *daemon_ctx = NULL;

void signal_handler(int sig __attribute__((unused))) {
    if (daemon_ctx) {
        daemon_ctx->running = 0;
    }
}

void print_usage(const char *prog) {
    printf("Usage: %s [OPTIONS]\n", prog);
    printf("Options:\n");
    printf("  -p PASSWORD    Set authentication password\n");
    printf("  -l DIRECTORY   Enable sandbox mode with root directory\n");
    printf("  -s SOCKET      Unix socket path (default: /tmp/rt.sock)\n");
    printf("  -h             Show this help message\n");
}

int setup_socket(const char *socket_path) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }

    unlink(socket_path);

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(fd);
        return -1;
    }

    if (listen(fd, 5) < 0) {
        perror("listen");
        close(fd);
        return -1;
    }

    chmod(socket_path, 0600);
    return fd;
}

int spawn_shell(const char *cwd, Sandbox *sandbox) {
    int master, slave;

    if (openpty(&master, &slave, NULL, NULL, NULL) < 0) {
        perror("openpty");
        return -1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        close(master);
        close(slave);
        return -1;
    }

    if (pid == 0) {
        close(master);
        setsid();
        ioctl(slave, TIOCSCTTY, 0);
        dup2(slave, STDIN_FILENO);
        dup2(slave, STDOUT_FILENO);
        dup2(slave, STDERR_FILENO);
        close(slave);

        if (chdir(cwd) != 0) {
            perror("chdir");
            exit(1);
        }

        if (sandbox && sandbox_enter(sandbox, getpid()) != 0) {
            perror("sandbox_enter");
            exit(1);
        }

        char *shell = getenv("SHELL");
        if (!shell) shell = "/bin/bash";

        execl(shell, shell, NULL);
        perror("execl");
        exit(1);
    }

    close(slave);
    fcntl(master, F_SETFL, O_NONBLOCK);

    return master;
}

void* handle_client(void *arg) {
    int client_fd = (intptr_t)arg;
    char buffer[4096];
    int authenticated = 0;

    while (daemon_ctx->running) {
        if (daemon_ctx->sessions->hibernation_mode && authenticated) {
            dprintf(client_fd, "ERR:System in hibernation\n");
            break;
        }

        int n = read(client_fd, buffer, sizeof(buffer) - 1);
        if (n <= 0) break;

        buffer[n] = '\0';

        char *cmd = buffer;
        char *arg = NULL;
        char *p = strchr(buffer, ':');
        if (p) {
            *p = '\0';
            arg = p + 1;
        }

        if (strcmp(cmd, "AUTH") == 0 && arg) {
            if (auth_verify(daemon_ctx->auth, arg)) {
                authenticated = 1;
                dprintf(client_fd, "OK:Authenticated\n");
            } else {
                dprintf(client_fd, "ERR:Invalid password\n");
            }
        } else if (!authenticated) {
            dprintf(client_fd, "ERR:Not authenticated\n");
        } else if (strcmp(cmd, "SHELL") == 0) {
            Session *session = session_create(arg ? arg : "/");
            if (!session) {
                dprintf(client_fd, "ERR:Failed to create session\n");
                continue;
            }

            int shell_fd = spawn_shell(session->cwd, daemon_ctx->sandbox);
            if (shell_fd < 0) {
                dprintf(client_fd, "ERR:Failed to spawn shell\n");
                session_free(session);
                continue;
            }

            session->shell_fd = shell_fd;
            if (session_manager_add(daemon_ctx->sessions, session) < 0) {
                dprintf(client_fd, "ERR:Failed to add session\n");
                close(shell_fd);
                session_free(session);
                continue;
            }

            dprintf(client_fd, "OK:%s\n", session->id);
        } else if (strcmp(cmd, "CD") == 0 && arg) {
            Session *session = session_get(daemon_ctx->sessions, arg);
            if (session) {
                char *newdir = strchr(arg, ':');
                if (newdir) {
                    newdir++;
                    if (!daemon_ctx->sandbox || sandbox_is_path_allowed(daemon_ctx->sandbox, newdir)) {
                        session_change_dir(session, newdir);
                        dprintf(client_fd, "OK:Changed directory\n");
                    } else {
                        dprintf(client_fd, "ERR:Path not allowed\n");
                    }
                }
            } else {
                dprintf(client_fd, "ERR:Session not found\n");
            }
        } else if (strcmp(cmd, "HIBERNATE") == 0) {
            session_manager_hibernate(daemon_ctx->sessions);
            dprintf(client_fd, "OK:Hibernation enabled\n");
        } else if (strcmp(cmd, "WAKE") == 0) {
            session_manager_wake(daemon_ctx->sessions);
            dprintf(client_fd, "OK:Hibernation disabled\n");
        } else {
            dprintf(client_fd, "ERR:Unknown command\n");
        }
    }

    close(client_fd);
    return NULL;
}

int main(int argc, char *argv[]) {
    char password[256] = {0};
    char sandbox_path[PATH_MAX] = {0};
    char socket_path[256] = "/tmp/rt.sock";
    int opt;

    while ((opt = getopt(argc, argv, "p:l:s:h")) != -1) {
        switch (opt) {
            case 'p':
                strncpy(password, optarg, sizeof(password) - 1);
                break;
            case 'l':
                strncpy(sandbox_path, optarg, sizeof(sandbox_path) - 1);
                break;
            case 's':
                strncpy(socket_path, optarg, sizeof(socket_path) - 1);
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    if (password[0] == '\0') {
        fprintf(stderr, "Error: Password required (-p option)\n");
        return 1;
    }

    daemon_ctx = malloc(sizeof(DaemonContext));
    if (!daemon_ctx) {
        perror("malloc");
        return 1;
    }

    daemon_ctx->auth = auth_init(password, 5, 30);
    if (!daemon_ctx->auth) {
        fprintf(stderr, "Failed to initialize authentication\n");
        free(daemon_ctx);
        return 1;
    }

    daemon_ctx->sessions = session_manager_init();
    if (!daemon_ctx->sessions) {
        fprintf(stderr, "Failed to initialize session manager\n");
        auth_free(daemon_ctx->auth);
        free(daemon_ctx);
        return 1;
    }

    daemon_ctx->sandbox = NULL;
    if (sandbox_path[0] != '\0') {
        daemon_ctx->sandbox = sandbox_init(sandbox_path);
        if (!daemon_ctx->sandbox) {
            fprintf(stderr, "Failed to initialize sandbox\n");
            session_manager_free(daemon_ctx->sessions);
            auth_free(daemon_ctx->auth);
            free(daemon_ctx);
            return 1;
        }
    }

    strncpy(daemon_ctx->socket_path, socket_path, sizeof(daemon_ctx->socket_path) - 1);
    daemon_ctx->running = 1;
    pthread_mutex_init(&daemon_ctx->shutdown_lock, NULL);

    daemon_ctx->listen_fd = setup_socket(socket_path);
    if (daemon_ctx->listen_fd < 0) {
        fprintf(stderr, "Failed to set up socket\n");
        if (daemon_ctx->sandbox) sandbox_free(daemon_ctx->sandbox);
        session_manager_free(daemon_ctx->sessions);
        auth_free(daemon_ctx->auth);
        free(daemon_ctx);
        return 1;
    }

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    printf("rtd: Listening on %s\n", socket_path);

    while (daemon_ctx->running) {
        int client_fd = accept(daemon_ctx->listen_fd, NULL, NULL);
        if (client_fd < 0) {
            if (daemon_ctx->running) perror("accept");
            continue;
        }

        pthread_t thread;
        if (pthread_create(&thread, NULL, handle_client, (void *)(intptr_t)client_fd) != 0) {
            perror("pthread_create");
            close(client_fd);
        } else {
            pthread_detach(thread);
        }
    }

    close(daemon_ctx->listen_fd);
    unlink(socket_path);

    if (daemon_ctx->sandbox) sandbox_free(daemon_ctx->sandbox);
    session_manager_free(daemon_ctx->sessions);
    auth_free(daemon_ctx->auth);
    pthread_mutex_destroy(&daemon_ctx->shutdown_lock);
    free(daemon_ctx);

    printf("rtd: Shutdown complete\n");
    return 0;
}
