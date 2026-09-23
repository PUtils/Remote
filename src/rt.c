#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <getopt.h>
#include <libgen.h>
#include <termios.h>
#include <signal.h>
#include <sys/select.h>
#include <limits.h>
#include <stdint.h>

#ifdef __APPLE__
#include <sys/ioctl.h>
extern int cfmakeraw(struct termios *tp);
#else
#define cfmakeraw(tp) do { \
    (tp)->c_iflag &= ~(IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR | IGNCR | ICRNL | IXON); \
    (tp)->c_oflag &= ~OPOST; \
    (tp)->c_lflag &= ~(ECHO | ECHONL | ICANON | ISIG | IEXTEN); \
    (tp)->c_cflag &= ~(CSIZE | PARENB); \
    (tp)->c_cflag |= CS8; \
    (tp)->c_cc[VMIN] = 0; \
    (tp)->c_cc[VTIME] = 0; \
} while (0)
#endif

typedef struct {
    int hibernate_mode;
    int limit_directory;
    char directory[PATH_MAX];
    char socket_path[256];
    char password[256];
} Options;

int connect_socket(const char *socket_path) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        close(fd);
        return -1;
    }

    return fd;
}

int send_command(int sock, const char *cmd) {
    if (send(sock, cmd, strlen(cmd), 0) < 0) {
        perror("send");
        return -1;
    }

    char response[4096];
    int n = recv(sock, response, sizeof(response) - 1, 0);
    if (n > 0) {
        response[n] = '\0';
        printf("%s", response);
        return 0;
    }

    return -1;
}

void print_usage(const char *prog) {
    printf("Usage: %s [OPTIONS] [COMMAND]\n", prog);
    printf("\nOptions:\n");
    printf("  -l [DIRECTORY]  Start remote session (sandbox if directory given)\n");
    printf("  -h              Access hibernation control panel\n");
    printf("  -s SOCKET       Unix socket path (default: /tmp/rt.sock)\n");
    printf("  -p PASSWORD     Password for authentication\n");
    printf("  --help          Show this help message\n");
    printf("\nExamples:\n");
    printf("  %s -l                    # Start remote session in current directory\n", prog);
    printf("  %s -l /home/user/project # Start remote session in sandbox\n", prog);
    printf("  %s -h                    # Access hibernation panel\n", prog);
}

void interactive_shell(int sock, const char *session_id) {
    struct termios original, raw;
    tcgetattr(STDIN_FILENO, &original);
    raw = original;
    cfmakeraw(&raw);
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw);

    fd_set readfds;
    char buffer[4096];

    printf("Connected to session %s (type 'exit' to disconnect)\n", session_id);

    while (1) {
        FD_ZERO(&readfds);
        FD_SET(STDIN_FILENO, &readfds);
        FD_SET(sock, &readfds);

        int nfds = (sock > STDIN_FILENO) ? sock + 1 : STDIN_FILENO + 1;
        int ret = select(nfds, &readfds, NULL, NULL, NULL);

        if (ret < 0) {
            perror("select");
            break;
        }

        if (FD_ISSET(STDIN_FILENO, &readfds)) {
            int n = read(STDIN_FILENO, buffer, sizeof(buffer));
            if (n > 0) {
                if (send(sock, buffer, n, 0) < 0) {
                    perror("send");
                    break;
                }
            } else {
                break;
            }
        }

        if (FD_ISSET(sock, &readfds)) {
            int n = recv(sock, buffer, sizeof(buffer), 0);
            if (n > 0) {
                write(STDOUT_FILENO, buffer, n);
            } else {
                break;
            }
        }
    }

    tcsetattr(STDIN_FILENO, TCSAFLUSH, &original);
}

int main(int argc, char *argv[]) {
    Options opts = {
        .hibernate_mode = 0,
        .limit_directory = 0,
        .directory = {0},
        .socket_path = "/tmp/rt.sock",
        .password = {0}
    };

    int opt;
    while ((opt = getopt(argc, argv, "l::hs:p:-:")) != -1) {
        switch (opt) {
            case 'l':
                opts.limit_directory = 1;
                if (optarg) {
                    strncpy(opts.directory, optarg, sizeof(opts.directory) - 1);
                } else if (optind < argc && argv[optind][0] != '-') {
                    strncpy(opts.directory, argv[optind++], sizeof(opts.directory) - 1);
                } else {
                    char cwd[PATH_MAX];
                    if (getcwd(cwd, sizeof(cwd))) {
                        strncpy(opts.directory, cwd, sizeof(opts.directory) - 1);
                    }
                }
                break;
            case 'h':
                opts.hibernate_mode = 1;
                break;
            case 's':
                strncpy(opts.socket_path, optarg, sizeof(opts.socket_path) - 1);
                break;
            case 'p':
                strncpy(opts.password, optarg, sizeof(opts.password) - 1);
                break;
            case '-':
                if (strcmp(optarg, "help") == 0) {
                    print_usage(argv[0]);
                    return 0;
                }
                break;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    if (opts.password[0] == '\0') {
        fprintf(stderr, "Error: Password required (-p option)\n");
        return 1;
    }

    int sock = connect_socket(opts.socket_path);
    if (sock < 0) {
        fprintf(stderr, "Error: Could not connect to daemon\n");
        fprintf(stderr, "Make sure rtd is running: rtd -p <password> [-l <directory>]\n");
        return 1;
    }

    char auth_cmd[512];
    snprintf(auth_cmd, sizeof(auth_cmd), "AUTH:%s\n", opts.password);
    if (send_command(sock, auth_cmd) < 0) {
        close(sock);
        return 1;
    }

    if (opts.hibernate_mode) {
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "HIBERNATE\n");
        send_command(sock, cmd);
    } else if (opts.limit_directory) {
        char cmd[512];
        snprintf(cmd, sizeof(cmd), "SHELL:%s\n", opts.directory);
        send_command(sock, cmd);

        char response[256];
        int n = recv(sock, response, sizeof(response) - 1, 0);
        if (n > 0) {
            response[n] = '\0';
            if (strncmp(response, "OK:", 3) == 0) {
                char *session_id = response + 3;
                char *newline = strchr(session_id, '\n');
                if (newline) *newline = '\0';
                interactive_shell(sock, session_id);
            }
        }
    } else {
        print_usage(argv[0]);
    }

    close(sock);
    return 0;
}
