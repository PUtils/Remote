#include "rt.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
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

#define SUP_FD 4
#define RING_SIZE 65536
#define MAX_MSG 65536
#define DETACHED_TTL (15 * 60)
#define PING_EVERY 25

static int master = -1, client = -1;
static pid_t shell = -1;
static unsigned char ring[RING_SIZE];
static size_t ring_head, ring_len;
static unsigned char in[MAX_MSG + 16];
static size_t in_len;
static unsigned char msg[MAX_MSG];
static size_t msg_len;
static volatile sig_atomic_t got_term;

static void tell(char kind, const char *s)
{
    char b[128];
    int n = snprintf(b, sizeof b, "%c%s", kind, s);
    send(SUP_FD, b, n < (int)sizeof b ? (size_t)n : sizeof b - 1, 0);
}

static void on_term(int sig)
{
    (void)sig;
    got_term = 1;
}

static int write_all(int fd, const unsigned char *p, size_t len)
{
    time_t end = time(NULL) + 10;
    while (len > 0) {
        ssize_t n = write(fd, p, len);
        if (n > 0) {
            p += n;
            len -= (size_t)n;
        } else if (n < 0 && (errno == EAGAIN || errno == EINTR) && time(NULL) < end) {
            struct pollfd pf = {fd, POLLOUT, 0};
            poll(&pf, 1, 1000);
        } else {
            return -1;
        }
    }
    return 0;
}

static void detach(void)
{
    if (client < 0)
        return;
    close(client);
    client = -1;
    in_len = msg_len = 0;
    tell('I', "browser terminal (detached)");
}

static void ws_send(int opcode, const unsigned char *p, size_t len)
{
    if (client < 0)
        return;
    unsigned char h[10];
    size_t hl = 2;
    h[0] = (unsigned char)(0x80 | opcode);
    if (len < 126) {
        h[1] = (unsigned char)len;
    } else if (len < 65536) {
        h[1] = 126;
        h[2] = (unsigned char)(len >> 8);
        h[3] = (unsigned char)len;
        hl = 4;
    } else {
        h[1] = 127;
        for (int i = 0; i < 8; i++)
            h[2 + i] = (unsigned char)((uint64_t)len >> (56 - 8 * i));
        hl = 10;
    }
    if (write_all(client, h, hl) != 0 || write_all(client, p, len) != 0)
        detach();
}

static void ring_add(const unsigned char *p, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        ring[(ring_head + ring_len) % RING_SIZE] = p[i];
        if (ring_len < RING_SIZE)
            ring_len++;
        else
            ring_head = (ring_head + 1) % RING_SIZE;
    }
}

static void replay(void)
{
    size_t first = ring_len < RING_SIZE - ring_head ? ring_len : RING_SIZE - ring_head;
    if (first)
        ws_send(2, ring + ring_head, first);
    if (ring_len > first)
        ws_send(2, ring, ring_len - first);
}

/* Messages from the page: "0" + keyboard input, or "1" + "cols,rows". */
static void handle_message(void)
{
    if (msg_len == 0)
        return;
    if (msg[0] == '0' && master >= 0) {
        write_all(master, msg + 1, msg_len - 1);
    } else if (msg[0] == '1' && msg_len < 32) {
        char tmp[32];
        memcpy(tmp, msg + 1, msg_len - 1);
        tmp[msg_len - 1] = '\0';
        int cols = 0, rows = 0;
        if (sscanf(tmp, "%d,%d", &cols, &rows) == 2 && cols > 0 && rows > 0 && cols < 1000 &&
            rows < 1000) {
            struct winsize ws = {(unsigned short)rows, (unsigned short)cols, 0, 0};
            ioctl(master, TIOCSWINSZ, &ws);
        }
    }
}

static void read_client(void)
{
    ssize_t n = read(client, in + in_len, sizeof in - in_len);
    if (n <= 0) {
        if (n == 0 || (errno != EAGAIN && errno != EINTR))
            detach();
        return;
    }
    in_len += (size_t)n;
    for (;;) {
        if (in_len < 2)
            return;
        int fin = in[0] & 0x80, op = in[0] & 0x0f, masked = in[1] & 0x80;
        uint64_t len = in[1] & 0x7f;
        size_t off = 2;
        if (len == 126) {
            if (in_len < 4)
                return;
            len = (uint64_t)in[2] << 8 | in[3];
            off = 4;
        } else if (len == 127) {
            if (in_len < 10)
                return;
            len = 0;
            for (int i = 0; i < 8; i++)
                len = len << 8 | in[2 + i];
            off = 10;
        }
        if (!masked || len > MAX_MSG) {
            detach();
            return;
        }
        if (in_len < off + 4 + len)
            return;
        const unsigned char *key = in + off, *p = in + off + 4;
        if (op == 0x8) {
            ws_send(0x8, NULL, 0);
            detach();
            return;
        }
        if (op == 0x9 || op == 0x0 || op == 0x1 || op == 0x2) {
            unsigned char tmp[125];
            unsigned char *dst = op == 0x9 ? tmp : msg + msg_len;
            if (op == 0x9 && len > sizeof tmp) {
                detach();
                return;
            }
            if (op != 0x9 && msg_len + len > MAX_MSG) {
                detach();
                return;
            }
            for (uint64_t i = 0; i < len; i++)
                dst[i] = p[i] ^ key[i % 4];
            if (op == 0x9) {
                ws_send(0xA, tmp, (size_t)len);
            } else {
                msg_len += (size_t)len;
                if (fin) {
                    handle_message();
                    msg_len = 0;
                }
            }
        }
        size_t used = off + 4 + (size_t)len;
        memmove(in, in + used, in_len - used);
        in_len -= used;
    }
}

static void receive_from_supervisor(void)
{
    char data[8];
    char cbuf[CMSG_SPACE(sizeof(int))];
    struct iovec iov = {data, sizeof data};
    struct msghdr mh = {0};
    mh.msg_iov = &iov;
    mh.msg_iovlen = 1;
    mh.msg_control = cbuf;
    mh.msg_controllen = sizeof cbuf;
    ssize_t n = recvmsg(SUP_FD, &mh, 0);
    if (n <= 0) {
        got_term = 1;
        return;
    }
    struct cmsghdr *cm = CMSG_FIRSTHDR(&mh);
    if (!cm || cm->cmsg_level != SOL_SOCKET || cm->cmsg_type != SCM_RIGHTS)
        return;
    int fd;
    memcpy(&fd, CMSG_DATA(cm), sizeof fd);
    detach();
    client = fd;
    fcntl(client, F_SETFD, FD_CLOEXEC);
    fcntl(client, F_SETFL, O_NONBLOCK);
    tell('I', "browser terminal");
    replay();
}

void web_main(char **argv)
{
    signal(SIGPIPE, SIG_IGN);
    signal(SIGTERM, on_term);
    signal(SIGHUP, on_term);
    fcntl(SUP_FD, F_SETFD, FD_CLOEXEC);
    spawnctx.sbhome = argv[2];
    spawnctx.statedir = argv[3];

    char cfgmsg[PATH_MAX + 8];
    ssize_t n = recv(SUP_FD, cfgmsg, sizeof cfgmsg - 1, 0);
    if (n < 3 || cfgmsg[0] != 'C')
        _exit(1);
    cfgmsg[n] = '\0';
    spawnctx.sandboxed = cfgmsg[1] == '1';
    strlcpy(spawnctx.dir, cfgmsg + 2, sizeof spawnctx.dir);

    struct winsize ws = {24, 80, 0, 0};
    int slave;
    if (openpty(&master, &slave, NULL, NULL, &ws) != 0)
        _exit(1);
    fcntl(master, F_SETFD, FD_CLOEXEC);
    shell = spawn_command(NULL, slave, NULL, NULL, 0, "xterm-256color");
    close(slave);
    if (shell < 0)
        _exit(1);
    char g[16];
    snprintf(g, sizeof g, "%d", (int)shell);
    tell('G', g);
    tell('I', "browser terminal (waiting)");

    time_t detached_at = time(NULL), last_ping = time(NULL);
    while (!got_term) {
        struct pollfd pf[3] = {{SUP_FD, POLLIN, 0}, {master, POLLIN, 0}, {client, POLLIN, 0}};
        int np = client >= 0 ? 3 : 2;
        if (poll(pf, (nfds_t)np, 1000) < 0 && errno != EINTR)
            break;
        if (pf[0].revents & (POLLIN | POLLHUP))
            receive_from_supervisor();
        if (pf[1].revents & (POLLIN | POLLHUP | POLLERR)) {
            unsigned char buf[16384];
            ssize_t r = read(master, buf, sizeof buf);
            if (r > 0) {
                ring_add(buf, (size_t)r);
                ws_send(2, buf, (size_t)r);
            } else if (r == 0 || errno != EAGAIN) {
                break;
            }
        }
        if (np == 3 && client >= 0 && (pf[2].revents & (POLLIN | POLLHUP | POLLERR)))
            read_client();

        time_t now = time(NULL);
        if (client >= 0) {
            detached_at = now;
            if (now - last_ping >= PING_EVERY) {
                ws_send(0x9, NULL, 0);
                last_ping = now;
            }
        } else if (now - detached_at > DETACHED_TTL) {
            break;
        }
        if (waitpid(shell, NULL, WNOHANG) == shell) {
            shell = -1;
            break;
        }
    }

    if (client >= 0) {
        static const unsigned char bye[] = {0x03, 0xe8};
        ws_send(0x8, bye, sizeof bye);
    }
    if (shell > 0) {
        killpg(shell, SIGHUP);
        for (int i = 0; i < 20 && waitpid(shell, NULL, WNOHANG) == 0; i++)
            usleep(100000);
        killpg(shell, SIGKILL);
    }
    tell('g', g);
    _exit(0);
}
