#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/tcp.h>

#include "include/config.h"
#include "include/scanner.h"
#include "include/queue.h"

int scan_epfd = -1;
ScanConn *scan_conns = NULL;
pthread_mutex_t scan_conns_mutex = PTHREAD_MUTEX_INITIALIZER;

volatile int g_scan_total = 0;
volatile int g_scan_active = 0;
volatile int g_scan_open = 0;

typedef struct { uint32_t start; uint32_t end; } Range;

static Range bogons[] = {
    {0x00000000, 0x00FFFFFF},
    {0x0A000000, 0x0AFFFFFF},
    {0x64400000, 0x647FFFFF},
    {0x7F000000, 0x7FFFFFFF},
    {0xA9FE0000, 0xA9FEFFFF},
    {0xAC100000, 0xAC1FFFFF},
    {0xC0000000, 0xC00000FF},
    {0xC0A80000, 0xC0A8FFFF},
    {0xC6120000, 0xC613FFFF},
    {0xC6336400, 0xC63364FF},
    {0xCB007100, 0xCB0071FF},
    {0xE0000000, 0xEFFFFFFF},
    {0xF0000000, 0xFFFFFFFF},
};

int is_bogon(uint32_t ip) {
    for (int i = 0; i < (int)(sizeof(bogons)/sizeof(bogons[0])); i++) {
        if (ip >= bogons[i].start && ip <= bogons[i].end)
            return 1;
    }
    return 0;
}

uint32_t random_ip(void) {
    uint32_t ip;
    do {
        ip = ((uint32_t)rand() << 16) ^ (uint32_t)rand();
    } while (is_bogon(ip));
    return ip;
}

void ip_to_str(uint32_t ip, char *buf) {
    snprintf(buf, 16, "%u.%u.%u.%u",
        (ip >> 24) & 0xFF,
        (ip >> 16) & 0xFF,
        (ip >> 8)  & 0xFF,
         ip        & 0xFF);
}

int parse_range(const char *input, uint32_t *start, uint32_t *end) {
    char buf[64];
    strncpy(buf, input, sizeof(buf)-1);
    buf[sizeof(buf)-1] = 0;

    char *slash = strchr(buf, '/');
    if (slash) {
        *slash = 0;
        int prefix = atoi(slash + 1);
        if (prefix < 0 || prefix > 32) return -1;

        struct in_addr addr;
        if (inet_pton(AF_INET, buf, &addr) != 1) return -1;

        uint32_t ip = ntohl(addr.s_addr);
        uint32_t mask = (prefix == 0) ? 0 : (~0U << (32 - prefix));
        uint32_t net = ip & mask;
        uint32_t bcast = ip | ~mask;

        if (prefix >= 31) {
            *start = net;
            *end = bcast;
        } else {
            *start = net + 1;
            *end = bcast - 1;
        }
        if (*start > *end) return -1;
        return 0;
    }

    char *dash = strchr(buf, '-');
    if (dash) {
        *dash = 0;
        struct in_addr a1, a2;
        if (inet_pton(AF_INET, buf, &a1) != 1) return -1;
        if (inet_pton(AF_INET, dash+1, &a2) != 1) return -1;
        *start = ntohl(a1.s_addr);
        *end = ntohl(a2.s_addr);
        if (*start > *end) return -1;
        return 0;
    }

    struct in_addr addr;
    if (inet_pton(AF_INET, buf, &addr) != 1) return -1;
    *start = ntohl(addr.s_addr);
    *end = *start;
    return 0;
}

void scan_init(void) {
    scan_epfd = epoll_create1(0);
    scan_conns = calloc(MAX_FDS, sizeof(ScanConn));
}

void scan_disconnect(ScanConn *sc) {
    if (sc->fd > 0) {
        epoll_ctl(scan_epfd, EPOLL_CTL_DEL, sc->fd, NULL);
        close(sc->fd);
    }
    memset(sc, 0, sizeof(ScanConn));
    ATOMIC_DEC(&g_scan_active);
}

void scan_start(const char *addr, int port) {
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (fd < 0 || fd >= MAX_FDS) {
        if (fd >= 0) close(fd);
        return;
    }

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    inet_pton(AF_INET, addr, &sa.sin_addr);

    connect(fd, (struct sockaddr *)&sa, sizeof(sa));

    ScanConn *sc = &scan_conns[fd];
    memset(sc, 0, sizeof(ScanConn));
    sc->fd = fd;
    sc->port = port;
    sc->last_time = time(NULL);
    strncpy(sc->address, addr, ADDR_LEN - 1);

    struct epoll_event ev;
    ev.events = EPOLLOUT | EPOLLERR | EPOLLHUP | EPOLLET;
    ev.data.fd = fd;
    epoll_ctl(scan_epfd, EPOLL_CTL_ADD, fd, &ev);

    ATOMIC_INC(&g_scan_active);
    ATOMIC_INC(&g_scan_total);
}

void scan_check_connect(int fd) {
    ScanConn *sc = &scan_conns[fd];
    if (sc->fd <= 0) return;

    int err = 0;
    socklen_t len = sizeof(err);
    getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len);

    if (err == 0) {
        ATOMIC_INC(&g_scan_open);
        while (queue_push(&brute_queue, sc->address, sc->port) != 0) {
            usleep(1000);
        }
    }

    scan_disconnect(sc);
}
