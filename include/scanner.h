#pragma once

#include <stdint.h>
#include <pthread.h>
#include "config.h"

typedef struct {
    int fd;
    int port;
    int last_time;
    char address[ADDR_LEN];
} ScanConn;

extern int scan_epfd;
extern ScanConn *scan_conns;
extern pthread_mutex_t scan_conns_mutex;

extern volatile int g_scan_total;
extern volatile int g_scan_active;
extern volatile int g_scan_open;

void scan_init(void);
void scan_start(const char *addr, int port);
void scan_check_connect(int fd);
void scan_disconnect(ScanConn *sc);

uint32_t random_ip(void);
void ip_to_str(uint32_t ip, char *buf);
int is_bogon(uint32_t ip);
int parse_range(const char *input, uint32_t *start, uint32_t *end);
