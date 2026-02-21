#pragma once

#include <stdint.h>
#include <pthread.h>
#include "config.h"
#include "combos.h"

typedef enum {
    ST_CONNECTING,
    ST_IAC,
    ST_WAIT_PROMPT,
    ST_SENT_USER,
    ST_SENT_PASS,
    ST_SEND_ENABLE,
    ST_SEND_LSHELL,
    ST_SEND_SYSTEM,
    ST_SEND_SH,
    ST_SEND_BUSYBOX,
    ST_WAIT_TOKEN
} BruteStage;

typedef struct {
    int fd;
    int port;
    int combo_idx;
    int rdbuf_pos;
    int last_recv;
    BruteStage stage;
    char address[ADDR_LEN];
    char rdbuf[RDBUF_SIZE];
} BruteConn;

extern int brute_epfd;
extern BruteConn *brute_conns;
extern pthread_mutex_t brute_conns_mutex;

extern volatile int g_brute_active;
extern volatile int g_brute_found;
extern volatile int g_brute_failed;
extern volatile int g_brute_honeypots;
extern volatile int g_brute_logged;

void brute_init(void);
void brute_start(const char *addr, int port);
void brute_disconnect(BruteConn *bc);
void brute_check_connect(int fd);
void brute_handle_data(int fd);
