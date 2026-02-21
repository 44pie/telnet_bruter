#pragma once

#include <pthread.h>
#include "config.h"

typedef struct {
    char address[ADDR_LEN];
    int port;
    int active;
} QueueEntry;

typedef struct {
    QueueEntry *entries;
    int size;
    volatile int count;
    pthread_mutex_t mutex;
} Queue;

extern Queue scan_queue;
extern Queue brute_queue;

void queue_create(Queue *q, int size);
int queue_push(Queue *q, const char *addr, int port);
int queue_pop(Queue *q, char *addr, int *port);
int queue_count(Queue *q);
