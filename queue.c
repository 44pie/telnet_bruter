#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "include/config.h"
#include "include/queue.h"

Queue scan_queue;
Queue brute_queue;

void queue_create(Queue *q, int size) {
    q->entries = calloc(size, sizeof(QueueEntry));
    q->size = size;
    q->count = 0;
    pthread_mutex_init(&q->mutex, NULL);
}

int queue_push(Queue *q, const char *addr, int port) {
    pthread_mutex_lock(&q->mutex);
    for (int i = 0; i < q->size; i++) {
        if (!q->entries[i].active) {
            strncpy(q->entries[i].address, addr, ADDR_LEN - 1);
            q->entries[i].address[ADDR_LEN - 1] = 0;
            q->entries[i].port = port;
            q->entries[i].active = 1;
            ATOMIC_INC(&q->count);
            pthread_mutex_unlock(&q->mutex);
            return 0;
        }
    }
    pthread_mutex_unlock(&q->mutex);
    return -1;
}

int queue_pop(Queue *q, char *addr, int *port) {
    pthread_mutex_lock(&q->mutex);
    for (int i = 0; i < q->size; i++) {
        if (q->entries[i].active) {
            strncpy(addr, q->entries[i].address, ADDR_LEN - 1);
            addr[ADDR_LEN - 1] = 0;
            *port = q->entries[i].port;
            q->entries[i].active = 0;
            ATOMIC_DEC(&q->count);
            pthread_mutex_unlock(&q->mutex);
            return 0;
        }
    }
    pthread_mutex_unlock(&q->mutex);
    return -1;
}

int queue_count(Queue *q) {
    return ATOMIC_GET(&q->count);
}
