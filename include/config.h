#pragma once

#define SCAN_TIMEOUT_SEC    2
#define BRUTE_TIMEOUT_SEC   15
#define BRUTE_CONNECT_SEC   3
#define MAX_FDS             65536
#define MAX_SCAN_ACTIVE     5000
#define MAX_BRUTE_ACTIVE    500
#define RDBUF_SIZE          4096
#define SCAN_QUEUE_SIZE     500000
#define BRUTE_QUEUE_SIZE    100000
#define MAX_COMBOS          256
#define ADDR_LEN            16

#define ATOMIC_ADD(ptr, i) __sync_fetch_and_add((ptr), i)
#define ATOMIC_SUB(ptr, i) __sync_fetch_and_sub((ptr), i)
#define ATOMIC_INC(ptr)    ATOMIC_ADD((ptr), 1)
#define ATOMIC_DEC(ptr)    ATOMIC_SUB((ptr), 1)
#define ATOMIC_GET(ptr)    ATOMIC_ADD((ptr), 0)
