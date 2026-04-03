#include "scanner.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/uio.h>

static void print_banner(void) {
    // taglines
    static const char *taglines[] = {
        "Nmap slow? Ewww...",
        "Rustscan who?",
        "Half-open ports, fully open secrets.",
        "We don't knock. We peek.",
        "Sending RSTs since day one.",
        "Your firewall called. It's scared.",
        "Nmap, Rustscan, Masscan can eat my ahh-",
        "Fragmented packets, unfragmented results.",
        "Slow scan? Only if you want it.",
        "Zero handshakes. All the info.",
        "We found your ports before you knew they were open.",
    };

    int n = sizeof(taglines) / sizeof(taglines[0]);
    srand((unsigned)time(NULL));
    const char *tag = taglines[rand() % n];

    printf("\033[1;36m");   /* bold cyan */
    printf("                                                        \n");
    printf("  ███████╗███████╗██████╗  ██████╗ ███╗   ███╗ █████╗ ██████╗ \n");
    printf("     ███╔╝██╔════╝██╔══██╗██╔═══██╗████╗ ████║██╔══██╗██╔══██╗\n");
    printf("    ███╔╝ █████╗  ██████╔╝██║   ██║██╔████╔██║███████║██████╔╝\n");
    printf("   ███╔╝  ██╔══╝  ██╔══██╗██║   ██║██║╚██╔╝██║██╔══██║██╔═══╝ \n");
    printf("  ███████╗███████╗██║  ██║╚██████╔╝██║ ╚═╝ ██║██║  ██║██║     \n");
    printf("  ╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝     \n");
    printf("\033[0m");      /* reset */

    printf("\033[0;36m");   /* dim cyan */
    printf("Z E R O M A P  —  G o d s p e e d  E d i t i o n\n");
    printf("\033[0m");

    printf("\033[1;33m");   /* bold yellow */
    printf("[ %s ]\n", tag);
    printf("\033[0m");

    printf("\033[0;90m");   /* dark grey */
    printf("         Raw sockets · Multi-mode · Shodan passive · Decoy burst\n");
    printf("  ─────────────────────────────────────────────────────────────────\n");
    printf("\033[0m\n");
}

static void print_usage(const char *prog) {
    printf("\nUsage: %s <target-IP> [--mode]\n\n", prog);
    printf("Modes:\n");
    printf("  (none)   SYN scan  – fast half-open scan (default)\n");
    printf("  --syn    SYN scan  – same as default\n");
    printf("  --fin    FIN scan  – send FIN instead of SYN\n");
    printf("             Works on RFC-compliant stacks (Linux, BSD).\n");
    printf("             Closed ports send RST; open ports stay silent.\n");
    printf("  --null   NULL scan – no TCP flags at all\n");
    printf("             Same detection logic as FIN.\n");
    printf("  --xmas   XMAS scan – FIN+PSH+URG flags set\n");
    printf("             Christmas-tree packet; same idea as FIN/NULL.\n");
    printf("  --decoy  Decoy SYN – burst fake-IP traffic first,\n");
    printf("             then run a normal SYN scan. Buries your IP.\n");
    printf("  --frag   Frag scan – split SYN across two IP fragments.\n");
    printf("             Confuses older firewalls that inspect only\n");
    printf("             the first fragment.\n");
    printf("  --slow   Slow scan – SYN with random inter-packet delay.\n");
    printf("             Evades rate-based IDS thresholds.\n");
    printf("  --shodan Shodan scan - Passive scan without active interaction.\n");
    printf("             Evades all types of defensive mechanism.\n\n");
    printf("Examples:\n");
    printf("  %s 192.168.1.1\n", prog);
    printf("  %s 192.168.1.1 --xmas\n", prog);
    printf("  %s 192.168.1.1 --decoy\n", prog);
    printf("  %s 192.168.1.1 --xmas --decoy\n\n", prog);
}

static int parse_mode(const char *arg, scan_mode_t *out) {
    if (!arg || strcmp(arg, "--syn")   == 0) { *out = MODE_SYN;   return 0; }
    if (strcmp(arg, "--fin")   == 0)         { *out = MODE_FIN;   return 0; }
    if (strcmp(arg, "--null")  == 0)         { *out = MODE_NULL;  return 0; }
    if (strcmp(arg, "--xmas")  == 0)         { *out = MODE_XMAS;  return 0; }
    if (strcmp(arg, "--frag")  == 0)         { *out = MODE_FRAG;  return 0; }
    if (strcmp(arg, "--slow")  == 0)         { *out = MODE_SLOW;  return 0; }
    return -1;
}

// Parse port range
static int parse_port_range(const char *arg, int *start, int *end) {
    // Accepts "21" (single port) or "1-1000" (range)
    char *dash = strchr(arg, '-');
    if (dash) {
        *start = atoi(arg);
        *end = atoi(dash + 1);
    }
    else {
        *start = *end = atoi(arg);
    }
    // Validate
    if (*start < 1 || *end > MAX_PORT || *start > *end) {
        return -1;
    }
    return 0;
}

static const char *mode_name(scan_mode_t m) {
    switch (m) {
        case MODE_SYN:   return "SYN (half-open)";
        case MODE_FIN:   return "FIN";
        case MODE_NULL:  return "NULL (no flags)";
        case MODE_XMAS:  return "XMAS (FIN+PSH+URG)";
        case MODE_DECOY: return "Decoy SYN";
        case MODE_FRAG:  return "Fragmented SYN";
        case MODE_SLOW:  return "Slow SYN";
        default:         return "Unknown";
    }
}

static void retry_scan(scan_data_t *data) {
    int is_stealth = (data->mode == MODE_FIN  ||
                      data->mode == MODE_NULL ||
                      data->mode == MODE_XMAS);

    int *retry_ports = malloc((MAX_PORT + 1) * sizeof(int));
    if (!retry_ports) { perror("malloc retry_ports"); return; }

    int retry_count = 0;
    for (int p = 1; p <= MAX_PORT; p++) {
        /*
         * Only retry ports that are genuinely unresolved:
         * - We sent a probe            (syn_sent)
         * - No SYN+ACK received        (!open_ports)
         * - No RST received            (!closed_ports)  ← KEY FIX
         *
         * For stealth modes this means truly ambiguous ports.
         * For SYN mode closed_ports[] is also set on RST, so we
         * only retry ports that got no reply at all.
         */
        if (data->syn_sent[p]
         && !data->open_ports[p]
         && !data->closed_ports[p])
            retry_ports[retry_count++] = p;
    }

    if (retry_count == 0) {
        printf("[*] Retry pass: nothing to retry.\n");
        free(retry_ports);
        return;
    }
    printf("[*] Retry pass: re-scanning %d unresolved ports...\n", retry_count);

    threads_done = 0;
    all_sent     = 0;

    pthread_t rx;
    pthread_create(&rx, NULL, recv_thread, data);

    int n_threads = TX_THREADS;
    if (retry_count < n_threads) n_threads = retry_count;

    pthread_t  tx[TX_THREADS];
    tx_args_t  args[TX_THREADS];

    int base   = retry_count / n_threads;
    int extra  = retry_count % n_threads;
    int offset = 0;

    for (int i = 0; i < n_threads; i++) {
        int count = base + (i < extra ? 1 : 0);
        args[i].data       = data;
        args[i].thread_id  = i;
        args[i].port_list  = retry_ports + offset;
        args[i].port_count = count;
        args[i].total_threads = n_threads;
        offset += count;
        pthread_create(&tx[i], NULL, send_thread, &args[i]);
    }

    for (int i = 0; i < n_threads; i++) pthread_join(tx[i], NULL);
    pthread_join(rx, NULL);

    free(retry_ports);
}

static char **load_targets(const char *path, int *count) {
    FILE *fp = fopen(path, "r");
    if (!fp) {
        perror("[-] Cannot open target file");
        return NULL;
    }

    // First pass - count non-empty, non-comment lines
    char line[64];
    int n = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (line[0] != '#' && line[0] != '\n' && line[0] != '\r') {
            n++;
        }
    }
    rewind(fp);

    char **ips = malloc(n * sizeof(char *));
    if (!ips) {
        fclose(fp);
        return NULL;
    }

    // Second pass - store each IP string
    int i = 0;
    while (i < n && fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\r\n")] = '\0';
        if (line[0] == "#" || line[0] == "\0") {
            continue;
        }
        ips[i++] = strdup(line);
    }
    fclose(fp);
    *count = i;
    return ips;
}

static void run_scan(scan_data_t *data) {
    memset(data->open_ports, 0, sizeof(data->open_ports));
    memset(data->closed_ports, 0, sizeof(data->closed_ports));
    memset(data->syn_sent, 0, sizeof(data->syn_sent));
    threads_done = 0;
    all_sent = 0;

    if (data->use_decoy) {
        unsigned char src_mac[6], dst_mac[6];
        char src_ip[16];
        get_iface_info(src_mac, src_ip);
        get_target_mac(data->target_ip, dst_mac);
        send_decoy_burst(data, src_mac, dst_mac);
    }

    pthread_t rx;
    pthread_create(&rx, NULL, recv_thread, data);

    pthread_t tx[TX_THREADS];
    tx_args_t args[TX_THREADS];
    for (int i = 0; i < TX_THREADS; i++) {
        args[i].data = data;
        args[i].thread_id = i;
        args[i].port_list = NULL;
        args[i].port_count = 0;
        args[i].total_threads = TX_THREADS;
        pthread_create(&tx[i], NULL, send_thread, &args[i]);
    }

    for (int i = 0; i < TX_THREADS; i++) {
        pthread_join(tx[i], NULL);
    }
    pthread_join(rx, NULL);
}

#if MAX_RETRIES > 0
    {
        struct timespec delay = { 0, RETRY_DELAY_MS * 1000000L };
        nanosleep(&delay, NULL);
        retry_scan(data);
    }
#endif

int main(int argc, char *argv[]) {
    print_banner();
    int use_shodan = 0;

    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
        print_usage(argv[0]);
        return 0;
    }

    scan_mode_t mode = MODE_SYN;

    scan_data_t data;
    memset(&data, 0, sizeof(data));
    strncpy(data.target_ip, argv[1], 15);
    data.mode = mode;
    data.start_port = 1;
    data.end_port = MAX_PORT;
    data.use_decoy = 0;
    const char *target_file = NULL;
    int arg_start = 2;

    // FILE or IP
    if (strcmp(argv[1], "--file") == 0) {
        if (argc < 3) {
            fprintf(stderr, "[-] --file requires a path argument.\n");
            print_usage(argv[0]);
            return 1;
        }
        target_file = argv[2];
        arg_start = 3;
    }
    else {
        strncpy(data.target_ip, argv[1], 15);
        data.target_ip[15] = '\0';
    }

    // Parse argv - look for "--ports" anywhere in the arguments
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--ports") == 0 && i + 1 < argc) {
            if (parse_port_range(argv[i + 1], &data.start_port, &data.end_port) != 0) {
                fprintf(stderr, "[-] Invalid port range: %s\n", argv[i + 1]);
                return 1;
            }
            i++;
        }
        else if (strcmp(argv[i], "--decoy") == 0) {
            data.use_decoy = 1;
        }
        else if (parse_mode(argv[i], &mode) == 0) {
            data.mode = mode;
        }
        else if (strcmp(argv[i], "--shodan") == 0) {
            use_shodan = 1;
        }
        else {
            fprintf(stderr, "[-] Unknown argument: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    printf("\n[*] Target  : %s\n", data.target_ip);
    printf("[*] Mode    : %s\n",   mode_name(mode));
    printf("[*] Threads : %d TX + 1 RX\n", TX_THREADS);
    printf("[*] Ports   : %d – %d\n\n", data.start_port, data.end_port);

    if (target_file) {
        int count = 0;
        char **ips = load_targets(target_file, &count);
        if (!ips) {
            return 1;
        }

        printf("[*] Loaded %d target(s) from '%s'\n", count, target_file);

        for (int t = 0; t < count; t++) {
            printf("\n\033[1;36m");
            printf("  ┌─────────────────────────────────────────────┐\n");
            printf("  │  Target %d / %d  :  %-28s│\n",
                   t + 1, count, ips[t]);
            printf("  └─────────────────────────────────────────────┘\n");
            printf("\033[0m\n");

            strncpy(data.target_ip, ips[t], 15);
            data.target_ip[15] = '\0';

            if (use_shodan) {
                shodan_scan(data.target_ip, data.start_port, data.end_port);
            }
            else {
                run_scan(&data);
                printf("\n[*] DONE : %s\n", data.target_ip);
            }
            free(ips[t]);
        }
        free(ips);
    }
    else {
        printf("[*] Target: %s\n\n", data.target_ip);

        if (use_shodan) {
            shodan_scan(data.target_ip, data.start_port, data.end_port);
        }
        else {
            run_scan(&data);
            printf("\n[*] Done scanning %s\n", data.target_ip);
        }
    }

    printf("\n\033[1;32m[*] All scans complete.\033[0m\n\n");
    return 0;
}
