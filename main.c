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

// PRINT BANNER
static void print_banner(void) {
    static const char *taglines[] = {
        "Nmap slow? Ewww...",
        "Rustscan who?",
        "Half-open ports, fully open secrets.",
        "We don't knock. We peek.",
        "Sending RSTs since day one.",
        "Your firewall called. It's scared.",
        "Fragmented packets, unfragmented results.",
        "Slow scan? Only if you want it.",
        "Zero handshakes. All the info.",
        "We found your ports before you knew they were open.",
        "nmap still loading... ZeroMap already done",
    };
    int n = sizeof(taglines) / sizeof(taglines[0]);
    srand((unsigned)time(NULL));
    const char *tag = taglines[rand() % n];

    printf("\033[1;36m");
    printf("                                                        \n");
    printf("  ███████╗███████╗██████╗  ██████╗ ███╗   ███╗ █████╗ ██████╗ \n");
    printf("     ███╔╝██╔════╝██╔══██╗██╔═══██╗████╗ ████║██╔══██╗██╔══██╗\n");
    printf("    ███╔╝ █████╗  ██████╔╝██║   ██║██╔████╔██║███████║██████╔╝\n");
    printf("   ███╔╝  ██╔══╝  ██╔══██╗██║   ██║██║╚██╔╝██║██╔══██║██╔═══╝ \n");
    printf("  ███████╗███████╗██║  ██║╚██████╔╝██║ ╚═╝ ██║██║  ██║██║     \n");
    printf("  ╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝     \n");
    printf("~# By Z3R0"\n);
    printf("\033[0m");
    printf("\033[0;36m");
    printf("Z E R O M A P  —  G o d s p e e d  E d i t i o n\n");
    printf("\033[0m");
    printf("\033[1;33m");
    printf("[ %s ]\n", tag);
    printf("\033[0m");
    printf("\033[0;90m");
    printf("       Raw sockets · Multi-mode · Shodan passive · Decoy burst\n");
    printf("  ─────────────────────────────────────────────────────────────────\n");
    printf("\033[0m\n");
}

// PRINT USAGE
static void print_usage(const char *prog) {
    printf("\nUsage:\n");
    printf("  %s <target-IP> [--ports <range>] [--mode] [--decoy] [--shodan]\n", prog);
    printf("  %s --file <targets.txt> [--ports <range>] [--mode] [--decoy] [--shodan]\n\n", prog);

    printf("Target:\n");
    printf("  <IP>              Single target IP\n");
    printf("  --file <path>     File with one IP per line (# = comment)\n\n");

    printf("Port range:\n");
    printf("  --ports 1-1024    Scan ports 1 to 1024\n");
    printf("  --ports 80        Scan only port 80\n");
    printf("  (none)            Scan all ports 1-%d (default)\n\n", MAX_PORT);

    printf("Scan modes:\n");
    printf("  (none)   SYN scan  – fast half-open scan (default)\n");
    printf("  --syn    SYN scan  – same as default\n");
    printf("  --fin    FIN scan  – send FIN instead of SYN\n");
    printf("  --null   NULL scan – no TCP flags at all\n");
    printf("  --xmas   XMAS scan – FIN+PSH+URG flags set\n");
    printf("  --frag   Frag scan – split SYN across two IP fragments\n");
    printf("  --slow   Slow scan – SYN with random inter-packet delay\n");
    printf("  --tun    Tun scan  – Layer 3 scan via tun0 (VPN/HTB targets)\n\n");

    printf("Flags:\n");
    printf("  --source-port <n>  TCP source port for outgoing packets (default: random)\n");
    printf("  --decoy            Fire spoofed-IP burst before the real scan\n");
    printf("  --shodan           Passive Shodan lookup only (no packets sent)\n\n");

    printf("Examples:\n");
    printf("  %s 192.168.1.1\n", prog);
    printf("  %s 192.168.1.1 --ports 1-1024 --xmas\n", prog);
    printf("  %s 192.168.1.1 --slow --decoy\n", prog);
    printf("  %s 192.168.1.1 --source-port 12345\n", prog);
    printf("  %s 192.168.1.1 --ports 1-1024 --fin --source-port 9999\n", prog);
    printf("  %s 192.168.1.1 --shodan --ports 1-1024\n", prog);
    printf("  %s 10.10.10.5 --tun\n", prog);
    printf("  %s 10.10.10.5 --tun --fin --ports 1-1024\n", prog);
    printf("  %s --file targets.txt\n", prog);
    printf("  %s --file targets.txt --ports 1-1024 --syn --decoy\n\n", prog);

    printf("Target file format:\n");
    printf("  # This is a comment\n");
    printf("  192.168.1.1\n");
    printf("  10.0.0.5\n");
    printf("  172.16.0.99\n\n");
}

// PARSE MODE
static int parse_mode(const char *arg, scan_mode_t *out) {
    if (strcmp(arg, "--syn")  == 0) { *out = MODE_SYN;  return 0; }
    if (strcmp(arg, "--fin")  == 0) { *out = MODE_FIN;  return 0; }
    if (strcmp(arg, "--null") == 0) { *out = MODE_NULL; return 0; }
    if (strcmp(arg, "--xmas") == 0) { *out = MODE_XMAS; return 0; }
    if (strcmp(arg, "--frag") == 0) { *out = MODE_FRAG; return 0; }
    if (strcmp(arg, "--slow") == 0) { *out = MODE_SLOW; return 0; }
    return -1;
}

// MODE NAME
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

// PARSE PORT RANGE
static int parse_port_range(const char *arg, int *start, int *end) {
    char *dash = strchr(arg, '-');
    if (dash) { *start = atoi(arg); *end = atoi(dash + 1); }
    else      { *start = *end = atoi(arg); }
    if (*start < 1 || *end > MAX_PORT || *start > *end) return -1;
    return 0;
}

// LOAD TARGETS
static char **load_targets(const char *path, int *count) {
    FILE *fp = fopen(path, "r");
    if (!fp) { perror("[-] Cannot open target file"); return NULL; }

    char line[64];
    int  n = 0;
    while (fgets(line, sizeof(line), fp))
        if (line[0] != '#' && line[0] != '\n' && line[0] != '\r') n++;
    rewind(fp);

    if (n == 0) {
        fprintf(stderr, "[-] Target file '%s' has no valid entries\n", path);
        fclose(fp); *count = 0; return NULL;
    }

    char **ips = malloc(n * sizeof(char *));
    if (!ips) { perror("malloc ips"); fclose(fp); return NULL; }

    int i = 0;
    while (i < n && fgets(line, sizeof(line), fp)) {
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r') continue;
        line[strcspn(line, "\r\n")] = '\0';
        ips[i++] = strdup(line);
    }
    fclose(fp);
    *count = i;
    return ips;
}

// retry_scan_eth — Ethernet retry (multi-threaded, port list)
static void retry_scan_eth(scan_data_t *data) {
    int *retry_ports = malloc((MAX_PORT + 1) * sizeof(int));
    if (!retry_ports) { perror("malloc retry_ports"); return; }

    // Stealth scans: open|filtered is the correct final answer for ports that
    // sent no RST back. Retrying them would re-probe open ports that will
    // never reply with anything, causing rst_count to stay 0 forever,
    // grace_start to never be set, and the RX thread to hang indefinitely.
    if (data->mode == MODE_FIN  ||
        data->mode == MODE_NULL ||
        data->mode == MODE_XMAS) {
        free(retry_ports);
        return;
    }

    int retry_count = 0;
    for (int p = data->start_port; p <= data->end_port; p++) {
        if (data->syn_sent[p]
         && !data->open_ports[p]
         && !data->closed_ports[p])
            retry_ports[retry_count++] = p;
    }

    if (retry_count == 0) {
        free(retry_ports); return;
    }

    threads_done = 0;
    all_sent     = 0;

    pthread_t rx;
    pthread_create(&rx, NULL, recv_thread, data);

    int n_threads = TX_THREADS;
    if (retry_count < n_threads) n_threads = retry_count;

    pthread_t  tx[TX_THREADS];
    tx_args_t  args[TX_THREADS];
    int base = retry_count / n_threads, extra = retry_count % n_threads, offset = 0;

    for (int i = 0; i < n_threads; i++) {
        int cnt = base + (i < extra ? 1 : 0);
        args[i].data          = data;
        args[i].thread_id     = i;
        args[i].port_list     = retry_ports + offset;
        args[i].port_count    = cnt;
        args[i].total_threads = n_threads;
        offset += cnt;
        pthread_create(&tx[i], NULL, send_thread, &args[i]);
    }
    for (int i = 0; i < n_threads; i++) pthread_join(tx[i], NULL);
    pthread_join(rx, NULL);
    free(retry_ports);
}

// retry_scan_tun — tun retry (single-threaded, port list)
static void retry_scan_tun(scan_data_t *data) {
    int *retry_ports = malloc((MAX_PORT + 1) * sizeof(int));
    if (!retry_ports) { perror("malloc retry_ports_tun"); return; }

    // Same guard as retry_scan_eth: stealth open|filtered ports never reply,
    // so retrying them hangs the RX thread waiting for RSTs that won't come.
    if (data->mode == MODE_FIN  ||
        data->mode == MODE_NULL ||
        data->mode == MODE_XMAS) {
        free(retry_ports);
        return;
    }

    int retry_count = 0;
    for (int p = data->start_port; p <= data->end_port; p++) {
        if (data->syn_sent[p]
         && !data->open_ports[p]
         && !data->closed_ports[p])
            retry_ports[retry_count++] = p;
    }

    if (retry_count == 0) {
        free(retry_ports); return;
    }

    threads_done = 0;
    all_sent     = 0;

    tx_args_t retry_args = {
        .data          = data,
        .thread_id     = 0,
        .port_list     = retry_ports,
        .port_count    = retry_count,
        .total_threads = 1,
    };

    pthread_t rx, tx;

    pthread_create(&rx, NULL, recv_thread,           data);
    pthread_create(&tx, NULL, send_thread_tun_retry, &retry_args);

    pthread_join(tx, NULL);
    pthread_join(rx, NULL);

    free(retry_ports);
}

// run_scan - tun path, eth path
static void run_scan(scan_data_t *data) {
    memset(data->open_ports,   0, sizeof(data->open_ports));
    memset(data->closed_ports, 0, sizeof(data->closed_ports));
    memset(data->syn_sent,     0, sizeof(data->syn_sent));
    threads_done = 0;
    all_sent     = 0;

    /* TUN path */
    if (data->use_tun) {
        pthread_t rx, tx;
        pthread_create(&rx, NULL, recv_thread,     data);
        pthread_create(&tx, NULL, send_thread_tun, data);
        pthread_join(tx, NULL);
        pthread_join(rx, NULL);

        struct timespec delay = { 0, RETRY_DELAY_MS * 1000000L };
        nanosleep(&delay, NULL);
        retry_scan_tun(data);
        return;
    }

    /* Ethernet path */
    pthread_t rx;
    pthread_create(&rx, NULL, recv_thread, data);

    pthread_t  tx[TX_THREADS];
    tx_args_t  args[TX_THREADS];
    for (int i = 0; i < TX_THREADS; i++) {
        args[i].data          = data;
        args[i].thread_id     = i;
        args[i].port_list     = NULL;
        args[i].port_count    = 0;
        args[i].total_threads = TX_THREADS;
        pthread_create(&tx[i], NULL, send_thread, &args[i]);
    }
    for (int i = 0; i < TX_THREADS; i++) pthread_join(tx[i], NULL);
    pthread_join(rx, NULL);

#if MAX_RETRIES > 0
    {
        struct timespec delay = { 0, RETRY_DELAY_MS * 1000000L };
        nanosleep(&delay, NULL);
        retry_scan_eth(data);
    }
#endif
}

// MAIN
int main(int argc, char *argv[]) {
    print_banner();

    if (argc < 2) { print_usage(argv[0]); return 1; }
    if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
        print_usage(argv[0]); return 0;
    }

    scan_data_t data;
    memset(&data, 0, sizeof(data));
    data.mode       = MODE_SYN;
    data.start_port = 1;
    data.end_port   = MAX_PORT;
    data.use_decoy  = 0;
    data.use_tun    = 0;
    data.src_port   = SRC_PORT;

    const char *target_file = NULL;
    int         use_shodan  = 0;
    int         arg_start   = 2;

    if (strcmp(argv[1], "--file") == 0) {
        if (argc < 3) {
            fprintf(stderr, "[-] --file requires a path argument\n");
            print_usage(argv[0]); return 1;
        }
        target_file = argv[2];
        arg_start   = 3;
    } else {
        strncpy(data.target_ip, argv[1], 15);
        data.target_ip[15] = '\0';
    }

    for (int i = arg_start; i < argc; i++) {
        if (strcmp(argv[i], "--ports") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "[-] --ports requires an argument\n"); return 1;
            }
            if (parse_port_range(argv[++i], &data.start_port, &data.end_port) != 0) {
                fprintf(stderr, "[-] Invalid port range: %s\n", argv[i]); return 1;
            }
            continue;
        }

        if (strcmp(argv[i], "--source-port") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "[-] --source-port requires an argument\n"); return 1;
            }
            int sp = atoi(argv[++i]);
            if (sp < 1 || sp > 65535) {
                fprintf(stderr, "[-] --source-port must be between 1 and 65535\n"); return 1;
            }
            data.src_port = (uint16_t)sp;
            continue;
        }

        if (strcmp(argv[i], "--tun")    == 0) { data.use_tun   = 1; continue; }
        if (strcmp(argv[i], "--decoy")  == 0) { data.use_decoy = 1; continue; }
        if (strcmp(argv[i], "--shodan") == 0) { use_shodan     = 1; continue; }

        scan_mode_t m;
        if (parse_mode(argv[i], &m) == 0) { data.mode = m; continue; }

        fprintf(stderr, "[-] Unknown argument: %s\n", argv[i]);
        print_usage(argv[0]); return 1;
    }

    printf("[*] Mode    : %s%s%s\n",
           mode_name(data.mode),
           data.use_decoy ? " + Decoy burst" : "",
           data.use_tun   ? " + tun0 (L3)"   : "");
    printf("[*] Threads : %s\n",
           data.use_tun ? "1 TX + 1 RX (tun), retry enabled"
                        : "4 TX + 1 RX (eth), retry enabled");
    printf("[*] Ports   : %d – %d\n", data.start_port, data.end_port);
    printf("[*] Src port: %d\n", data.src_port);
    if (use_shodan)
        printf("[*] Method  : Shodan passive (no packets sent to target)\n");
    printf("\n");

    if (target_file) {
        int    count = 0;
        char **ips   = load_targets(target_file, &count);
        if (!ips) return 1;

        printf("[*] Loaded %d target(s) from '%s'\n", count, target_file);

        for (int t = 0; t < count; t++) {
            printf("\n\033[1;36m");
            printf("  ┌─────────────────────────────────────────────┐\n");
            printf("  │  Target %d / %d  :  %-28s│\n", t + 1, count, ips[t]);
            printf("  └─────────────────────────────────────────────┘\n");
            printf("\033[0m\n");

            strncpy(data.target_ip, ips[t], 15);
            data.target_ip[15] = '\0';

            if (use_shodan)
                shodan_scan(data.target_ip, data.start_port, data.end_port);
            else {
                run_scan(&data);
                printf("\n[*] Done : %s\n", data.target_ip);
            }
            free(ips[t]);
        }
        free(ips);
    } else {
        printf("[*] Target  : %s\n\n", data.target_ip);
        if (use_shodan)
            shodan_scan(data.target_ip, data.start_port, data.end_port);
        else {
            run_scan(&data);
            printf("\n[*] Done scanning %s\n", data.target_ip);
        }
    }

    printf("\n\033[1;32m[*] All scans complete.\033[0m\n\n");
    return 0;
}
