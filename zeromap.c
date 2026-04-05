#define _GNU_SOURCE
#include "scanner.h"
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <net/if.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <signal.h>
#include <curl/curl.h>
#include <cjson/cJSON.h>

// GLOBAL STATE
volatile int threads_done = 0;
volatile int all_sent     = 0;
static volatile unsigned long packets_sent = 0;

// CHECKSUM HELPERS
unsigned short checksum(unsigned short *ptr, int nbytes) {
    long sum = 0;
    while (nbytes > 1) { sum += *ptr++; nbytes -= 2; }
    if (nbytes) sum += *(unsigned char *)ptr;
    sum  = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

struct pseudo_hdr {
    uint32_t src, dst;
    uint8_t  zero, proto;
    uint16_t tcp_len;
};

static unsigned short tcp_checksum(struct iphdr *iph, struct tcphdr *tcph) {
    struct pseudo_hdr ph;
    ph.src     = iph->saddr;
    ph.dst     = iph->daddr;
    ph.zero    = 0;
    ph.proto   = IPPROTO_TCP;
    ph.tcp_len = htons(sizeof(struct tcphdr));

    char buf[sizeof(ph) + sizeof(struct tcphdr)];
    memcpy(buf,              &ph,  sizeof(ph));
    memcpy(buf + sizeof(ph), tcph, sizeof(struct tcphdr));
    return checksum((unsigned short *)buf, sizeof(buf));
}

// INTERFACE HELPERS - Get iface where target belongs
void get_iface_info(unsigned char *mac, char *ip) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, IFACE, IFNAMSIZ - 1);

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) { perror("MAC ioctl"); exit(1); }
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);

    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) { perror("IP ioctl"); exit(1); }
    strcpy(ip, inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
    close(fd);
}

// GET TARGET'S MAC - extract mac of target from ARP tables
void get_target_mac(const char *ip, unsigned char *mac) {
    for (int attempt = 0; attempt < 3; attempt++) {
        if (attempt == 0) {
            char ping_cmd[64];
            snprintf(ping_cmd, sizeof(ping_cmd),
                     "ping -c 1 -W 1 %s > /dev/null 2>&1", ip);
            system(ping_cmd);
        }

        char cmd[128];
        snprintf(cmd, sizeof(cmd),
                 "arp -n %s | awk 'NR>1{print $3}' | head -n1", ip);
        FILE *fp = popen(cmd, "r");
        if (!fp) { perror("popen arp"); exit(1); }

        char mac_str[32] = {0};
        fgets(mac_str, sizeof(mac_str), fp);
        pclose(fp);
        mac_str[strcspn(mac_str, "\n")] = 0;

        if (sscanf(mac_str,
                   "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                   &mac[0], &mac[1], &mac[2],
                   &mac[3], &mac[4], &mac[5]) == 6) return;

        fprintf(stderr, "[!] ARP attempt %d failed for %s, retrying...\n",
                attempt + 1, ip);
        sleep(1);
    }
    fprintf(stderr, "[-] Could not resolve MAC for %s\n", ip);
    exit(1);
}

// IDENTIFY SERVICE - compare port with /etc/services
static const char *identify_service(int port, const char *proto) {
    struct servent *sv = getservbyport(htons(port), proto);
    return sv ? sv->s_name : "unknown";
}

// PACKET BUILDER - build raw packets to avoid kernel overhead (ethernet only)
void build_packet(char *buffer,
                  const char *src_ip, const char *dst_ip,
                  unsigned char *src_mac, unsigned char *dst_mac,
                  int port, scan_mode_t mode) {

    memset(buffer, 0, 1500);

    struct ether_header *eth  = (struct ether_header *)buffer;
    struct iphdr        *iph  = (struct iphdr *)(buffer + sizeof(*eth));
    struct tcphdr       *tcph = (struct tcphdr *)((char *)iph + sizeof(*iph));

    memcpy(eth->ether_shost, src_mac, 6);
    memcpy(eth->ether_dhost, dst_mac, 6);
    eth->ether_type = htons(ETH_P_IP);

    iph->ihl      = 5;
    iph->version  = 4;
    iph->tot_len  = htons(sizeof(*iph) + sizeof(*tcph));
    iph->ttl      = 64;
    iph->protocol = IPPROTO_TCP;
    iph->saddr    = inet_addr(src_ip);
    iph->daddr    = inet_addr(dst_ip);
    iph->check    = checksum((unsigned short *)iph, sizeof(*iph));

    tcph->source = htons(SRC_PORT);
    tcph->dest   = htons(port);
    tcph->seq    = htonl(rand());
    tcph->doff   = 5;
    tcph->window = htons(1024);

    switch (mode) {
        case MODE_FIN:  tcph->fin = 1; break;
        case MODE_NULL: break;
        case MODE_XMAS: tcph->fin = 1; tcph->psh = 1; tcph->urg = 1; break;
        default:        tcph->syn = 1; break;
    }

    tcph->check = tcp_checksum(iph, tcph);
}

// DECOY BURST - Uses 5 different IPs to burst packets from
void send_decoy_burst(scan_data_t *data,
                      unsigned char *src_mac,
                      unsigned char *dst_mac) {

    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) { perror("decoy socket"); return; }

    struct sockaddr_ll addr = {0};
    addr.sll_family  = AF_PACKET;
    addr.sll_ifindex = if_nametoindex(IFACE);
    addr.sll_halen   = ETH_ALEN;
    memcpy(addr.sll_addr, dst_mac, 6);

    char pkt[1500];
    printf("[DECOY] Sending decoy bursts from %d fake IPs...\n", MAX_DECOYS);

    for (int d = 0; d < MAX_DECOYS; d++) {
        for (int i = 0; i < 100; i++) {
            int fake_port = (rand() % 64512) + 1024;
            build_packet(pkt, DECOY_IPS[d], data->target_ip,
                         src_mac, dst_mac, fake_port, MODE_SYN);
            size_t pkt_len = sizeof(struct ether_header)
                           + sizeof(struct iphdr)
                           + sizeof(struct tcphdr);
            sendto(sock, pkt, pkt_len, 0,
                   (struct sockaddr *)&addr, sizeof(addr));
        }
        printf("[DECOY]  Burst from %s done\n", DECOY_IPS[d]);
    }

    close(sock);
    printf("[DECOY] Decoy burst complete. Starting real scan...\n");
}

// FRAGMENT SENDER - send fragments when '--frag' option is used 
static void send_fragment(int sock, struct sockaddr_ll *addr,
                           const char *src_ip, const char *dst_ip,
                           unsigned char *src_mac, unsigned char *dst_mac,
                           int port, uint16_t ip_id) {

    char frag1[sizeof(struct ether_header) + sizeof(struct iphdr) + 8];
    memset(frag1, 0, sizeof(frag1));
    struct ether_header *eth1 = (struct ether_header *)frag1;
    struct iphdr        *ip1  = (struct iphdr *)(frag1 + sizeof(*eth1));
    char                *tcp1 = (char *)ip1 + sizeof(*ip1);

    memcpy(eth1->ether_shost, src_mac, 6);
    memcpy(eth1->ether_dhost, dst_mac, 6);
    eth1->ether_type = htons(ETH_P_IP);
    ip1->ihl      = 5; ip1->version = 4;
    ip1->tot_len  = htons(sizeof(*ip1) + 8);
    ip1->id       = htons(ip_id);
    ip1->frag_off = htons(IP_MF);
    ip1->ttl      = 64; ip1->protocol = IPPROTO_TCP;
    ip1->saddr    = inet_addr(src_ip);
    ip1->daddr    = inet_addr(dst_ip);
    ip1->check    = checksum((unsigned short *)ip1, sizeof(*ip1));
    ip1->frag_off = htons(IP_MF);

    char full_tcp[20];
    struct tcphdr *tcp = (struct tcphdr *)full_tcp;
    memset(full_tcp, 0, 20);
    tcp->source = htons(SRC_PORT); tcp->dest = htons(port);
    tcp->seq    = htonl(rand());   tcp->doff = 5;
    tcp->syn    = 1;               tcp->window = htons(1024);
    tcp->check  = tcp_checksum(ip1, tcp);
    memcpy(tcp1, full_tcp, 8);
    sendto(sock, frag1, sizeof(frag1), 0, (struct sockaddr *)addr, sizeof(*addr));

    char frag2[sizeof(struct ether_header) + sizeof(struct iphdr) + 12];
    memset(frag2, 0, sizeof(frag2));
    struct ether_header *eth2 = (struct ether_header *)frag2;
    struct iphdr        *ip2  = (struct iphdr *)(frag2 + sizeof(*eth2));
    memcpy(eth2->ether_shost, src_mac, 6);
    memcpy(eth2->ether_dhost, dst_mac, 6);
    eth2->ether_type = htons(ETH_P_IP);
    ip2->ihl      = 5; ip2->version = 4;
    ip2->tot_len  = htons(sizeof(*ip2) + 12);
    ip2->id       = htons(ip_id); ip2->frag_off = htons(1);
    ip2->ttl      = 64; ip2->protocol = IPPROTO_TCP;
    ip2->saddr    = inet_addr(src_ip); ip2->daddr = inet_addr(dst_ip);
    ip2->check    = checksum((unsigned short *)ip2, sizeof(*ip2));
    memcpy((char *)ip2 + sizeof(*ip2), full_tcp + 8, 12);
    sendto(sock, frag2, sizeof(frag2), 0, (struct sockaddr *)addr, sizeof(*addr));
}

// SHODAN - Ultimate detection evasion technique (only for public facing systems)
typedef struct { char *data; size_t len; } curl_buf_t;

static size_t curl_write_cb(void *ptr, size_t size, size_t nmemb, void *ud) {
    curl_buf_t *buf = (curl_buf_t *)ud;
    size_t total = size * nmemb;
    char *tmp = realloc(buf->data, buf->len + total + 1);
    if (!tmp) return 0;
    buf->data = tmp;
    memcpy(buf->data + buf->len, ptr, total);
    buf->len += total;
    buf->data[buf->len] = '\0';
    return total;
}

void shodan_scan(const char *ip, int start_port, int end_port) {
    printf("\n[SHODAN] Passive lookup for %s (ports %d-%d)...\n",
           ip, start_port, end_port);

    char url[256];
    snprintf(url, sizeof(url),
             "https://api.shodan.io/shodan/host/%s?key=%s", ip, SHODAN_API_KEY);

    CURL *curl = curl_easy_init();
    if (!curl) { fprintf(stderr, "[-] curl init failed\n"); return; }

    curl_buf_t buf = { .data = malloc(1), .len = 0 };
    buf.data[0] = '\0';
    curl_easy_setopt(curl, CURLOPT_URL,           url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA,     &buf);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT,       10L);

    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        fprintf(stderr, "[-] Shodan request failed: %s\n",
                curl_easy_strerror(res));
        free(buf.data); return;
    }

    cJSON *root = cJSON_Parse(buf.data);
    free(buf.data);
    if (!root) { fprintf(stderr, "[-] Failed to parse Shodan JSON\n"); return; }

    cJSON *err = cJSON_GetObjectItem(root, "error");
    if (err && cJSON_IsString(err)) {
        fprintf(stderr, "[SHODAN] API error: %s\n", err->valuestring);
        cJSON_Delete(root); return;
    }

    cJSON *org     = cJSON_GetObjectItem(root, "org");
    cJSON *os      = cJSON_GetObjectItem(root, "os");
    cJSON *country = cJSON_GetObjectItem(root, "country_name");
    printf("[SHODAN] Organization : %s\n",
           (org && cJSON_IsString(org))         ? org->valuestring     : "N/A");
    printf("[SHODAN] OS           : %s\n",
           (os  && cJSON_IsString(os))          ? os->valuestring      : "N/A");
    printf("[SHODAN] Country      : %s\n",
           (country && cJSON_IsString(country)) ? country->valuestring : "N/A");

    cJSON *ports_arr = cJSON_GetObjectItem(root, "ports");
    if (ports_arr && cJSON_IsArray(ports_arr)) {
        printf("[SHODAN] All known open ports:");
        cJSON *p;
        cJSON_ArrayForEach(p, ports_arr)
            if (p->valueint >= start_port && p->valueint <= end_port)
                printf(" %d", p->valueint);
        printf("\n");
    }

    cJSON *data_arr = cJSON_GetObjectItem(root, "data");
    if (!data_arr || !cJSON_IsArray(data_arr)) {
        printf("[SHODAN] No per-service data available.\n");
        cJSON_Delete(root); return;
    }

    printf("\n[SHODAN] Service details:\n");
    printf("%-7s %-12s %-10s %s\n", "Port","Transport","Product","Banner (first 80 chars)");
    printf("%-7s %-12s %-10s %s\n", "------","----------","---------","------");

    cJSON *svc;
    cJSON_ArrayForEach(svc, data_arr) {
        cJSON *port_j    = cJSON_GetObjectItem(svc, "port");
        cJSON *transport = cJSON_GetObjectItem(svc, "transport");
        cJSON *product   = cJSON_GetObjectItem(svc, "product");
        cJSON *banner    = cJSON_GetObjectItem(svc, "data");
        if (!port_j) continue;
        int port_num = port_j->valueint;
        if (port_num < start_port || port_num > end_port) continue;
        char banner_short[81] = "N/A";
        if (banner && cJSON_IsString(banner) && banner->valuestring[0]) {
            strncpy(banner_short, banner->valuestring, 80);
            banner_short[80] = '\0';
            for (int i = 0; banner_short[i]; i++)
                if (banner_short[i] == '\n' || banner_short[i] == '\r')
                    banner_short[i] = ' ';
        }
        printf("%-7d %-12s %-10s %.80s\n", port_num,
               (transport && cJSON_IsString(transport)) ? transport->valuestring : "tcp",
               (product   && cJSON_IsString(product))   ? product->valuestring   : "N/A",
               banner_short);
    }

    cJSON_Delete(root);
    printf("\n[SHODAN] Passive scan complete. No packets sent to target.\n\n");
}

// TUN core send helper
#define TUN_BATCH_PAUSE_US      500    /* µs between SYN batches            */
#define TUN_STEALTH_BATCH_PAUSE 8000   /* µs between FIN/NULL/XMAS batches  */

static void tun_send_ports(scan_data_t *data,
                            int *port_list, int port_count) {

    srand((unsigned)time(NULL) ^ (unsigned)getpid());

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) { perror("SOCK_RAW TX (tun)"); return; }

    int one = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    int sndbuf = 4 * 1024 * 1024;
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));

    /* Get source IP from tun0 */
    char src_ip[16] = {0};
    {
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, TUN_IFACE, IFNAMSIZ - 1);
        if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
            perror("Failed to get tun0 IP");
            close(fd); close(sock); return;
        }
        strcpy(src_ip,
               inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
        close(fd);
    }

    struct sockaddr_in dst = {0};
    dst.sin_family      = AF_INET;
    dst.sin_addr.s_addr = inet_addr(data->target_ip);

    int is_stealth = (data->mode == MODE_FIN  ||
                      data->mode == MODE_NULL ||
                      data->mode == MODE_XMAS);
    long pause_us = is_stealth ? TUN_STEALTH_BATCH_PAUSE : TUN_BATCH_PAUSE_US;

    char pkt[sizeof(struct iphdr) + sizeof(struct tcphdr)];

    /* Determine iteration bounds */
    int total     = port_list ? port_count
                              : (data->end_port - data->start_port + 1);
    int port_base = port_list ? 0 : data->start_port;

    for (int idx = 0; idx < total; idx++) {
        int port = port_list ? port_list[idx] : (port_base + idx);

        memset(pkt, 0, sizeof(pkt));
        struct iphdr  *iph  = (struct iphdr *)pkt;
        struct tcphdr *tcph = (struct tcphdr *)(pkt + sizeof(*iph));

        iph->ihl      = 5;
        iph->version  = 4;
        iph->tot_len  = htons(sizeof(*iph) + sizeof(*tcph));
        iph->ttl      = 64;
        iph->protocol = IPPROTO_TCP;
        iph->saddr    = inet_addr(src_ip);
        iph->daddr    = inet_addr(data->target_ip);
        iph->check    = checksum((unsigned short *)iph, sizeof(*iph));

        tcph->source = htons(SRC_PORT);
        tcph->dest   = htons(port);
        tcph->seq    = htonl(rand());
        tcph->doff   = 5;
        tcph->window = htons(1024);

        switch (data->mode) {
            case MODE_FIN:  tcph->fin = 1; break;
            case MODE_NULL: break;
            case MODE_XMAS: tcph->fin = 1; tcph->psh = 1; tcph->urg = 1; break;
            default:        tcph->syn = 1; break;
        }

        tcph->check = tcp_checksum(iph, tcph);

        sendto(sock, pkt, sizeof(pkt), 0,
               (struct sockaddr *)&dst, sizeof(dst));

        data->syn_sent[port] = 1;
        __sync_fetch_and_add(&packets_sent, 1);

        if ((idx % BATCH_SIZE) == 0 && idx > 0) {
            struct timespec ts = { .tv_sec  = 0,
                                   .tv_nsec = pause_us * 1000L };
            nanosleep(&ts, NULL);
        }
    }

    close(sock);
}

// send_thread_tun  — full range scan, spawned by run_scan() for initial pass
void *send_thread_tun(void *arg) {
    scan_data_t *data = (scan_data_t *)arg;

    tun_send_ports(data, NULL, 0);   /* NULL = sequential full range */

    printf("[*] All TX done (tun). Total sent: %lu\n", packets_sent);
    threads_done = TX_THREADS;       /* satisfy the global counter check */
    all_sent     = 1;
    return NULL;
}

// send_thread_tun_retry  — retry pass, takes a tx_args_t with a port list
void *send_thread_tun_retry(void *arg) {
    tx_args_t   *args = (tx_args_t *)arg;
    scan_data_t *data = args->data;

    tun_send_ports(data, args->port_list, args->port_count);

    printf("[*] Retry TX done (tun). Total sent: %lu\n", packets_sent);
    threads_done = TX_THREADS;
    all_sent     = 1;
    return NULL;
}

// Ethernet TX (multi-threaded, unchanged)
static void do_send(scan_data_t *data, int thread_id,
                    int *port_list, int port_count) {

    srand((unsigned)time(NULL) ^ (unsigned)getpid() ^ (unsigned)(thread_id * 1337));

    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) { perror("AF_PACKET TX"); return; }

    struct sockaddr_ll addr = {0};
    addr.sll_family  = AF_PACKET;
    addr.sll_ifindex = if_nametoindex(IFACE);
    addr.sll_halen   = ETH_ALEN;

    unsigned char src_mac[6], dst_mac[6];
    char src_ip[16];
    get_iface_info(src_mac, src_ip);
    get_target_mac(data->target_ip, dst_mac);
    memcpy(addr.sll_addr, dst_mac, 6);

    int start_port = 0, end_port = 0;
    if (!port_list) {
        int range            = data->end_port - data->start_port + 1;
        int ports_per_thread = range / TX_THREADS;
        start_port = data->start_port + thread_id * ports_per_thread;
        end_port   = (thread_id == TX_THREADS - 1)
                     ? data->end_port
                     : start_port + ports_per_thread - 1;
    }

    int total = port_list ? port_count : (end_port - start_port + 1);

    if (data->mode == MODE_FRAG) {
        uint16_t ip_id = (uint16_t)(rand() & 0xFFFF);
        for (int idx = 0; idx < total; idx++) {
            int port = port_list ? port_list[idx] : (start_port + idx);
            send_fragment(sock, &addr, src_ip, data->target_ip,
                          src_mac, dst_mac, port, ip_id++);
            data->syn_sent[port] = 1;
            __sync_fetch_and_add(&packets_sent, 2);
        }
        close(sock); return;
    }

    if (data->mode == MODE_SLOW) {
        char pkt[1500];
        size_t pkt_len = sizeof(struct ether_header)
                       + sizeof(struct iphdr)
                       + sizeof(struct tcphdr);
        for (int idx = 0; idx < total; idx++) {
            int port = port_list ? port_list[idx] : (start_port + idx);
            build_packet(pkt, src_ip, data->target_ip,
                         src_mac, dst_mac, port, data->mode);
            sendto(sock, pkt, pkt_len, 0,
                   (struct sockaddr *)&addr, sizeof(addr));
            data->syn_sent[port] = 1;
            __sync_fetch_and_add(&packets_sent, 1);
            long delay_us = SLOW_MIN_DELAY_US
                          + rand() % (SLOW_MAX_DELAY_US - SLOW_MIN_DELAY_US);
            struct timespec ts = { 0, delay_us * 1000L };
            nanosleep(&ts, NULL);
        }
        close(sock); return;
    }

    struct mmsghdr msgs[BATCH_SIZE];
    struct iovec   iov[BATCH_SIZE];
    char           packets[BATCH_SIZE][1500];
    int sent = 0;
    unsigned long local_sent = 0;

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    for (int idx = 0; idx < total; idx++) {
        int port = port_list ? port_list[idx] : (start_port + idx);

        build_packet(packets[sent], src_ip, data->target_ip,
                     src_mac, dst_mac, port, data->mode);

        iov[sent].iov_base = packets[sent];
        iov[sent].iov_len  = sizeof(struct ether_header)
                           + sizeof(struct iphdr)
                           + sizeof(struct tcphdr);

        memset(&msgs[sent].msg_hdr, 0, sizeof(msgs[sent].msg_hdr));
        msgs[sent].msg_hdr.msg_iov     = &iov[sent];
        msgs[sent].msg_hdr.msg_iovlen  = 1;
        msgs[sent].msg_hdr.msg_name    = &addr;
        msgs[sent].msg_hdr.msg_namelen = sizeof(addr);
        sent++;

        data->syn_sent[port] = 1;

        if (sent == BATCH_SIZE || idx == total - 1) {
            sendmmsg(sock, msgs, sent, 0);
            if (data->mode == MODE_FIN  ||
                data->mode == MODE_NULL ||
                data->mode == MODE_XMAS)
                usleep(5000);
            local_sent += sent;
            __sync_fetch_and_add(&packets_sent, sent);
            sent = 0;
        }
    }

    clock_gettime(CLOCK_MONOTONIC, &t1);
    double elapsed = (t1.tv_sec - t0.tv_sec)
                   + (t1.tv_nsec - t0.tv_nsec) / 1e9;
    if (!port_list)
        printf("[TX %d] sent %lu packets in %.2fs\n",
               thread_id, local_sent, elapsed);

    close(sock);
}

void *send_thread(void *arg) {
    tx_args_t   *args          = (tx_args_t *)arg;
    scan_data_t *data          = args->data;
    int          thread_id     = args->thread_id;
    int          total_threads = args->total_threads;

    do_send(data, thread_id, args->port_list, args->port_count);

    if (__sync_add_and_fetch(&threads_done, 1) == total_threads) {
        printf("[*] All TX threads done. Total sent: %lu\n", packets_sent);
        all_sent = 1;
    }
    return NULL;
}

// TUN RX thread
#define TUN_RX_GRACE  (RX_GRACE + 3)

static void *recv_thread_tun(void *arg) {
    scan_data_t *data = (scan_data_t *)arg;

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) { perror("RX AF_INET/IPPROTO_TCP"); return NULL; }

    int rcvbuf = 32 * 1024 * 1024;
    setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

    struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    int is_stealth = (data->mode == MODE_FIN  ||
                      data->mode == MODE_NULL ||
                      data->mode == MODE_XMAS);

    unsigned long rst_count  = 0;
    time_t        grace_start = 0;

    while (1) {
        char buf[65536];
        struct sockaddr_in sender;
        socklen_t slen = sizeof(sender);

        int len = recvfrom(sock, buf, sizeof(buf), 0,
                           (struct sockaddr *)&sender, &slen);
        if (len < 0) goto check_grace_tun;

        if (len < (int)(sizeof(struct iphdr) + sizeof(struct tcphdr)))
            goto check_grace_tun;

        struct iphdr  *iph  = (struct iphdr *)buf;
        if (iph->protocol != IPPROTO_TCP) goto check_grace_tun;

        struct tcphdr *tcph = (struct tcphdr *)(buf + iph->ihl * 4);
        if ((char *)tcph + sizeof(*tcph) > buf + len) goto check_grace_tun;

        if (iph->saddr != inet_addr(data->target_ip)) goto check_grace_tun;
        if (ntohs(tcph->dest) != SRC_PORT)             goto check_grace_tun;

        int port = ntohs(tcph->source);
        if (port < 1 || port > MAX_PORT)  goto check_grace_tun;
        if (!data->syn_sent[port])         goto check_grace_tun;

        if (tcph->syn && tcph->ack) {
            if (!data->open_ports[port]) {
                data->open_ports[port] = 1;
                printf("[OPEN] %d - %s\n",
                       port, identify_service(port, "tcp"));
                fflush(stdout);
            }
            if (all_sent && grace_start != 0)
                grace_start = time(NULL);
        }

        if (tcph->rst) {
            if (!data->closed_ports[port]) {
                data->closed_ports[port] = 1;
                if (is_stealth) rst_count++;
            }
            if (all_sent && grace_start != 0)
                grace_start = time(NULL);
        }

check_grace_tun:
        if (all_sent) {
            if (grace_start == 0) grace_start = time(NULL);
            else if (time(NULL) - grace_start > TUN_RX_GRACE) break;
        }
    }

    if (is_stealth) {
        printf("\n[*] RSTs received: %lu (closed ports)\n", rst_count);
        if (rst_count == 0) {
            printf("[!] Zero RST replies — target may be Windows, or a "
                   "firewall is dropping replies.\n");
            printf("[!] Try raising TUN_STEALTH_BATCH_PAUSE in scanner.c\n");
            printf("[!] tcpdump -i %s 'tcp[tcpflags] & tcp-rst != 0 "
                   "and dst port %d'\n", TUN_IFACE, SRC_PORT);
        } else {
            int found = 0;
            for (int p = data->start_port; p <= data->end_port; p++) {
                if (data->syn_sent[p]
                 && !data->closed_ports[p]
                 && !data->open_ports[p]) {
                    printf("[OPEN|FILTERED] %d - %s\n",
                           p, identify_service(p, "tcp"));
                    fflush(stdout);
                    found++;
                }
            }
            if (!found) printf("[*] No open|filtered ports found.\n");
        }
    }

    close(sock);
    return NULL;
}

// Ethernet RX thread 
void *recv_thread(void *arg) {
    scan_data_t *data = (scan_data_t *)arg;
    if (data->use_tun) return recv_thread_tun(arg);

    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    if (sock < 0) { perror("RX AF_PACKET"); return NULL; }

    int rcvbuf = 32 * 1024 * 1024;
    setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
    int busy_poll = 50;
    setsockopt(sock, SOL_SOCKET, SO_BUSY_POLL, &busy_poll, sizeof(busy_poll));
    struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    int is_stealth = (data->mode == MODE_FIN  ||
                      data->mode == MODE_NULL ||
                      data->mode == MODE_XMAS);
    unsigned long rst_count = 0;
    struct sockaddr_ll saddr;
    socklen_t saddr_len = sizeof(saddr);
    time_t grace_start  = 0;

    while (1) {
        char buf[65536];
        int len = recvfrom(sock, buf, sizeof(buf), 0,
                           (struct sockaddr *)&saddr, &saddr_len);

        if (len < (int)(sizeof(struct ether_header)
                        + sizeof(struct iphdr)
                        + sizeof(struct tcphdr)))
            goto check_grace;

        struct ether_header *eth = (struct ether_header *)buf;
        if (ntohs(eth->ether_type) != ETH_P_IP) goto check_grace;
        struct iphdr *iph = (struct iphdr *)(buf + sizeof(*eth));
        if (iph->protocol != IPPROTO_TCP)        goto check_grace;
        struct tcphdr *tcph = (struct tcphdr *)((char *)iph + iph->ihl * 4);
        if ((char *)tcph + sizeof(*tcph) > buf + len) goto check_grace;

        if (iph->saddr != inet_addr(data->target_ip)) goto check_grace;
        if (ntohs(tcph->dest) != SRC_PORT)            goto check_grace;

        int port = ntohs(tcph->source);
        if (port < 1 || port > MAX_PORT)   goto check_grace;
        if (!data->syn_sent[port])          goto check_grace;

        if (tcph->syn && tcph->ack) {
            if (!data->open_ports[port]) {
                data->open_ports[port] = 1;
                printf("[OPEN] %d - %s\n", port, identify_service(port, "tcp"));
                fflush(stdout);
            }
            if (all_sent && grace_start != 0) grace_start = time(NULL);
        }
        if (tcph->rst) {
            if (!data->closed_ports[port]) {
                data->closed_ports[port] = 1;
                if (is_stealth) rst_count++;
            }
            if (all_sent && grace_start != 0) grace_start = time(NULL);
        }

check_grace:
        if (all_sent) {
            if (grace_start == 0) grace_start = time(NULL);
            else if (time(NULL) - grace_start > RX_GRACE) break;
        }
    }

    if (is_stealth) {
        printf("\n[*] RSTs received: %lu (closed ports)\n", rst_count);
        if (rst_count == 0) {
            printf("[!] Zero RST replies received.\n");
            printf("[!] Possible causes:\n");
            printf("[!]   - Target is Windows (FIN/NULL/XMAS don't work against it)\n");
            printf("[!]   - Firewall is blocking/dropping all replies\n");
            printf("[!]   - Run: tcpdump -i %s 'tcp[tcpflags] & tcp-rst != 0 "
                   "and dst port %d' to verify\n", IFACE, SRC_PORT);
        } else {
            int found = 0;
            for (int p = data->start_port; p <= data->end_port; p++) {
                if (data->syn_sent[p]
                 && !data->closed_ports[p]
                 && !data->open_ports[p]) {
                    printf("[OPEN|FILTERED] %d - %s\n",
                           p, identify_service(p, "tcp"));
                    fflush(stdout);
                    found++;
                }
            }
            if (!found) printf("[*] No open|filtered ports found.\n");
        }
    }

    close(sock);
    return NULL;
}
