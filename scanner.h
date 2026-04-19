#ifndef SCANNER_H
#define SCANNER_H

#include <stdint.h>
#include <pthread.h>

// Basic Configuration
#define MAX_PORT        65535
#define SRC_PORT        54321
#define IFACE           "eth0"
#define TUN_IFACE       "tun0"
#define BATCH_SIZE      64
#define TX_THREADS      4
#define RX_GRACE        2
#define RX_GRACE_STEALTH 4   

// Retry Configuration
#define RETRY_DELAY_MS  800
#define MAX_RETRIES     1

// Shodan Configuration
#define SHODAN_API_KEY  "YOUR_SHODAN_API_KEY_HERE"

// Scan Methods
typedef enum {
    MODE_SYN   = 0,
    MODE_FIN   = 1,
    MODE_NULL  = 2,
    MODE_XMAS  = 3,
    MODE_DECOY = 4,
    MODE_FRAG  = 5,
    MODE_SLOW  = 6
} scan_mode_t;

// Decoy Configuration
#define MAX_DECOYS  100
static const char *DECOY_IPS[MAX_DECOYS] = {
    "10.0.0.5", "10.0.0.12", "10.0.0.28", "10.0.0.45", "10.0.0.67", "10.0.0.89", "10.0.0.102", "10.0.0.115", "10.0.0.130", "10.0.0.155",
    "10.0.1.10", "10.0.1.22", "10.0.1.34", "10.0.1.48", "10.0.1.61", "10.0.1.75", "10.0.1.90", "10.0.1.112", "10.0.1.140", "10.0.1.180",
    "192.168.0.15", "192.168.0.24", "192.168.0.38", "192.168.0.52", "192.168.0.77", "192.168.0.84", "192.168.0.91", "192.168.0.110", "192.168.0.125", "192.168.0.150",
    "192.168.1.12", "192.168.1.25", "192.168.1.33", "192.168.1.47", "192.168.1.60", "192.168.1.72", "192.168.1.88", "192.168.1.105", "192.168.1.120", "192.168.1.202",
    "192.168.2.14", "192.168.2.31", "192.168.2.49", "192.168.2.66", "192.168.2.82", "192.168.2.95", "192.168.2.118", "192.168.2.134", "192.168.2.160", "192.168.2.190",
    "172.16.0.5", "172.16.0.18", "172.16.0.33", "172.16.0.47", "172.16.0.62", "172.16.0.88", "172.16.0.104", "172.16.0.125", "172.16.0.140", "172.16.0.210",
    "172.16.1.11", "172.16.1.27", "172.16.1.43", "172.16.1.59", "172.16.1.76", "172.16.1.92", "172.16.1.114", "172.16.1.130", "172.16.1.155", "172.16.1.205",
    "10.10.1.5", "10.10.1.15", "10.10.1.25", "10.10.1.35", "10.10.1.45", "10.10.1.55", "10.10.1.65", "10.10.1.75", "10.10.1.85", "10.10.1.95",
    "10.20.30.40", "10.20.30.50", "10.20.30.60", "10.20.30.70", "10.20.30.80", "10.20.30.90", "10.20.30.100", "10.20.30.110", "10.20.30.120", "10.20.30.130",
    "192.168.10.10", "192.168.10.20", "192.168.10.30", "192.168.10.40", "192.168.10.50", "192.168.10.60", "192.168.10.70", "192.168.10.80", "192.168.10.90", "192.168.10.100"
};

// Slow-mode Configuration
#define SLOW_MIN_DELAY_US    5000
#define SLOW_MAX_DELAY_US   50000

// Shared-data structure
typedef struct {
    char        target_ip[16];
    uint8_t     open_ports[MAX_PORT + 1];
    uint8_t     closed_ports[MAX_PORT + 1];
    uint8_t     syn_sent[MAX_PORT + 1];
    uint32_t    seq_for_port[MAX_PORT + 1];
    scan_mode_t mode;
    int         start_port;
    int         end_port;
    int         use_decoy;
    int         use_tun;
    uint16_t    src_port;      // runtime source port; defaults to SRC_PORT
} scan_data_t;

typedef struct {
    scan_data_t *data;
    int          thread_id;
    int         *port_list;
    int          port_count;
    int          total_threads;
} tx_args_t;

// Globals
extern volatile int threads_done;
extern volatile int all_sent;

// Public API

// Ethernet multi-threaded TX
void *send_thread(void *arg);

// TUN single-threaded TX — sequential full-range scan.
void *send_thread_tun(void *arg);

// TUN retry TX — sequential scan of an explicit port list.
void *send_thread_tun_retry(void *arg);

// RX thread — dispatches to Ethernet or tun path based on data->use_tun
void *recv_thread(void *arg);

void get_iface_info(unsigned char *mac, char *ip);
void get_target_mac(const char *ip, unsigned char *mac);

// src_port added so every caller passes data->src_port instead of the #define
void build_packet(char *buffer,
                  const char *src_ip, const char *dst_ip,
                  unsigned char *src_mac, unsigned char *dst_mac,
                  int port, scan_mode_t mode,
                  uint16_t src_port);

void send_decoy_burst(scan_data_t *data,
                      unsigned char *src_mac,
                      unsigned char *dst_mac);
void shodan_scan(const char *ip, int start_port, int end_port);

#endif
