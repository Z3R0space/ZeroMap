#ifndef SCANNER_H
#define SCANNER_H

#include <stdint.h>
#include <pthread.h>

// basic conf
#define MAX_PORT       65535
#define SRC_PORT       54321
#define IFACE          "ens33"
#define TUN_IFACE      "tun0"
#define BATCH_SIZE     64
#define TX_THREADS     4
#define RX_GRACE       2

// Retry variables
#define RETRY_DELAY_MS 800
#define MAX_RETRIES    1

// defining stealth modes
typedef enum {
    MODE_SYN   = 0,
    MODE_FIN   = 1,
    MODE_NULL  = 2,
    MODE_XMAS  = 3,
    MODE_DECOY = 4,
    MODE_FRAG  = 5,
    MODE_SLOW  = 6
} scan_mode_t;

// Conf for decoy
#define MAX_DECOYS  5
static const char *DECOY_IPS[MAX_DECOYS] = {
    "10.0.0.200",
    "10.0.0.201",
    "192.168.1.50",
    "192.168.1.51",
    "172.16.0.99"
};

// Conf for slow mode
#define SLOW_MIN_DELAY_US   5000
#define SLOW_MAX_DELAY_US  50000

// Shodan conf
#define SHODAN_API_KEY  "XR6lTYiy9Ej2U8QDVRB0slhHImP7pV3g"
void shodan_scan(const char *ip, int start_port, int end_port);

// Shared data structure
typedef struct {
    char        target_ip[16];
    uint8_t     open_ports[MAX_PORT + 1];
    uint8_t     closed_ports[MAX_PORT + 1];  // NEW: RST received = confirmed closed
    uint8_t     syn_sent[MAX_PORT + 1];
    uint32_t    seq_for_port[MAX_PORT + 1];
    scan_mode_t mode;
    int         start_port;
    int         end_port;
    int         use_decoy;
    int         use_tun;
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
void *send_thread(void *arg);
void *recv_thread(void *arg);

void get_iface_info(unsigned char *mac, char *ip);
void get_target_mac(const char *ip, unsigned char *mac);
void build_packet(char *buffer,
                  const char *src_ip, const char *dst_ip,
                  unsigned char *src_mac, unsigned char *dst_mac,
                  int port, scan_mode_t mode);

void send_decoy_burst(scan_data_t *data,
                      unsigned char *src_mac,
                      unsigned char *dst_mac);

#endif
