#include "scanner.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <curl/curl.h>
#include <cjson/cJSON.h>

char *DECOY_IPS[MAX_DECOYS];
size_t DECOY_COUNT = 0;

typedef struct {
    char *data;
    size_t size;
} Memory;

static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t total = size * nmemb;
    Memory *mem = (Memory *)userp;

    mem->data = realloc(mem->data, mem->size + total + 1);
    memcpy(mem->data + mem->size, contents, total);

    mem->size += total;
    mem->data[mem->size] = 0;

    return total;
}

static void add_ip(const char *ip) {
    if (DECOY_COUNT >= MAX_DECOYS) return;
    DECOY_IPS[DECOY_COUNT++] = strdup(ip);
}

static void expand_cidr(const char *cidr) {
    char ip_str[32];
    int prefix;

    sscanf(cidr, "%[^/]/%d", ip_str, &prefix);

    struct in_addr addr;
    inet_pton(AF_INET, ip_str, &addr);

    uint32_t ip = ntohl(addr.s_addr);
    uint32_t mask = (prefix == 0) ? 0 : (0xFFFFFFFF << (32 - prefix));

    uint32_t network = ip & mask;
    uint32_t broadcast = network | ~mask;

    for (uint32_t i = network; i <= broadcast && DECOY_COUNT < MAX_DECOYS; i++) {
        struct in_addr out;
        out.s_addr = htonl(i);
        add_ip(inet_ntoa(out));
    }
}

void init_decoy_ips() {
    CURL *curl = curl_easy_init();
    Memory chunk = {0};

    curl_easy_setopt(curl, CURLOPT_URL, "https://api.cloudflare.com/client/v4/ips");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &chunk);

    if (curl_easy_perform(curl) != CURLE_OK) {
        fprintf(stderr, "[!] Failed to fetch CDN IPs\n");
        return;
    }

    cJSON *json = cJSON_Parse(chunk.data);
    cJSON *result = cJSON_GetObjectItem(json, "result");
    cJSON *ipv4 = cJSON_GetObjectItem(result, "ipv4_cidrs");

    for (int i = 0; i < cJSON_GetArraySize(ipv4); i++) {
        const char *cidr = cJSON_GetArrayItem(ipv4, i)->valuestring;
        expand_cidr(cidr);
    }

    printf("[+] Loaded %zu decoy IPs\n", DECOY_COUNT);

    cJSON_Delete(json);
    free(chunk.data);
    curl_easy_cleanup(curl);
}
