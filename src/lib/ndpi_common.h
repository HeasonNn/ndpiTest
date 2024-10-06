#pragma once

#include <errno.h>
#include <ndpi/ndpi_api.h>
#include <ndpi/ndpi_main.h>
#include <ndpi/ndpi_typedefs.h>
#include <pcap.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>

// #define VERBOSE 1
#define MAX_FLOW_ROOTS_PER_THREAD 2048
#define MAX_IDLE_FLOWS_PER_THREAD 64
#define TICK_RESOLUTION           1000
#define MAX_READER_THREADS        4
#define IDLE_SCAN_PERIOD          10000  /* msec */
#define MAX_IDLE_TIME             300000 /* msec */
#define INITIAL_THREAD_HASH       0x03dd018b

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

#ifndef ETH_P_IPV6
#define ETH_P_IPV6 0x86DD
#endif

#ifndef ETH_P_ARP
#define ETH_P_ARP 0x0806
#endif

enum nDPI_l3_type
{
    L3_IP,
    L3_IP6
};

struct nDPI_flow_info
{
    uint32_t flow_id;
    unsigned long long int packets_processed;
    uint64_t first_seen;
    uint64_t last_seen;
    uint64_t hashval;

    enum nDPI_l3_type l3_type;
    union
    {
        struct
        {
            uint32_t src;
            uint32_t pad_00[3];
            uint32_t dst;
            uint32_t pad_01[3];
        } v4;
        struct
        {
            uint64_t src[2];
            uint64_t dst[2];
        } v6;

        struct
        {
            uint32_t src[4];
            uint32_t dst[4];
        } u32;
    } ip_tuple;

    unsigned long long int total_l4_data_len;
    uint16_t src_port;
    uint16_t dst_port;

    uint8_t is_midstream_flow : 1;
    uint8_t flow_fin_ack_seen : 1;
    uint8_t flow_ack_seen : 1;
    uint8_t detection_completed : 1;
    uint8_t tls_client_hello_seen : 1;
    uint8_t tls_server_hello_seen : 1;
    uint8_t flow_info_printed : 1;
    uint8_t reserved_00 : 1;
    uint8_t l4_protocol;

    struct ndpi_proto detected_l7_protocol;
    struct ndpi_proto guessed_protocol;

    struct ndpi_flow_struct *ndpi_flow;
};

struct nDPI_workflow
{
    pcap_t *pcap_handle;

    volatile long int error_or_eof;

    unsigned long long int packets_captured;
    unsigned long long int packets_processed;
    unsigned long long int total_l4_data_len;
    unsigned long long int detected_flow_protocols;

    uint64_t last_idle_scan_time;
    uint64_t last_time;

    void **ndpi_flows_active;
    unsigned long long int max_active_flows;
    unsigned long long int cur_active_flows;
    unsigned long long int total_active_flows;

    void **ndpi_flows_idle;
    unsigned long long int max_idle_flows;
    unsigned long long int cur_idle_flows;
    unsigned long long int total_idle_flows;

    struct ndpi_detection_module_struct *ndpi_struct;
};

static void free_workflow(struct nDPI_workflow **const workflow);
struct nDPI_workflow *init_workflow(char const *const file_or_device);
static void ndpi_flow_info_freer(void *const node);
static int ip_tuples_compare(struct nDPI_flow_info const *const A,
                             struct nDPI_flow_info const *const B);
static void ndpi_idle_scan_walker(void const *const A, ndpi_VISIT which,
                                  int depth, void *const user_data);
static int ndpi_workflow_node_cmp(void const *const A, void const *const B);
static void check_for_idle_flows(struct nDPI_workflow *const workflow);

static int ip_tuple_to_string(struct nDPI_flow_info const *const flow,
                              char *const src_addr_str, size_t src_addr_len,
                              char *const dst_addr_str, size_t dst_addr_len);
#ifdef VERBOSE
static void print_packet_info(
    struct nDPI_reader_thread const *const reader_thread,
    struct pcap_pkthdr const *const header, uint32_t l4_data_len,
    struct nDPI_flow_info const *const flow);
#endif

void ndpi_process_packet(uint8_t *const args,
                                struct pcap_pkthdr const *const header,
                                uint8_t const *const packet);

static volatile long int flow_id = 0;
static volatile long int main_thread_shutdown = 0;
