#include "ndpi_common.h"

struct nDPI_workflow *init_workflow(char const *const file_or_device)
{
    char pcap_error_buffer[PCAP_ERRBUF_SIZE];
    struct nDPI_workflow *workflow =
        (struct nDPI_workflow *)ndpi_calloc(1, sizeof(*workflow));
    const char *bpfFilter = "ip or ip6";
    static struct bpf_program bpf_code;
    static struct bpf_program *bpf_cfilter = NULL;

    if (workflow == NULL)
    {
        return NULL;
    }

    if (access(file_or_device, R_OK) != 0 && errno == ENOENT)
    {
        workflow->pcap_handle = pcap_open_live(file_or_device, /* 1536 */ 65535,
                                               1, 250, pcap_error_buffer);
    }
    else
    {
#ifdef WIN32
        workflow->pcap_handle =
            pcap_open_offline(file_or_device, pcap_error_buffer);
#else
        workflow->pcap_handle = pcap_open_offline_with_tstamp_precision(
            file_or_device, PCAP_TSTAMP_PRECISION_MICRO, pcap_error_buffer);
#endif
    }

    if (workflow->pcap_handle == NULL)
    {
        fprintf(stderr, "pcap_open_live / pcap_open_offline: %.*s\n",
                (int)PCAP_ERRBUF_SIZE, pcap_error_buffer);
        free_workflow(&workflow);
        return NULL;
    }

    if (pcap_compile(workflow->pcap_handle, &bpf_code, bpfFilter, 1,
                     0xFFFFFF00) < 0)
    {
        printf("pcap_compile error: '%s'\n",
               pcap_geterr(workflow->pcap_handle));
        exit(-1);
    }

    bpf_cfilter = &bpf_code;

    if (pcap_setfilter(workflow->pcap_handle, bpf_cfilter) < 0)
    {
        printf("pcap_setfilter error: '%s'\n",
               pcap_geterr(workflow->pcap_handle));
    }

    workflow->ndpi_struct = ndpi_init_detection_module(NULL);
    if (workflow->ndpi_struct == NULL)
    {
        free_workflow(&workflow);
        return NULL;
    }

    workflow->total_active_flows = 0;
    workflow->max_active_flows = MAX_FLOW_ROOTS_PER_THREAD;
    workflow->ndpi_flows_active =
        (void **)ndpi_calloc(workflow->max_active_flows, sizeof(void *));
    if (workflow->ndpi_flows_active == NULL)
    {
        free_workflow(&workflow);
        return NULL;
    }

    workflow->total_idle_flows = 0;
    workflow->max_idle_flows = MAX_IDLE_FLOWS_PER_THREAD;
    workflow->ndpi_flows_idle =
        (void **)ndpi_calloc(workflow->max_idle_flows, sizeof(void *));
    if (workflow->ndpi_flows_idle == NULL)
    {
        free_workflow(&workflow);
        return NULL;
    }

    NDPI_PROTOCOL_BITMASK protos;
    NDPI_BITMASK_SET_ALL(protos);
    ndpi_set_protocol_detection_bitmask2(workflow->ndpi_struct, &protos);
    ndpi_finalize_initialization(workflow->ndpi_struct);

    return workflow;
}

static void ndpi_flow_info_freer(void *const node)
{
    struct nDPI_flow_info *const flow = (struct nDPI_flow_info *)node;

    ndpi_flow_free(flow->ndpi_flow);
    ndpi_free(flow);
}

static void free_workflow(struct nDPI_workflow **const workflow)
{
    struct nDPI_workflow *const w = *workflow;
    size_t i;

    if (w == NULL)
    {
        return;
    }

    if (w->pcap_handle != NULL)
    {
        pcap_close(w->pcap_handle);
        w->pcap_handle = NULL;
    }

    if (w->ndpi_struct != NULL)
    {
        ndpi_exit_detection_module(w->ndpi_struct);
    }
    for (i = 0; i < w->max_active_flows; i++)
    {
        ndpi_tdestroy(w->ndpi_flows_active[i], ndpi_flow_info_freer);
    }
    ndpi_free(w->ndpi_flows_active);
    ndpi_free(w->ndpi_flows_idle);
    ndpi_free(w);
    *workflow = NULL;
}

static int ip_tuple_to_string(struct nDPI_flow_info const *const flow,
                              char *const src_addr_str, size_t src_addr_len,
                              char *const dst_addr_str, size_t dst_addr_len)
{
    switch (flow->l3_type)
    {
        case L3_IP:
            return inet_ntop(AF_INET,
                             (struct sockaddr_in *)&flow->ip_tuple.v4.src,
                             src_addr_str, src_addr_len) != NULL &&
                   inet_ntop(AF_INET,
                             (struct sockaddr_in *)&flow->ip_tuple.v4.dst,
                             dst_addr_str, dst_addr_len) != NULL;
        case L3_IP6:
            return inet_ntop(AF_INET6,
                             (struct sockaddr_in6 *)&flow->ip_tuple.v6.src[0],
                             src_addr_str, src_addr_len) != NULL &&
                   inet_ntop(AF_INET6,
                             (struct sockaddr_in6 *)&flow->ip_tuple.v6.dst[0],
                             dst_addr_str, dst_addr_len) != NULL;
    }

    return 0;
}

#ifdef VERBOSE
static void print_packet_info(
    struct nDPI_reader_thread const *const reader_thread,
    struct pcap_pkthdr const *const header, uint32_t l4_data_len,
    struct nDPI_flow_info const *const flow)
{
    struct nDPI_workflow const *const workflow = reader_thread->workflow;
    char src_addr_str[INET6_ADDRSTRLEN + 1] = {0};
    char dst_addr_str[INET6_ADDRSTRLEN + 1] = {0};
    char buf[256];
    int used = 0, ret;

    ret = ndpi_snprintf(buf, sizeof(buf), "[%8llu, %d, %4u] %4u bytes: ",
                        workflow->packets_captured, reader_thread->array_index,
                        flow->flow_id, header->caplen);
    if (ret > 0)
    {
        used += ret;
    }

    if (ip_tuple_to_string(flow, src_addr_str, sizeof(src_addr_str),
                           dst_addr_str, sizeof(dst_addr_str)) != 0)
    {
        ret = ndpi_snprintf(buf + used, sizeof(buf) - used, "IP[%s -> %s]",
                            src_addr_str, dst_addr_str);
    }
    else
    {
        ret = ndpi_snprintf(buf + used, sizeof(buf) - used, "IP[ERROR]");
    }
    if (ret > 0)
    {
        used += ret;
    }

    switch (flow->l4_protocol)
    {
        case IPPROTO_UDP:
            ret = ndpi_snprintf(buf + used, sizeof(buf) - used,
                                " -> UDP[%u -> %u, %u bytes]", flow->src_port,
                                flow->dst_port, l4_data_len);
            break;
        case IPPROTO_TCP:
            ret = ndpi_snprintf(buf + used, sizeof(buf) - used,
                                " -> TCP[%u -> %u, %u bytes]", flow->src_port,
                                flow->dst_port, l4_data_len);
            break;
        case IPPROTO_ICMP:
            ret = ndpi_snprintf(buf + used, sizeof(buf) - used, " -> ICMP");
            break;
        case IPPROTO_ICMPV6:
            ret = ndpi_snprintf(buf + used, sizeof(buf) - used, " -> ICMP6");
            break;
        case IPPROTO_HOPOPTS:
            ret = ndpi_snprintf(buf + used, sizeof(buf) - used,
                                " -> ICMP6 Hop-By-Hop");
            break;
        default:
            ret = ndpi_snprintf(buf + used, sizeof(buf) - used,
                                " -> Unknown[0x%X]", flow->l4_protocol);
            break;
    }
    if (ret > 0)
    {
        used += ret;
    }

    printf("%.*s\n", used, buf);
}
#endif

static int ip_tuples_compare(struct nDPI_flow_info const *const A,
                             struct nDPI_flow_info const *const B)
{
    // generate a warning if the enum changes
    switch (A->l3_type)
    {
        case L3_IP:
        case L3_IP6:
            break;
    }

    if (A->l3_type == L3_IP && B->l3_type == L3_IP)
    {
        if (A->ip_tuple.v4.src < B->ip_tuple.v4.src)
        {
            return -1;
        }
        if (A->ip_tuple.v4.src > B->ip_tuple.v4.src)
        {
            return 1;
        }
        if (A->ip_tuple.v4.dst < B->ip_tuple.v4.dst)
        {
            return -1;
        }
        if (A->ip_tuple.v4.dst > B->ip_tuple.v4.dst)
        {
            return 1;
        }
    }
    else if (A->l3_type == L3_IP6 && B->l3_type == L3_IP6)
    {
        if (A->ip_tuple.v6.src[0] < B->ip_tuple.v6.src[0] &&
            A->ip_tuple.v6.src[1] < B->ip_tuple.v6.src[1])
        {
            return -1;
        }
        if (A->ip_tuple.v6.src[0] > B->ip_tuple.v6.src[0] &&
            A->ip_tuple.v6.src[1] > B->ip_tuple.v6.src[1])
        {
            return 1;
        }
        if (A->ip_tuple.v6.dst[0] < B->ip_tuple.v6.dst[0] &&
            A->ip_tuple.v6.dst[1] < B->ip_tuple.v6.dst[1])
        {
            return -1;
        }
        if (A->ip_tuple.v6.dst[0] > B->ip_tuple.v6.dst[0] &&
            A->ip_tuple.v6.dst[1] > B->ip_tuple.v6.dst[1])
        {
            return 1;
        }
    }

    if (A->src_port < B->src_port)
    {
        return -1;
    }
    if (A->src_port > B->src_port)
    {
        return 1;
    }
    if (A->dst_port < B->dst_port)
    {
        return -1;
    }
    if (A->dst_port > B->dst_port)
    {
        return 1;
    }

    return 0;
}

static void ndpi_idle_scan_walker(void const *const A, ndpi_VISIT which,
                                  int depth, void *const user_data)
{
    struct nDPI_workflow *const workflow = (struct nDPI_workflow *)user_data;
    struct nDPI_flow_info *const flow = *(struct nDPI_flow_info **)A;

    (void)depth;

    if (workflow == NULL || flow == NULL)
    {
        return;
    }

    if (workflow->cur_idle_flows == MAX_IDLE_FLOWS_PER_THREAD)
    {
        return;
    }

    if (which == ndpi_preorder || which == ndpi_leaf)
    {
        if ((flow->flow_fin_ack_seen == 1 && flow->flow_ack_seen == 1) ||
            flow->last_seen + MAX_IDLE_TIME < workflow->last_time)
        {
            char src_addr_str[INET6_ADDRSTRLEN + 1];
            char dst_addr_str[INET6_ADDRSTRLEN + 1];
            ip_tuple_to_string(flow, src_addr_str, sizeof(src_addr_str),
                               dst_addr_str, sizeof(dst_addr_str));
            workflow->ndpi_flows_idle[workflow->cur_idle_flows++] = flow;
            workflow->total_idle_flows++;
        }
    }
}

static int ndpi_workflow_node_cmp(void const *const A, void const *const B)
{
    struct nDPI_flow_info const *const flow_info_a = (struct nDPI_flow_info *)A;
    struct nDPI_flow_info const *const flow_info_b = (struct nDPI_flow_info *)B;

    if (flow_info_a->hashval < flow_info_b->hashval)
    {
        return (-1);
    }
    else if (flow_info_a->hashval > flow_info_b->hashval)
    {
        return (1);
    }

    /* Flows have the same hash */
    if (flow_info_a->l4_protocol < flow_info_b->l4_protocol)
    {
        return (-1);
    }
    else if (flow_info_a->l4_protocol > flow_info_b->l4_protocol)
    {
        return (1);
    }

    return ip_tuples_compare(flow_info_a, flow_info_b);
}

static void check_for_idle_flows(struct nDPI_workflow *const workflow)
{
    size_t idle_scan_index;

    if (workflow->last_idle_scan_time + IDLE_SCAN_PERIOD < workflow->last_time)
    {
        for (idle_scan_index = 0; idle_scan_index < workflow->max_active_flows;
             ++idle_scan_index)
        {
            ndpi_twalk(workflow->ndpi_flows_active[idle_scan_index],
                       ndpi_idle_scan_walker, workflow);

            while (workflow->cur_idle_flows > 0)
            {
                struct nDPI_flow_info *const f =
                    (struct nDPI_flow_info *)
                        workflow->ndpi_flows_idle[--workflow->cur_idle_flows];
                if (f->flow_fin_ack_seen == 1)
                {
                    printf("Free fin flow with id %u\n", f->flow_id);
                }
                else
                {
                    printf("Free idle flow with id %u\n", f->flow_id);
                }
                ndpi_tdelete(f, &workflow->ndpi_flows_active[idle_scan_index],
                             ndpi_workflow_node_cmp);
                ndpi_flow_info_freer(f);
                workflow->cur_active_flows--;
            }
        }

        workflow->last_idle_scan_time = workflow->last_time;
    }
}

void ndpi_process_packet(uint8_t *const args,
                         struct pcap_pkthdr const *const header,
                         uint8_t const *const packet)
{
    struct nDPI_workflow *workflow = (struct nDPI_workflow *)args;
    if (workflow == NULL)
    {
        return;
    }

    struct nDPI_flow_info flow;

    size_t hashed_index;
    void *tree_result;
    struct nDPI_flow_info *flow_to_process;

    const struct ndpi_ethhdr *ethernet;
    const struct ndpi_iphdr *ip;
    struct ndpi_ipv6hdr *ip6;

    uint64_t time_ms;
    const uint16_t eth_offset = 0;
    uint16_t ip_offset;
    uint16_t ip_size;

    const uint8_t *l4_ptr = NULL;
    uint16_t l4_len = 0;

    uint16_t type;
    uint32_t thread_index =
        INITIAL_THREAD_HASH;  // generated with `dd if=/dev/random bs=1024
                              // count=1 |& hd'

    memset(&flow, '\0', sizeof(flow));

    workflow->packets_captured++;
    time_ms = ((uint64_t)header->ts.tv_sec) * TICK_RESOLUTION +
              header->ts.tv_usec / (1000000 / TICK_RESOLUTION);
    workflow->last_time = time_ms;

    check_for_idle_flows(workflow);

    /* process datalink layer */
    switch (pcap_datalink(workflow->pcap_handle))
    {
        case DLT_NULL:
            if (ntohl(*((uint32_t *)&packet[eth_offset])) == 0x00000002)
            {
                type = ETH_P_IP;
            }
            else
            {
                type = ETH_P_IPV6;
            }
            ip_offset = 4 + eth_offset;
            break;
        case DLT_EN10MB:
            if (header->len < sizeof(struct ndpi_ethhdr))
            {
                fprintf(stderr,
                        "[%8llu, %d] Ethernet packet too short - skipping\n",
                        workflow->packets_captured, 0);
                return;
            }
            ethernet = (struct ndpi_ethhdr *)&packet[eth_offset];
            ip_offset = sizeof(struct ndpi_ethhdr) + eth_offset;
            type = ntohs(ethernet->h_proto);
            switch (type)
            {
                case ETH_P_IP: /* IPv4 */
                    if (header->len <
                        sizeof(struct ndpi_ethhdr) + sizeof(struct ndpi_iphdr))
                    {
                        fprintf(stderr,
                                "[%8llu, %d] IP packet too short - skipping\n",
                                workflow->packets_captured, 0);
                        return;
                    }
                    break;
                case ETH_P_IPV6: /* IPV6 */
                    if (header->len < sizeof(struct ndpi_ethhdr) +
                                          sizeof(struct ndpi_ipv6hdr))
                    {
                        fprintf(stderr,
                                "[%8llu, %d] IP6 packet too short - skipping\n",
                                workflow->packets_captured, 0);
                        return;
                    }
                    break;
                case ETH_P_ARP: /* ARP */
                    return;
                default:
                    fprintf(stderr,
                            "[%8llu, %d] Unknown Ethernet packet with type "
                            "0x%X - skipping\n",
                            workflow->packets_captured, 0, 0);
                    return;
            }
            break;
        default:
            fprintf(stderr,
                    "[%8llu, %d] Captured non IP/Ethernet packet with datalink "
                    "type 0x%X - skipping\n",
                    workflow->packets_captured, 0,
                    pcap_datalink(workflow->pcap_handle));
            return;
    }

    if (type == ETH_P_IP)
    {
        ip = (struct ndpi_iphdr *)&packet[ip_offset];
        ip6 = NULL;
    }
    else if (type == ETH_P_IPV6)
    {
        ip = NULL;
        ip6 = (struct ndpi_ipv6hdr *)&packet[ip_offset];
    }
    else
    {
        fprintf(stderr,
                "[%8llu, %d] Captured non IPv4/IPv6 packet with type 0x%X - "
                "skipping\n",
                workflow->packets_captured, 0, type);
        return;
    }
    ip_size = header->len - ip_offset;

    if (type == ETH_P_IP && header->len >= ip_offset)
    {
        if (header->caplen < header->len)
        {
            fprintf(stderr,
                    "[%8llu, %d] Captured packet size is smaller than packet "
                    "size: %u < %u\n",
                    workflow->packets_captured, 0, header->caplen, header->len);
        }
    }

    /* process layer3 e.g. IPv4 / IPv6 */
    if (ip != NULL && ip->version == 4)
    {
        if (ip_size < sizeof(*ip))
        {
            fprintf(
                stderr,
                "[%8llu, %d] Packet smaller than IP4 header length: %u < %zu\n",
                workflow->packets_captured, 0, ip_size, sizeof(*ip));
            return;
        }

        flow.l3_type = L3_IP;
        if (ndpi_detection_get_l4((uint8_t *)ip, ip_size, &l4_ptr, &l4_len,
                                  &flow.l4_protocol,
                                  NDPI_DETECTION_ONLY_IPV4) != 0)
        {
            fprintf(stderr,
                    "[%8llu, %d] nDPI IPv4/L4 payload detection failed, L4 "
                    "length: %zu\n",
                    workflow->packets_captured, 0, ip_size - sizeof(*ip));
            return;
        }

        flow.ip_tuple.v4.src = ip->saddr;
        flow.ip_tuple.v4.dst = ip->daddr;
        uint32_t min_addr = (flow.ip_tuple.v4.src > flow.ip_tuple.v4.dst
                                 ? flow.ip_tuple.v4.dst
                                 : flow.ip_tuple.v4.src);
        thread_index = min_addr + ip->protocol;
    }
    else if (ip6 != NULL)
    {
        if (ip_size < sizeof(ip6->ip6_hdr))
        {
            fprintf(
                stderr,
                "[%8llu, %d] Packet smaller than IP6 header length: %u < %zu\n",
                workflow->packets_captured, 0, ip_size, sizeof(ip6->ip6_hdr));
            return;
        }

        flow.l3_type = L3_IP6;
        if (ndpi_detection_get_l4((uint8_t *)ip6, ip_size, &l4_ptr, &l4_len,
                                  &flow.l4_protocol,
                                  NDPI_DETECTION_ONLY_IPV6) != 0)
        {
            fprintf(stderr,
                    "[%8llu, %d] nDPI IPv6/L4 payload detection failed, L4 "
                    "length: %zu\n",
                    workflow->packets_captured, 0, ip_size - sizeof(*ip6));
            return;
        }

        flow.ip_tuple.v6.src[0] = ip6->ip6_src.u6_addr.u6_addr64[0];
        flow.ip_tuple.v6.src[1] = ip6->ip6_src.u6_addr.u6_addr64[1];
        flow.ip_tuple.v6.dst[0] = ip6->ip6_dst.u6_addr.u6_addr64[0];
        flow.ip_tuple.v6.dst[1] = ip6->ip6_dst.u6_addr.u6_addr64[1];
        uint64_t min_addr[2];
        if (flow.ip_tuple.v6.src[0] > flow.ip_tuple.v6.dst[0] &&
            flow.ip_tuple.v6.src[1] > flow.ip_tuple.v6.dst[1])
        {
            min_addr[0] = flow.ip_tuple.v6.dst[0];
            min_addr[1] = flow.ip_tuple.v6.dst[0];
        }
        else
        {
            min_addr[0] = flow.ip_tuple.v6.src[0];
            min_addr[1] = flow.ip_tuple.v6.src[0];
        }
        thread_index = min_addr[0] + min_addr[1] + ip6->ip6_hdr.ip6_un1_nxt;
    }
    else
    {
        fprintf(stderr, "[%8llu, %d] Non IP/IPv6 protocol detected: 0x%X\n",
                workflow->packets_captured, 0, type);
        return;
    }

    /* process layer4 e.g. TCP / UDP */
    if (flow.l4_protocol == IPPROTO_TCP)
    {
        const struct ndpi_tcphdr *tcp;

        if (header->len < (l4_ptr - packet) + sizeof(struct ndpi_tcphdr))
        {
            fprintf(stderr,
                    "[%8llu, %d] Malformed TCP packet, packet size smaller "
                    "than expected: %u < %zu\n",
                    workflow->packets_captured, 0, header->len,
                    (l4_ptr - packet) + sizeof(struct ndpi_tcphdr));
            return;
        }
        tcp = (struct ndpi_tcphdr *)l4_ptr;
        flow.is_midstream_flow = (tcp->syn == 0 ? 1 : 0);
        flow.flow_fin_ack_seen = (tcp->fin == 1 && tcp->ack == 1 ? 1 : 0);
        flow.flow_ack_seen = tcp->ack;
        flow.src_port = ntohs(tcp->source);
        flow.dst_port = ntohs(tcp->dest);
    }
    else if (flow.l4_protocol == IPPROTO_UDP)
    {
        const struct ndpi_udphdr *udp;

        if (header->len < (l4_ptr - packet) + sizeof(struct ndpi_udphdr))
        {
            fprintf(stderr,
                    "[%8llu, %d] Malformed UDP packet, packet size smaller "
                    "than expected: %u < %zu\n",
                    workflow->packets_captured, 0, header->len,
                    (l4_ptr - packet) + sizeof(struct ndpi_udphdr));
            return;
        }
        udp = (struct ndpi_udphdr *)l4_ptr;
        flow.src_port = ntohs(udp->source);
        flow.dst_port = ntohs(udp->dest);
    }

    workflow->packets_processed++;
    workflow->total_l4_data_len += l4_len;

#ifdef VERBOSE
    print_packet_info(reader_thread, header, l4_len, &flow);
#endif

    {
        uint64_t tmp[4] = {};

        /* calculate flow hash for btree find, search(insert) */
        if (flow.l3_type == L3_IP)
        {
            if (ndpi_flowv4_flow_hash(flow.l4_protocol, flow.ip_tuple.v4.src,
                                      flow.ip_tuple.v4.dst, flow.src_port,
                                      flow.dst_port, 0, 0, (uint8_t *)&tmp[0],
                                      sizeof(tmp)) != 0)
            {
                flow.hashval =
                    flow.ip_tuple.v4.src + flow.ip_tuple.v4.dst;  // fallback
            }
            else
            {
                flow.hashval = tmp[0] + tmp[1] + tmp[2] + tmp[3];
            }
        }
        else if (flow.l3_type == L3_IP6)
        {
            if (ndpi_flowv6_flow_hash(flow.l4_protocol, &ip6->ip6_src,
                                      &ip6->ip6_dst, flow.src_port,
                                      flow.dst_port, 0, 0, (uint8_t *)&tmp[0],
                                      sizeof(tmp)) != 0)
            {
                flow.hashval =
                    flow.ip_tuple.v6.src[0] + flow.ip_tuple.v6.src[1];
                flow.hashval +=
                    flow.ip_tuple.v6.dst[0] + flow.ip_tuple.v6.dst[1];
            }
            else
            {
                flow.hashval = tmp[0] + tmp[1] + tmp[2] + tmp[3];
            }
        }

        flow.hashval += flow.l4_protocol + flow.src_port + flow.dst_port;
    }

    hashed_index = flow.hashval % workflow->max_active_flows;
    tree_result = ndpi_tfind(&flow, &workflow->ndpi_flows_active[hashed_index],
                             ndpi_workflow_node_cmp);
    if (tree_result == NULL)
    {
        /* flow not found in btree: switch src <-> dst and try to find it again
         */
        uint32_t orig_src_ip[4] = {
            flow.ip_tuple.u32.src[0], flow.ip_tuple.u32.src[1],
            flow.ip_tuple.u32.src[2], flow.ip_tuple.u32.src[3]};
        uint32_t orig_dst_ip[4] = {
            flow.ip_tuple.u32.dst[0], flow.ip_tuple.u32.dst[1],
            flow.ip_tuple.u32.dst[2], flow.ip_tuple.u32.dst[3]};
        uint16_t orig_src_port = flow.src_port;
        uint16_t orig_dst_port = flow.dst_port;

        flow.ip_tuple.u32.src[0] = orig_dst_ip[0];
        flow.ip_tuple.u32.src[1] = orig_dst_ip[1];
        flow.ip_tuple.u32.src[2] = orig_dst_ip[2];
        flow.ip_tuple.u32.src[3] = orig_dst_ip[3];

        flow.ip_tuple.u32.dst[0] = orig_src_ip[0];
        flow.ip_tuple.u32.dst[1] = orig_src_ip[1];
        flow.ip_tuple.u32.dst[2] = orig_src_ip[2];
        flow.ip_tuple.u32.dst[3] = orig_src_ip[3];

        flow.src_port = orig_dst_port;
        flow.dst_port = orig_src_port;

        tree_result =
            ndpi_tfind(&flow, &workflow->ndpi_flows_active[hashed_index],
                       ndpi_workflow_node_cmp);

        flow.ip_tuple.u32.src[0] = orig_src_ip[0];
        flow.ip_tuple.u32.src[1] = orig_src_ip[1];
        flow.ip_tuple.u32.src[2] = orig_src_ip[2];
        flow.ip_tuple.u32.src[3] = orig_src_ip[3];

        flow.ip_tuple.u32.dst[0] = orig_dst_ip[0];
        flow.ip_tuple.u32.dst[1] = orig_dst_ip[1];
        flow.ip_tuple.u32.dst[2] = orig_dst_ip[2];
        flow.ip_tuple.u32.dst[3] = orig_dst_ip[3];

        flow.src_port = orig_src_port;
        flow.dst_port = orig_dst_port;
    }

    if (tree_result == NULL)
    {
        /* flow still not found, must be new */
        if (workflow->cur_active_flows == workflow->max_active_flows)
        {
            fprintf(
                stderr,
                "[%8llu, %d] max flows to track reached: %llu, idle: %llu\n",
                workflow->packets_captured, 0, workflow->max_active_flows,
                workflow->cur_idle_flows);
            return;
        }

        flow_to_process =
            (struct nDPI_flow_info *)ndpi_malloc(sizeof(*flow_to_process));
        if (flow_to_process == NULL)
        {
            fprintf(stderr, "[%8llu, %d] Not enough memory for flow info\n",
                    workflow->packets_captured, 0);
            return;
        }

        memcpy(flow_to_process, &flow, sizeof(*flow_to_process));
        flow_to_process->flow_id = __sync_fetch_and_add(&flow_id, 1);

        flow_to_process->ndpi_flow =
            (struct ndpi_flow_struct *)ndpi_flow_malloc(SIZEOF_FLOW_STRUCT);
        if (flow_to_process->ndpi_flow == NULL)
        {
            fprintf(stderr,
                    "[%8llu, %d, %4u] Not enough memory for flow struct\n",
                    workflow->packets_captured, 0, flow_to_process->flow_id);
            return;
        }
        memset(flow_to_process->ndpi_flow, 0, SIZEOF_FLOW_STRUCT);

        printf("[%8llu, %d, %4u] new %sflow\n", workflow->packets_captured,
               thread_index, flow_to_process->flow_id,
               (flow_to_process->is_midstream_flow != 0 ? "midstream-" : ""));
        if (ndpi_tsearch(flow_to_process,
                         &workflow->ndpi_flows_active[hashed_index],
                         ndpi_workflow_node_cmp) == NULL)
        {
            /* Possible Leak, but should not happen as we'd abort earlier. */
            return;
        }

        workflow->cur_active_flows++;
        workflow->total_active_flows++;
    }
    else
    {
        flow_to_process = *(struct nDPI_flow_info **)tree_result;
    }

    flow_to_process->packets_processed++;
    flow_to_process->total_l4_data_len += l4_len;
    /* update timestamps, important for timeout handling */
    if (flow_to_process->first_seen == 0)
    {
        flow_to_process->first_seen = time_ms;
    }
    flow_to_process->last_seen = time_ms;
    /* current packet is an TCP-ACK? */
    flow_to_process->flow_ack_seen = flow.flow_ack_seen;

    /* TCP-FIN: indicates that at least one side wants to end the connection */
    if (flow.flow_fin_ack_seen != 0 && flow_to_process->flow_fin_ack_seen == 0)
    {
        flow_to_process->flow_fin_ack_seen = 1;
        printf("[%8llu, %d, %4u] end of flow\n", workflow->packets_captured,
               thread_index, flow_to_process->flow_id);
        return;
    }

    /*
     * This example tries to use maximum supported packets for detection:
     * for uint8: 0xFF
     */
    if (flow_to_process->ndpi_flow->num_processed_pkts == 0xFF)
    {
        return;
    }
    else if (flow_to_process->ndpi_flow->num_processed_pkts == 0xFE)
    {
        /* last chance to guess something, better then nothing */
        uint8_t protocol_was_guessed = 0;
        flow_to_process->guessed_protocol = ndpi_detection_giveup(
            workflow->ndpi_struct, flow_to_process->ndpi_flow,
            &protocol_was_guessed);
        if (protocol_was_guessed != 0)
        {
            printf(
                "[%8llu, %d, %4d][GUESSED] protocol: %s | app protocol: %s | "
                "category: %s\n",
                workflow->packets_captured, 0, flow_to_process->flow_id,
                ndpi_get_proto_name(
                    workflow->ndpi_struct,
                    flow_to_process->guessed_protocol.proto.master_protocol),
                ndpi_get_proto_name(
                    workflow->ndpi_struct,
                    flow_to_process->guessed_protocol.proto.app_protocol),
                ndpi_category_get_name(
                    workflow->ndpi_struct,
                    flow_to_process->guessed_protocol.category));
        }
        else
        {
            printf("[%8llu, %d, %4d][FLOW NOT CLASSIFIED]\n",
                   workflow->packets_captured, 0, flow_to_process->flow_id);
        }
    }

    flow_to_process->detected_l7_protocol = ndpi_detection_process_packet(
        workflow->ndpi_struct, flow_to_process->ndpi_flow,
        ip != NULL ? (uint8_t *)ip : (uint8_t *)ip6, ip_size, time_ms, NULL);

    if (ndpi_is_protocol_detected(flow_to_process->detected_l7_protocol) != 0 &&
        flow_to_process->detection_completed == 0)
    {
        if (flow_to_process->detected_l7_protocol.proto.master_protocol !=
                NDPI_PROTOCOL_UNKNOWN ||
            flow_to_process->detected_l7_protocol.proto.app_protocol !=
                NDPI_PROTOCOL_UNKNOWN)
        {
            flow_to_process->detection_completed = 1;
            workflow->detected_flow_protocols++;

            printf(
                "[%8llu, %d, %4d][DETECTED] protocol: %s | app protocol: %s | "
                "category: %s\n",
                workflow->packets_captured, 0, flow_to_process->flow_id,
                ndpi_get_proto_name(workflow->ndpi_struct,
                                    flow_to_process->detected_l7_protocol.proto
                                        .master_protocol),
                ndpi_get_proto_name(
                    workflow->ndpi_struct,
                    flow_to_process->detected_l7_protocol.proto.app_protocol),
                ndpi_category_get_name(
                    workflow->ndpi_struct,
                    flow_to_process->detected_l7_protocol.category));
        }
    }

    if (flow_to_process->ndpi_flow->num_extra_packets_checked <=
        flow_to_process->ndpi_flow->max_extra_packets_to_check)
    {
        /*
         * Your business logic starts here.
         *
         * This example does print some information about
         * TLS client and server hellos if available.
         *
         * You could also use nDPI's built-in json serialization
         * and send it to a high-level application for further processing.
         *
         * EoE - End of Example
         */

        if (flow_to_process->flow_info_printed == 0)
        {
            char const *const flow_info =
                ndpi_get_flow_info(flow_to_process->ndpi_flow,
                                   &flow_to_process->detected_l7_protocol);
            if (flow_info != NULL)
            {
                printf("[%8llu, %d, %4d] info: %s\n",
                       workflow->packets_captured, 0, flow_to_process->flow_id,
                       flow_info);
                flow_to_process->flow_info_printed = 1;
            }
        }

        if (flow_to_process->detected_l7_protocol.proto.master_protocol ==
                NDPI_PROTOCOL_TLS ||
            flow_to_process->detected_l7_protocol.proto.app_protocol ==
                NDPI_PROTOCOL_TLS)
        {
            if (flow_to_process->tls_client_hello_seen == 0 &&
                flow_to_process->ndpi_flow->protos.tls_quic
                        .client_hello_processed != 0)
            {
                uint8_t unknown_tls_version = 0;
                char buf_ver[16];
                printf(
                    "[%8llu, %d, %4d][TLS-CLIENT-HELLO] version: %s | sni: %s "
                    "| (advertised) ALPNs: %s\n",
                    workflow->packets_captured, 0, flow_to_process->flow_id,
                    ndpi_ssl_version2str(
                        buf_ver, sizeof(buf_ver),
                        flow_to_process->ndpi_flow->protos.tls_quic.ssl_version,
                        &unknown_tls_version),
                    flow_to_process->ndpi_flow->host_server_name,
                    (flow_to_process->ndpi_flow->protos.tls_quic
                                 .advertised_alpns != NULL
                         ? flow_to_process->ndpi_flow->protos.tls_quic
                               .advertised_alpns
                         : "-"));
                flow_to_process->tls_client_hello_seen = 1;
            }
            if (flow_to_process->tls_server_hello_seen == 0 &&
                flow_to_process->ndpi_flow->tls_quic.certificate_processed != 0)
            {
                uint8_t unknown_tls_version = 0;
                char buf_ver[16];
                printf(
                    "[%8llu, %d, %4d][TLS-SERVER-HELLO] version: %s | "
                    "common-name(s): %.*s | "
                    "issuer: %s | subject: %s\n",
                    workflow->packets_captured, 0, flow_to_process->flow_id,
                    ndpi_ssl_version2str(
                        buf_ver, sizeof(buf_ver),
                        flow_to_process->ndpi_flow->protos.tls_quic.ssl_version,
                        &unknown_tls_version),
                    (flow_to_process->ndpi_flow->protos.tls_quic
                                 .server_names_len == 0
                         ? 1
                         : flow_to_process->ndpi_flow->protos.tls_quic
                               .server_names_len),
                    (flow_to_process->ndpi_flow->protos.tls_quic.server_names ==
                             NULL
                         ? "-"
                         : flow_to_process->ndpi_flow->protos.tls_quic
                               .server_names),
                    (flow_to_process->ndpi_flow->protos.tls_quic.issuerDN !=
                             NULL
                         ? flow_to_process->ndpi_flow->protos.tls_quic.issuerDN
                         : "-"),
                    (flow_to_process->ndpi_flow->protos.tls_quic.subjectDN !=
                             NULL
                         ? flow_to_process->ndpi_flow->protos.tls_quic.subjectDN
                         : "-"));
                flow_to_process->tls_server_hello_seen = 1;
            }
        }
    }
}