// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

/* Ratelimit incoming TCP connections using XDP */
#define KBUILD_MODNAME "ebpf-ratelimiter"

#include <linux/bpf.h>
#include <netinet/in.h>
#include <stdint.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <iproute2/bpf_elf.h>


/* TCP flags */
#define TCP_FIN  0x01
#define TCP_SYN  0x02
#define TCP_RST  0x04
#define TCP_PSH  0x08
#define TCP_ACK  0x10
#define TCP_URG  0x20
#define TCP_ECE  0x40
#define TCP_CWR  0x80
#define TCP_FLAGS (TCP_FIN|TCP_SYN|TCP_RST|TCP_ACK|TCP_URG|TCP_ECE|TCP_CWR)

#define bpf_printk(fmt, ...)                            \
({                                                      \
        char ____fmt[] = fmt;                           \
        bpf_trace_printk(____fmt, sizeof(____fmt),      \
                         ##__VA_ARGS__);                \
})

#ifndef __section
# define __section(NAME)                  \
	__attribute__((section(NAME), used))
#endif

#define PIN_GLOBAL_NS        2

/* Stores the ratelimit value(per second) */
struct bpf_elf_map rl_config_map __section("maps") = {
	.type           = BPF_MAP_TYPE_ARRAY,
	.size_key       = sizeof(uint32_t),
	.size_value     = sizeof(uint64_t),
	.pinning        = PIN_GLOBAL_NS,
	.max_elem     = 1,
};

/* Maintains the timestamp of a window and the total number of
 * connections received in that window(window = 1 sec interval) */
struct bpf_elf_map SEC("maps") rl_window_map = {
	.type		= BPF_MAP_TYPE_HASH,
	.size_key	= sizeof(uint64_t),
	.size_value	= sizeof(uint64_t),
	.pinning    = PIN_GLOBAL_NS,
	.max_elem	= 100,
};

/* Maintains the total number of connections received(TCP-SYNs)
 * Used only for metrics visibility */
struct bpf_elf_map SEC("maps") rl_recv_count_map = {
	.type		= BPF_MAP_TYPE_HASH,
	.size_key	= sizeof(uint64_t),
	.size_value	= sizeof(uint64_t),
	.pinning    = PIN_GLOBAL_NS,
	.max_elem	= 1
	
};

/* Maintains the total number of connections dropped as the ratelimit is hit
 * Used only for metrics visibility */
struct bpf_elf_map SEC("maps") rl_drop_count_map = {
	.type		= BPF_MAP_TYPE_HASH,
	.size_key	= sizeof(uint64_t),
	.size_value	= sizeof(uint64_t),
	.pinning    = PIN_GLOBAL_NS,
	.max_elem	= 1
};

/* Maintains the ports to be ratelimited */
struct bpf_elf_map SEC("maps") rl_ports_map = {
    .type           = BPF_MAP_TYPE_HASH,
    .size_key       = sizeof(uint16_t),
    .size_value     = sizeof(uint8_t),
	.pinning        = PIN_GLOBAL_NS,
    .max_elem       = 50
};

/* Use atomics or spin locks where naive increments are used depending
 * on the accuracy tests and then do a tradeoff.
 * With 10k connections/sec tests, the error rate is < 3%. */
static __always_inline int __xdp_ratelimit(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;

    /* Check if it is a valid ethernet packet */
    if (data + sizeof(*eth) > data_end)
        return XDP_DROP;

    /* Ignore other than ethernet packets */
    /* TODO: Check if the packet is an IP packet, else ignore. */

    /* Ignore other than IP packets */
    struct iphdr *iph = data + sizeof(struct ethhdr);
    if (iph + 1 > data_end)
        return XDP_PASS;

    /* Ignore other than TCP packets */
    /* TODO: Ignore other than TCP packets */

    /* Check if its valid tcp packet */
    struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
    if (tcph + 1 > data_end)
        return XDP_PASS;
      
    /* TODO: Ignore any TCP packet which doesnt mark start of connection. */

    uint16_t dstport = bpf_ntohs(tcph->dest);

    uint64_t rkey = 0;
    uint64_t *rate;

    /* TODO: Lookup the allowed connection rate from rl_config map and
        store in the rate variable for us to use.*/
    bpf_printk("pass rate: %d\n",*rate);
        
    /* Current time in monotonic clock */
    /* NOTE: A helper function which tells ebpf what time is now? */
    uint64_t tnow = bpf_ktime_get_ns();

    /* Used for second to nanoseconds conversions and vice-versa */
    uint64_t NANO = 1000000000;

    /* Used for converting decimals points to percentages as decimal points
     * are not recommended in the kernel.
     * Ex: 0.3 would be converted as 30 with this multiplication factor to
     * perform the calculations needed. */
    uint64_t MULTIPLIER = 100;

    /* Round off the current time to form the current window key.
     * Ex: ts of the incoming connections from the time 16625000000000 till
     * 166259999999 is rounded off to 166250000000000 to track the incoming
     * connections received in that one second interval. */
    
    uint64_t cw_key = (tnow / NANO)  * NANO;

    /* Previous window is one second before the current window */
    uint64_t pw_key = cw_key - NANO;

    /* Number of incoming connections in the previous window(second) */
    uint64_t *pw_count = bpf_map_lookup_elem(&rl_window_map, &pw_key);

    /* Number of incoming connections in the current window(second) */
    uint32_t *cw_count = bpf_map_lookup_elem(&rl_window_map, &cw_key);

    /* Total number of incoming connections so far */
    uint64_t *in_count = bpf_map_lookup_elem(&rl_recv_count_map, &rkey);

    /* Total number of dropped connections so far */
    uint64_t *drop_count = bpf_map_lookup_elem(&rl_drop_count_map, &rkey);

    /* Just make the verifier happy, it would never be the case in real as
     * these two counters are initialised in the user space. */
    if(!in_count || !drop_count){
      bpf_printk("count null %d\n",rate);
      return XDP_PASS;
    }

    /* Increment the total number of incoming connections counter */
    (*in_count)++;

    if (!cw_count)
    {
        /* TODO:
           This is the first connection in the current window initialize the current window counter.
           Specifically, initialize the rl_window_map with connection window key and init count as 0.
           This time add a flag BPF_NOEXIST to make sure that the key doesn't exist. */

        /* load the cw_count back */
        cw_count = bpf_map_lookup_elem(&rl_window_map, &cw_key);
        /* Just make the verifier happy */
        if (!cw_count)
            return XDP_PASS;
    }
    if (!pw_count)
    {
        /* This is the fresh start of system or there have been no
         * connections in the last second, so make the decision purely based
         * on the incoming connections in the current window. */
        if (*cw_count >= *rate)
        {
            /* Connection count in the current window already exceeded the
             * rate limit so drop this connection. */
            (*drop_count)++;
            bpf_printk("DROPPING CONNECTION: CT  %d\n",*cw_count);
            return XDP_DROP;
        }
        /* Allow otherwise */
        (*cw_count)++;
        bpf_printk("ALLOWING CONNECTION: CT %d\n",*cw_count);
        return XDP_PASS;
    }

    /* Calculate the number of connections accepted in last 1 sec from tnow *
     * considering the connections accepted in previous window and          *
     * current window based on what % of the sliding window(tnow - 1) falls *
     * in previous window and what % of it is in the current window         */
    uint64_t pw_weight = MULTIPLIER -
        (uint64_t)(((tnow - cw_key) * MULTIPLIER) / NANO);

    uint64_t total_count = (uint64_t)((pw_weight * (*pw_count)) +
        (*cw_count) * MULTIPLIER);

    bpf_printk("tot_ct : %d\n", total_count);
    bpf_printk("cw1_ct : %d\n", *cw_count);

    if (total_count > (*rate))
    {
        /* Connection count from tnow to (tnow-1) exceeded the rate limit,
         * so drop this connection. */
        (*drop_count)++;
        bpf_printk("DROPPING CONNECTION: CT  %d\n", *cw_count);
        return XDP_DROP;
    }

    /* Allow otherwise */
    (*cw_count)++;
    bpf_printk("ALLOWING CONNECTION: CT  %d\n",*cw_count);
    return XDP_PASS;
}

SEC("xdp_ratelimiting")
int _xdp_ratelimiting(struct xdp_md *ctx)
{
  bpf_printk("rate_limiting\n");
  return __xdp_ratelimit(ctx);
}

char _license[] SEC("license") = "Dual BSD/GPL";