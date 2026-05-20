// SPDX-License-Identifier: GPL-2.0
//
//
// Intercepts packets destined for TARGET_PORT and rewrites their L2/L3
// destination to a single hardcoded backend, then returns XDP_TX so the
// NIC sends the modified packet back out the same interface.
//
// Change TARGET_PORT, BACKEND_IP, and BACKEND_MAC before loading.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// ── Hardcoded configuration ──────────────────────────────────────────────────
// update to host machines addresses.
#define TARGET_PORT  80            
#define BACKEND_IP   0x0a000002u   

#define BACKEND_MAC_0 0xaa
#define BACKEND_MAC_1 0xbb
#define BACKEND_MAC_2 0xcc
#define BACKEND_MAC_3 0xdd
#define BACKEND_MAC_4 0xee
#define BACKEND_MAC_5 0xff

// ── Helpers ───────────────────────────────────────────────────────────────────

// Recompute the IPv4 header checksum over a fixed 20-byte (ihl=5) header.
// We enforce ihl==5 before calling so the #pragma unroll over 10 u16 words
// is safe for the BPF verifier.
static __always_inline __u16 ip_csum(struct iphdr *iph)
{
    __u32 sum = 0;
    __u16 *p  = (__u16 *)iph;

    #pragma unroll
    for (int i = 0; i < 10; i++)
        sum += p[i];

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (__u16)~sum;
}

// ── XDP program ───────────────────────────────────────────────────────────────

SEC("xdp")
int xdp_lb(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // ── L2: Ethernet ─────────────────────────────────────────────────────────
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // ── L3: IPv4 ─────────────────────────────────────────────────────────────
    struct iphdr *iph = (struct iphdr *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    // Skip IP options; only handle the standard 20-byte header.
    if (iph->ihl != 5)
        return XDP_PASS;

    // ── L4: TCP / UDP ─────────────────────────────────────────────────────────
    __u16 dport = 0;

    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
        if ((void *)(tcph + 1) > data_end)
            return XDP_PASS;
        dport = bpf_ntohs(tcph->dest);

    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udph = (struct udphdr *)(iph + 1);
        if ((void *)(udph + 1) > data_end)
            return XDP_PASS;
        dport = bpf_ntohs(udph->dest);

    } else {
        return XDP_PASS;
    }

    if (dport != TARGET_PORT)
        return XDP_PASS;

    // ── Rewrite ───────────────────────────────────────────────────────────────

    // L2: overwrite destination MAC with the backend's MAC
    eth->h_dest[0] = BACKEND_MAC_0;
    eth->h_dest[1] = BACKEND_MAC_1;
    eth->h_dest[2] = BACKEND_MAC_2;
    eth->h_dest[3] = BACKEND_MAC_3;
    eth->h_dest[4] = BACKEND_MAC_4;
    eth->h_dest[5] = BACKEND_MAC_5;

    // L3: overwrite destination IP, then recompute checksum from scratch
    iph->daddr = bpf_htonl(BACKEND_IP);
    iph->check  = 0;
    iph->check  = ip_csum(iph);

    // Send the modified packet back out the ingress interface
    return XDP_TX;
}

char LICENSE[] SEC("license") = "GPL";
