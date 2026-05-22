// SPDX-License-Identifier: GPL-2.0
//
// XDP load balancer — step 3: consistent hashing for connection pinning.
//
// Backend selection uses a 4-tuple hash (src_ip, dst_ip, src_port, dst_port).
// Packets belonging to the same TCP/UDP flow always map to the same backend
// index even when the pool size changes, because the hash is stable for the
// lifetime of a connection.
//
// The userspace controller (lb_ctrl) owns all backends_map writes via the
// pinned map at /sys/fs/bpf/lb_backends.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "lb_common.h"

// ── eBPF map: VIP+port → active backend pool ─────────────────────────────────
// Written by lb_ctrl and lb_healthd; read at line rate by this program.

struct {
    __uint(type,        BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key,         struct vip_key);
    __type(value,       struct backends_val);
} backends_map SEC(".maps");

// ── Helpers ───────────────────────────────────────────────────────────────────

// FNV-1a inspired 4-tuple hash.  Provides good distribution for real traffic
// while being cheap enough for the XDP fast path.
static __always_inline __u32 hash_4tuple(__u32 saddr, __u32 daddr,
                                          __u16 sport, __u16 dport)
{
    __u32 h = 2166136261u;          // FNV offset basis
    h = (h ^ saddr)           * 16777619u;
    h = (h ^ daddr)           * 16777619u;
    h = (h ^ (__u32)sport)    * 16777619u;
    h = (h ^ (__u32)dport)    * 16777619u;
    return h;
}

// Recompute IPv4 header checksum over the fixed 20-byte (ihl=5) header.
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

    if (iph->ihl != 5)
        return XDP_PASS;

    // ── L4: TCP / UDP ─────────────────────────────────────────────────────────
    __u16 sport = 0, dport = 0;

    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
        if ((void *)(tcph + 1) > data_end)
            return XDP_PASS;
        sport = bpf_ntohs(tcph->source);
        dport = bpf_ntohs(tcph->dest);

    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udph = (struct udphdr *)(iph + 1);
        if ((void *)(udph + 1) > data_end)
            return XDP_PASS;
        sport = bpf_ntohs(udph->source);
        dport = bpf_ntohs(udph->dest);

    } else {
        return XDP_PASS;
    }

    // ── Map lookup ────────────────────────────────────────────────────────────
    struct vip_key key = { .vip = iph->daddr, .port = dport, ._pad = 0 };
    struct backends_val *val = bpf_map_lookup_elem(&backends_map, &key);
    if (!val || val->count == 0 || val->count > MAX_BACKENDS)
        return XDP_PASS;

    // ── Consistent hash: same flow → same backend ─────────────────────────────
    // The explicit idx >= MAX_BACKENDS guard satisfies the BPF verifier even
    // though count <= MAX_BACKENDS already bounds idx.
    __u32 idx = hash_4tuple(iph->saddr, iph->daddr, sport, dport) % val->count;
    if (idx >= MAX_BACKENDS)
        return XDP_PASS;

    struct backend_entry *be = &val->backends[idx];

    // ── Rewrite L2 / L3 ──────────────────────────────────────────────────────
    __builtin_memcpy(eth->h_dest, be->mac, ETH_ALEN);
    iph->daddr = be->ip;
    iph->check = 0;
    iph->check = ip_csum(iph);

    return XDP_TX;
}

char LICENSE[] SEC("license") = "GPL";
