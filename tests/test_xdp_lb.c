// Userspace unit tests for the XDP load-balancer packet-transformation logic.
//
// These tests compile and run on any POSIX host (Linux or macOS) — no kernel,
// no eBPF toolchain required.  They exercise the same algorithm used in
// src/xdp_lb.c by feeding raw byte buffers through a portable reimplementation
// of the XDP fast path.
//
// Step-3 update: process_packet() now also reads sport and uses hash_4tuple()
// to pick the backend index, matching the kernel program's consistent-hashing
// behaviour exactly.

#include <arpa/inet.h>
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "lb_common.h"
#include "maglev.h"

// ── XDP return codes (mirrors linux/bpf.h) ───────────────────────────────────

#define XDP_PASS  2
#define XDP_TX    3

// ── Minimal Linux network structs (byte-identical to kernel definitions) ─────

#define ETH_ALEN  6
#define ETH_P_IP  0x0800

struct ethhdr {
    uint8_t  h_dest[ETH_ALEN];
    uint8_t  h_source[ETH_ALEN];
    uint16_t h_proto;
} __attribute__((packed));

struct iphdr {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    uint8_t  ihl:4, version:4;
#else
    uint8_t  version:4, ihl:4;
#endif
    uint8_t  tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
} __attribute__((packed));

struct tcphdr {
    uint16_t source;
    uint16_t dest;
    uint32_t seq;
    uint32_t ack_seq;
    uint8_t  doff_res;
    uint8_t  flags;
    uint16_t window;
    uint16_t check;
    uint16_t urg_ptr;
} __attribute__((packed));

struct udphdr {
    uint16_t source;
    uint16_t dest;
    uint16_t len;
    uint16_t check;
} __attribute__((packed));

#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

// ── IP checksum ──────────────────────────────────────────────────────────────

static uint16_t ip_csum(struct iphdr *iph)
{
    uint32_t sum = 0;
    uint16_t *p  = (uint16_t *)iph;
    for (int i = 0; i < 10; i++)
        sum += p[i];
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (uint16_t)~sum;
}

// ── 4-tuple consistent hash (must be byte-for-byte identical to xdp_lb.c) ────

static uint32_t hash_4tuple(uint32_t saddr, uint32_t daddr,
                             uint16_t sport, uint16_t dport)
{
    uint32_t h = 2166136261u;
    h = (h ^ saddr)           * 16777619u;
    h = (h ^ daddr)           * 16777619u;
    h = (h ^ (uint32_t)sport) * 16777619u;
    h = (h ^ (uint32_t)dport) * 16777619u;
    return h;
}

// ── Portable reimplementation of the XDP fast path ───────────────────────────
//
// `val` simulates bpf_map_lookup_elem(&backends_map, &key).
// NULL → no entry → XDP_PASS.

static int process_packet(uint8_t *data, size_t len,
                          const struct backends_val *val)
{
    uint8_t *data_end = data + len;

    struct ethhdr *eth = (struct ethhdr *)data;
    if ((uint8_t *)(eth + 1) > data_end) return XDP_PASS;
    if (ntohs(eth->h_proto) != ETH_P_IP)  return XDP_PASS;

    struct iphdr *iph = (struct iphdr *)(eth + 1);
    if ((uint8_t *)(iph + 1) > data_end) return XDP_PASS;
    if (iph->ihl != 5)                   return XDP_PASS;

    uint16_t sport = 0, dport = 0;

    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
        if ((uint8_t *)(tcph + 1) > data_end) return XDP_PASS;
        sport = ntohs(tcph->source);
        dport = ntohs(tcph->dest);
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udph = (struct udphdr *)(iph + 1);
        if ((uint8_t *)(udph + 1) > data_end) return XDP_PASS;
        sport = ntohs(udph->source);
        dport = ntohs(udph->dest);
    } else {
        return XDP_PASS;
    }

    if (!val || val->count == 0 || val->count > MAX_BACKENDS)
        return XDP_PASS;

    uint32_t slot = hash_4tuple(ntohl(iph->saddr), ntohl(iph->daddr),
                                 sport, dport) % MAGLEV_M;
    if (slot >= MAGLEV_M) return XDP_PASS;
    uint32_t idx = val->maglev_table[slot];
    if (idx >= val->count || idx >= MAX_BACKENDS) return XDP_PASS;

    const struct backend_entry *be = &val->backends[idx];

    memcpy(eth->h_dest, be->mac, ETH_ALEN);
    iph->daddr = be->ip;
    iph->check = 0;
    iph->check = ip_csum(iph);

    return XDP_TX;
}

// ── Packet builders ──────────────────────────────────────────────────────────

static size_t build_tcp(uint8_t *buf, size_t cap,
                        uint32_t saddr, uint32_t daddr,
                        uint16_t sport, uint16_t dport)
{
    assert(cap >= sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr));

    struct ethhdr *eth = (struct ethhdr *)buf;
    memset(eth->h_dest,   0x11, ETH_ALEN);
    memset(eth->h_source, 0x22, ETH_ALEN);
    eth->h_proto = htons(ETH_P_IP);

    struct iphdr *iph = (struct iphdr *)(eth + 1);
    memset(iph, 0, sizeof(*iph));
    iph->version  = 4;
    iph->ihl      = 5;
    iph->tot_len  = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    iph->ttl      = 64;
    iph->protocol = IPPROTO_TCP;
    iph->saddr    = htonl(saddr);
    iph->daddr    = htonl(daddr);
    iph->check    = ip_csum(iph);

    struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
    memset(tcph, 0, sizeof(*tcph));
    tcph->source = htons(sport);
    tcph->dest   = htons(dport);

    return sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr);
}

static size_t build_udp(uint8_t *buf, size_t cap,
                        uint32_t saddr, uint32_t daddr,
                        uint16_t sport, uint16_t dport)
{
    assert(cap >= sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr));

    struct ethhdr *eth = (struct ethhdr *)buf;
    memset(eth->h_dest,   0x11, ETH_ALEN);
    memset(eth->h_source, 0x22, ETH_ALEN);
    eth->h_proto = htons(ETH_P_IP);

    struct iphdr *iph = (struct iphdr *)(eth + 1);
    memset(iph, 0, sizeof(*iph));
    iph->version  = 4;
    iph->ihl      = 5;
    iph->tot_len  = htons(sizeof(struct iphdr) + sizeof(struct udphdr));
    iph->ttl      = 64;
    iph->protocol = IPPROTO_UDP;
    iph->saddr    = htonl(saddr);
    iph->daddr    = htonl(daddr);
    iph->check    = ip_csum(iph);

    struct udphdr *udph = (struct udphdr *)(iph + 1);
    memset(udph, 0, sizeof(*udph));
    udph->source = htons(sport);
    udph->dest   = htons(dport);
    udph->len    = htons(sizeof(struct udphdr));

    return sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);
}

// Convenience wrappers using canonical test addresses.
#define SRC_IP  0xc0a80101u  /* 192.168.1.1   */
#define VIP_IP  0xc0a80164u  /* 192.168.1.100 */

static size_t tcp(uint8_t *buf, size_t cap, uint16_t sport, uint16_t dport)
{ return build_tcp(buf, cap, SRC_IP, VIP_IP, sport, dport); }

static size_t udp(uint8_t *buf, size_t cap, uint16_t sport, uint16_t dport)
{ return build_udp(buf, cap, SRC_IP, VIP_IP, sport, dport); }

// Build a minimal backends_val with up to 4 entries.
static struct backends_val make_pool(__u32 count)
{
    static const __u8 macs[4][ETH_ALEN] = {
        { 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x00 },
        { 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01 },
        { 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02 },
        { 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x03 },
    };
    assert(count <= 4);
    struct backends_val val;
    memset(&val, 0, sizeof(val));
    val.count = count;
    for (__u32 i = 0; i < count; i++) {
        val.backends[i].ip = htonl(0x0a000001u + i); /* 10.0.0.1, 10.0.0.2, … */
        memcpy(val.backends[i].mac, macs[i], ETH_ALEN);
    }
    maglev_build(&val);
    return val;
}

// ── Test helpers ─────────────────────────────────────────────────────────────

static int passed = 0;
static int failed = 0;

#define TEST(name) static void test_##name(void)
#define RUN(name)  do { printf("  %-60s", #name); test_##name(); } while(0)
#define PASS()     do { puts("PASS"); passed++; } while(0)
#define FAIL(msg)  do { puts("FAIL: " msg); failed++; } while(0)
#define CHECK(cond, msg) if (!(cond)) { FAIL(msg); return; }

// ── Map lookup / pass-through tests ──────────────────────────────────────────

TEST(tcp_with_map_entry_returns_xdp_tx) {
    uint8_t buf[256];
    size_t len = tcp(buf, sizeof(buf), 54321, 80);
    struct backends_val val = make_pool(1);
    CHECK(process_packet(buf, len, &val) == XDP_TX, "expected XDP_TX");
    PASS();
}

TEST(udp_with_map_entry_returns_xdp_tx) {
    uint8_t buf[256];
    size_t len = udp(buf, sizeof(buf), 54321, 80);
    struct backends_val val = make_pool(1);
    CHECK(process_packet(buf, len, &val) == XDP_TX, "expected XDP_TX");
    PASS();
}

TEST(no_map_entry_returns_xdp_pass) {
    uint8_t buf[256];
    size_t len = tcp(buf, sizeof(buf), 54321, 80);
    CHECK(process_packet(buf, len, NULL) == XDP_PASS, "expected XDP_PASS");
    PASS();
}

TEST(empty_backend_pool_returns_xdp_pass) {
    uint8_t buf[256];
    size_t len = tcp(buf, sizeof(buf), 54321, 80);
    struct backends_val val = make_pool(0);
    CHECK(process_packet(buf, len, &val) == XDP_PASS, "expected XDP_PASS");
    PASS();
}

TEST(non_ip_ethertype_returns_xdp_pass) {
    uint8_t buf[256] = {0};
    struct ethhdr *eth = (struct ethhdr *)buf;
    eth->h_proto = htons(0x86DD);
    struct backends_val val = make_pool(1);
    CHECK(process_packet(buf, sizeof(buf), &val) == XDP_PASS, "expected XDP_PASS");
    PASS();
}

TEST(truncated_eth_returns_xdp_pass) {
    uint8_t buf[4] = {0};
    struct backends_val val = make_pool(1);
    CHECK(process_packet(buf, sizeof(buf), &val) == XDP_PASS, "expected XDP_PASS");
    PASS();
}

TEST(truncated_ip_returns_xdp_pass) {
    uint8_t buf[sizeof(struct ethhdr) + 4];
    memset(buf, 0, sizeof(buf));
    ((struct ethhdr *)buf)->h_proto = htons(ETH_P_IP);
    struct backends_val val = make_pool(1);
    CHECK(process_packet(buf, sizeof(buf), &val) == XDP_PASS, "expected XDP_PASS");
    PASS();
}

TEST(truncated_tcp_returns_xdp_pass) {
    uint8_t buf[256];
    tcp(buf, sizeof(buf), 1234, 80);
    size_t short_len = sizeof(struct ethhdr) + sizeof(struct iphdr) + 2;
    struct backends_val val = make_pool(1);
    CHECK(process_packet(buf, short_len, &val) == XDP_PASS, "expected XDP_PASS");
    PASS();
}

TEST(ip_options_returns_xdp_pass) {
    uint8_t buf[256];
    size_t len = tcp(buf, sizeof(buf), 1234, 80);
    struct iphdr *iph = (struct iphdr *)(buf + sizeof(struct ethhdr));
    iph->ihl = 6;
    struct backends_val val = make_pool(1);
    CHECK(process_packet(buf, len, &val) == XDP_PASS, "expected XDP_PASS");
    PASS();
}

// ── Rewrite correctness tests ─────────────────────────────────────────────────

TEST(dst_mac_rewritten_from_selected_backend) {
    uint8_t buf[256];
    size_t len = tcp(buf, sizeof(buf), 1234, 80);
    struct backends_val val = make_pool(1);
    process_packet(buf, len, &val);
    struct ethhdr *eth = (struct ethhdr *)buf;
    CHECK(memcmp(eth->h_dest, val.backends[0].mac, ETH_ALEN) == 0,
          "MAC not rewritten");
    PASS();
}

TEST(dst_ip_rewritten_from_selected_backend) {
    uint8_t buf[256];
    size_t len = tcp(buf, sizeof(buf), 1234, 80);
    struct backends_val val = make_pool(1);
    process_packet(buf, len, &val);
    struct iphdr *iph = (struct iphdr *)(buf + sizeof(struct ethhdr));
    CHECK(iph->daddr == val.backends[0].ip, "IP not rewritten");
    PASS();
}

TEST(src_mac_unchanged_after_rewrite) {
    uint8_t buf[256];
    size_t len = tcp(buf, sizeof(buf), 1234, 80);
    struct ethhdr *eth = (struct ethhdr *)buf;
    uint8_t orig[ETH_ALEN];
    memcpy(orig, eth->h_source, ETH_ALEN);
    struct backends_val val = make_pool(1);
    process_packet(buf, len, &val);
    CHECK(memcmp(eth->h_source, orig, ETH_ALEN) == 0, "source MAC changed");
    PASS();
}

TEST(ip_checksum_valid_after_rewrite) {
    uint8_t buf[256];
    size_t len = tcp(buf, sizeof(buf), 1234, 80);
    struct backends_val val = make_pool(1);
    process_packet(buf, len, &val);
    struct iphdr *iph = (struct iphdr *)(buf + sizeof(struct ethhdr));
    uint32_t sum = 0;
    uint16_t *p = (uint16_t *)iph;
    for (int i = 0; i < 10; i++) sum += p[i];
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    CHECK((uint16_t)sum == 0xffff, "IP checksum invalid");
    PASS();
}

// ── Consistent hashing tests ──────────────────────────────────────────────────

TEST(same_flow_always_picks_same_backend) {
    // Two packets with identical 4-tuples must land on the same backend.
    uint8_t buf1[256], buf2[256];
    size_t  len = tcp(buf1, sizeof(buf1), 54321, 80);
    tcp(buf2, sizeof(buf2), 54321, 80);

    struct backends_val val = make_pool(4);
    process_packet(buf1, len, &val);
    process_packet(buf2, len, &val);

    struct ethhdr *e1 = (struct ethhdr *)buf1;
    struct ethhdr *e2 = (struct ethhdr *)buf2;
    CHECK(memcmp(e1->h_dest, e2->h_dest, ETH_ALEN) == 0,
          "same flow routed to different backends");
    PASS();
}

TEST(single_backend_pool_always_index_0) {
    // hash % 1 == 0 always.
    uint8_t buf[256];
    struct backends_val val = make_pool(1);

    // Try several different src ports.
    uint16_t ports[] = { 1000, 2000, 30000, 54321, 65535 };
    for (int i = 0; i < 5; i++) {
        size_t len = tcp(buf, sizeof(buf), ports[i], 80);
        memset(((struct ethhdr *)buf)->h_dest, 0xff, ETH_ALEN);
        process_packet(buf, len, &val);
        CHECK(memcmp(((struct ethhdr *)buf)->h_dest,
                     val.backends[0].mac, ETH_ALEN) == 0,
              "single backend: did not pick index 0");
    }
    PASS();
}

TEST(hash_picks_computed_index) {
    // Compute the expected index via the Maglev table and verify the packet
    // is rewritten to the matching backend.
    const uint16_t sport = 12345, dport = 443;
    struct backends_val val = make_pool(4);

    uint32_t slot = hash_4tuple(SRC_IP, VIP_IP, sport, dport) % MAGLEV_M;
    uint32_t expected_idx = val.maglev_table[slot];

    uint8_t buf[256];
    size_t len = tcp(buf, sizeof(buf), sport, dport);
    process_packet(buf, len, &val);

    struct ethhdr *eth = (struct ethhdr *)buf;
    CHECK(memcmp(eth->h_dest, val.backends[expected_idx].mac, ETH_ALEN) == 0,
          "backend chosen does not match maglev table");
    PASS();
}

TEST(different_src_port_can_pick_different_backend) {
    // With 4 backends, find two src ports that resolve to different backends
    // via the Maglev table — proving the hash distributes across the pool.
    struct backends_val val = make_pool(4);

    uint32_t slot0    = hash_4tuple(SRC_IP, VIP_IP, 1000, 80) % MAGLEV_M;
    uint32_t first_idx = val.maglev_table[slot0];

    int found_different = 0;
    for (uint16_t p = 1001; p < 2000; p++) {
        uint32_t slot = hash_4tuple(SRC_IP, VIP_IP, p, 80) % MAGLEV_M;
        if (val.maglev_table[slot] != first_idx) { found_different = 1; break; }
    }
    CHECK(found_different, "all src ports mapped to the same backend");
    PASS();
}

TEST(udp_consistent_hash_matches_tcp_formula) {
    // The hash function doesn't care about L4 protocol; verify UDP uses the
    // same Maglev table lookup as TCP.
    const uint16_t sport = 9999, dport = 5353;
    struct backends_val val = make_pool(3);

    uint32_t slot = hash_4tuple(SRC_IP, VIP_IP, sport, dport) % MAGLEV_M;
    uint32_t expected_idx = val.maglev_table[slot];

    uint8_t buf[256];
    size_t len = udp(buf, sizeof(buf), sport, dport);
    process_packet(buf, len, &val);

    struct ethhdr *eth = (struct ethhdr *)buf;
    CHECK(memcmp(eth->h_dest, val.backends[expected_idx].mac, ETH_ALEN) == 0,
          "UDP backend does not match maglev table");
    PASS();
}

// ── Maglev table property tests ───────────────────────────────────────────────

TEST(maglev_even_distribution) {
    // Each backend should own approximately MAGLEV_M / count slots.
    struct backends_val val = make_pool(4);
    uint32_t counts[4] = {0, 0, 0, 0};
    for (int s = 0; s < MAGLEV_M; s++)
        counts[val.maglev_table[s]]++;

    uint32_t expected = MAGLEV_M / 4;   // ~62
    for (int i = 0; i < 4; i++) {
        // Allow ±25% slack.
        CHECK(counts[i] >= expected * 3 / 4, "backend underrepresented in table");
        CHECK(counts[i] <= expected * 5 / 4 + 1, "backend overrepresented in table");
    }
    PASS();
}

TEST(maglev_minimal_disruption_on_remove) {
    // Remove the last backend from a 4-backend pool and verify that only
    // ~1/4 of table slots change — not the ~3/4 that modulo hashing would cause.
    struct backends_val full    = make_pool(4);
    struct backends_val reduced = make_pool(3);  // same first 3 backends

    uint32_t changed = 0;
    for (int s = 0; s < MAGLEV_M; s++) {
        if (full.maglev_table[s] != reduced.maglev_table[s])
            changed++;
    }

    // Ideal: ~MAGLEV_M/4 ≈ 63 slots change.  Allow 2× slack in both directions.
    uint32_t expected = MAGLEV_M / 4;
    CHECK(changed >= expected / 2, "suspiciously few slots changed");
    CHECK(changed <= expected * 2, "too many slots changed — not minimal disruption");
    PASS();
}

// ── Checksum sanity ───────────────────────────────────────────────────────────

TEST(checksum_correct_for_known_header) {
    struct iphdr iph = {0};
    iph.version  = 4;
    iph.ihl      = 5;
    iph.ttl      = 64;
    iph.protocol = IPPROTO_TCP;
    iph.saddr    = htonl(SRC_IP);
    iph.daddr    = htonl(0x0a000001u);
    iph.check    = ip_csum(&iph);

    uint32_t sum = 0;
    uint16_t *p = (uint16_t *)&iph;
    for (int i = 0; i < 10; i++) sum += p[i];
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    CHECK((uint16_t)sum == 0xffff, "ip_csum() produced wrong value");
    PASS();
}

// ── Main ─────────────────────────────────────────────────────────────────────

int main(void)
{
    printf("xdp_lb tests (step 5: maglev consistent hashing)\n\n");

    printf("map / pass-through:\n");
    RUN(tcp_with_map_entry_returns_xdp_tx);
    RUN(udp_with_map_entry_returns_xdp_tx);
    RUN(no_map_entry_returns_xdp_pass);
    RUN(empty_backend_pool_returns_xdp_pass);
    RUN(non_ip_ethertype_returns_xdp_pass);
    RUN(truncated_eth_returns_xdp_pass);
    RUN(truncated_ip_returns_xdp_pass);
    RUN(truncated_tcp_returns_xdp_pass);
    RUN(ip_options_returns_xdp_pass);

    printf("\nrewrite correctness:\n");
    RUN(dst_mac_rewritten_from_selected_backend);
    RUN(dst_ip_rewritten_from_selected_backend);
    RUN(src_mac_unchanged_after_rewrite);
    RUN(ip_checksum_valid_after_rewrite);

    printf("\nconsistent hashing:\n");
    RUN(same_flow_always_picks_same_backend);
    RUN(single_backend_pool_always_index_0);
    RUN(hash_picks_computed_index);
    RUN(different_src_port_can_pick_different_backend);
    RUN(udp_consistent_hash_matches_tcp_formula);

    printf("\nmaglev table properties:\n");
    RUN(maglev_even_distribution);
    RUN(maglev_minimal_disruption_on_remove);

    printf("\nchecksum:\n");
    RUN(checksum_correct_for_known_header);

    printf("\n%d passed, %d failed\n", passed, failed);
    return failed > 0 ? 1 : 0;
}
