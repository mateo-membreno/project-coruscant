// Userspace unit tests for the XDP load-balancer packet-transformation logic.
//
// These tests compile and run on any POSIX host (Linux or macOS) — no kernel,
// no eBPF toolchain required. They exercise the same algorithm that lives in
// src/xdp_lb.c using raw byte buffers and standard POSIX network headers.

#include <arpa/inet.h>
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

// ── Shim: constants that normally come from the BPF program ─────────────────

#define TARGET_PORT  80
#define BACKEND_IP   0x0a000002u   /* 10.0.0.2, host byte order */
#define BACKEND_MAC  { 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff }

// XDP return codes (mirrors linux/bpf.h)
#define XDP_PASS  2
#define XDP_TX    3

// ── Minimal Linux network structs (byte-identical to kernel definitions) ─────

#define ETH_ALEN   6
#define ETH_P_IP   0x0800

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

// ── IP checksum (same algorithm as in xdp_lb.c) ─────────────────────────────

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

// ── The packet-processing function under test ─────────────────────────────────
//
// This is a faithful userspace translation of the SEC("xdp") xdp_lb() function
// in src/xdp_lb.c. Keep the two in sync manually when the BPF program changes.

static int process_packet(uint8_t *data, size_t len)
{
    uint8_t *data_end = data + len;

    struct ethhdr *eth = (struct ethhdr *)data;
    if ((uint8_t *)(eth + 1) > data_end) return XDP_PASS;
    if (ntohs(eth->h_proto) != ETH_P_IP)  return XDP_PASS;

    struct iphdr *iph = (struct iphdr *)(eth + 1);
    if ((uint8_t *)(iph + 1) > data_end) return XDP_PASS;
    if (iph->ihl != 5)                   return XDP_PASS;

    uint16_t dport = 0;

    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
        if ((uint8_t *)(tcph + 1) > data_end) return XDP_PASS;
        dport = ntohs(tcph->dest);

    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udph = (struct udphdr *)(iph + 1);
        if ((uint8_t *)(udph + 1) > data_end) return XDP_PASS;
        dport = ntohs(udph->dest);

    } else {
        return XDP_PASS;
    }

    if (dport != TARGET_PORT) return XDP_PASS;

    static const uint8_t backend_mac[ETH_ALEN] = BACKEND_MAC;
    memcpy(eth->h_dest, backend_mac, ETH_ALEN);

    iph->daddr = htonl(BACKEND_IP);
    iph->check  = 0;
    iph->check  = ip_csum(iph);

    return XDP_TX;
}

// ── Packet builders ──────────────────────────────────────────────────────────

static size_t build_tcp(uint8_t *buf, size_t cap,
                        uint16_t src_port, uint16_t dst_port)
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
    iph->saddr    = htonl(0xc0a80101);  /* 192.168.1.1 */
    iph->daddr    = htonl(0xc0a80164);  /* 192.168.1.100 (VIP) */
    iph->check    = ip_csum(iph);

    struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
    memset(tcph, 0, sizeof(*tcph));
    tcph->source = htons(src_port);
    tcph->dest   = htons(dst_port);

    return sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr);
}

static size_t build_udp(uint8_t *buf, size_t cap,
                        uint16_t src_port, uint16_t dst_port)
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
    iph->saddr    = htonl(0xc0a80101);
    iph->daddr    = htonl(0xc0a80164);
    iph->check    = ip_csum(iph);

    struct udphdr *udph = (struct udphdr *)(iph + 1);
    memset(udph, 0, sizeof(*udph));
    udph->source = htons(src_port);
    udph->dest   = htons(dst_port);
    udph->len    = htons(sizeof(struct udphdr));

    return sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);
}

// ── Test helpers ─────────────────────────────────────────────────────────────

static int passed = 0;
static int failed = 0;

#define TEST(name) static void test_##name(void)
#define RUN(name)  do { printf("  %-50s", #name); test_##name(); } while(0)
#define PASS()     do { puts("PASS"); passed++; } while(0)
#define FAIL(msg)  do { puts("FAIL: " msg); failed++; } while(0)
#define CHECK(cond, msg) if (!(cond)) { FAIL(msg); return; }

// ── Tests ────────────────────────────────────────────────────────────────────

TEST(tcp_on_target_port_returns_xdp_tx) {
    uint8_t buf[256];
    size_t len = build_tcp(buf, sizeof(buf), 54321, TARGET_PORT);
    CHECK(process_packet(buf, len) == XDP_TX, "expected XDP_TX");
    PASS();
}

TEST(udp_on_target_port_returns_xdp_tx) {
    uint8_t buf[256];
    size_t len = build_udp(buf, sizeof(buf), 54321, TARGET_PORT);
    CHECK(process_packet(buf, len) == XDP_TX, "expected XDP_TX");
    PASS();
}

TEST(tcp_on_wrong_port_returns_xdp_pass) {
    uint8_t buf[256];
    size_t len = build_tcp(buf, sizeof(buf), 54321, 8080);
    CHECK(process_packet(buf, len) == XDP_PASS, "expected XDP_PASS");
    PASS();
}

TEST(udp_on_wrong_port_returns_xdp_pass) {
    uint8_t buf[256];
    size_t len = build_udp(buf, sizeof(buf), 54321, 443);
    CHECK(process_packet(buf, len) == XDP_PASS, "expected XDP_PASS");
    PASS();
}

TEST(non_ip_ethertype_returns_xdp_pass) {
    uint8_t buf[256] = {0};
    struct ethhdr *eth = (struct ethhdr *)buf;
    eth->h_proto = htons(0x86DD);  /* IPv6 */
    CHECK(process_packet(buf, sizeof(buf)) == XDP_PASS, "expected XDP_PASS");
    PASS();
}

TEST(truncated_eth_header_returns_xdp_pass) {
    uint8_t buf[4] = {0};  /* shorter than sizeof(ethhdr) */
    CHECK(process_packet(buf, sizeof(buf)) == XDP_PASS, "expected XDP_PASS");
    PASS();
}

TEST(truncated_ip_header_returns_xdp_pass) {
    uint8_t buf[sizeof(struct ethhdr) + 4];
    memset(buf, 0, sizeof(buf));
    struct ethhdr *eth = (struct ethhdr *)buf;
    eth->h_proto = htons(ETH_P_IP);
    CHECK(process_packet(buf, sizeof(buf)) == XDP_PASS, "expected XDP_PASS");
    PASS();
}

TEST(truncated_tcp_header_returns_xdp_pass) {
    uint8_t buf[256];
    build_tcp(buf, sizeof(buf), 1234, TARGET_PORT);
    // Lie about packet length so tcphdr appears truncated to process_packet
    size_t short_len = sizeof(struct ethhdr) + sizeof(struct iphdr) + 2;
    CHECK(process_packet(buf, short_len) == XDP_PASS, "expected XDP_PASS");
    PASS();
}

TEST(ip_options_present_returns_xdp_pass) {
    uint8_t buf[256];
    size_t len = build_tcp(buf, sizeof(buf), 1234, TARGET_PORT);
    struct iphdr *iph = (struct iphdr *)(buf + sizeof(struct ethhdr));
    iph->ihl = 6;  /* IP options present */
    CHECK(process_packet(buf, len) == XDP_PASS, "expected XDP_PASS");
    PASS();
}

TEST(dst_mac_rewritten_to_backend) {
    uint8_t buf[256];
    const uint8_t expected[ETH_ALEN] = BACKEND_MAC;
    size_t len = build_tcp(buf, sizeof(buf), 1234, TARGET_PORT);
    process_packet(buf, len);
    struct ethhdr *eth = (struct ethhdr *)buf;
    CHECK(memcmp(eth->h_dest, expected, ETH_ALEN) == 0, "MAC not rewritten");
    PASS();
}

TEST(dst_ip_rewritten_to_backend) {
    uint8_t buf[256];
    size_t len = build_tcp(buf, sizeof(buf), 1234, TARGET_PORT);
    process_packet(buf, len);
    struct iphdr *iph = (struct iphdr *)(buf + sizeof(struct ethhdr));
    CHECK(ntohl(iph->daddr) == BACKEND_IP, "IP not rewritten");
    PASS();
}

TEST(src_mac_unchanged_after_rewrite) {
    uint8_t buf[256];
    size_t len = build_tcp(buf, sizeof(buf), 1234, TARGET_PORT);
    struct ethhdr *eth = (struct ethhdr *)buf;
    uint8_t orig_src[ETH_ALEN];
    memcpy(orig_src, eth->h_source, ETH_ALEN);
    process_packet(buf, len);
    CHECK(memcmp(eth->h_source, orig_src, ETH_ALEN) == 0, "source MAC was changed");
    PASS();
}

TEST(ip_checksum_valid_after_rewrite) {
    uint8_t buf[256];
    size_t len = build_tcp(buf, sizeof(buf), 1234, TARGET_PORT);
    process_packet(buf, len);
    struct iphdr *iph = (struct iphdr *)(buf + sizeof(struct ethhdr));
    // A valid checksum means re-summing all header words (including check) == 0xffff
    uint32_t sum = 0;
    uint16_t *p = (uint16_t *)iph;
    for (int i = 0; i < 10; i++) sum += p[i];
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    CHECK((uint16_t)sum == 0xffff, "IP checksum invalid after rewrite");
    PASS();
}

TEST(checksum_correct_for_known_header) {
    // Build a header with known fields and verify ip_csum produces the right value.
    struct iphdr iph = {0};
    iph.version  = 4;
    iph.ihl      = 5;
    iph.ttl      = 64;
    iph.protocol = IPPROTO_TCP;
    iph.saddr    = htonl(0xc0a80101);   /* 192.168.1.1 */
    iph.daddr    = htonl(BACKEND_IP);
    uint16_t csum = ip_csum(&iph);
    iph.check = csum;

    // Re-sum all words — must fold to 0xffff for a valid header
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
    printf("xdp_lb tests\n\n");

    RUN(tcp_on_target_port_returns_xdp_tx);
    RUN(udp_on_target_port_returns_xdp_tx);
    RUN(tcp_on_wrong_port_returns_xdp_pass);
    RUN(udp_on_wrong_port_returns_xdp_pass);
    RUN(non_ip_ethertype_returns_xdp_pass);
    RUN(truncated_eth_header_returns_xdp_pass);
    RUN(truncated_ip_header_returns_xdp_pass);
    RUN(truncated_tcp_header_returns_xdp_pass);
    RUN(ip_options_present_returns_xdp_pass);
    RUN(dst_mac_rewritten_to_backend);
    RUN(dst_ip_rewritten_to_backend);
    RUN(src_mac_unchanged_after_rewrite);
    RUN(ip_checksum_valid_after_rewrite);
    RUN(checksum_correct_for_known_header);

    printf("\n%d passed, %d failed\n", passed, failed);
    return failed > 0 ? 1 : 0;
}
