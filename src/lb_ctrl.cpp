// Userspace controller for the XDP load balancer.
//
// Commands:
//   lb_ctrl attach <iface> [obj]           load xdp_lb.o, create+pin all maps
//   lb_ctrl detach <iface>                  remove XDP program, unpin maps
//   lb_ctrl setlbip <ip>                   set LB source IP for DSR IP-in-IP tunnels
//   lb_ctrl add <vip> <port> <ip> <mac>    add backend to both active + config maps
//   lb_ctrl del <vip> <port>               remove VIP entry from both maps
//   lb_ctrl list                            print active VIPs and their backends
//
// Three pinned maps are maintained:
//   MAP_PIN_PATH    — backends_map: active backends read by the XDP program
//   CONFIG_PIN_PATH — config_map:   full configured set, used by lb_healthd
//                                   to restore backends after they recover
//   LBIP_PIN_PATH   — lbip_map:     single-entry array holding the LB's own IP,
//                                   used as the outer IP-in-IP source address
//
// lb_healthd reads config_map as the source of truth and writes backends_map
// based on health probe results.

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_link.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "lb_common.h"

static constexpr const char *MAP_PIN_PATH    = "/sys/fs/bpf/lb_backends";
static constexpr const char *CONFIG_PIN_PATH = "/sys/fs/bpf/lb_config";
static constexpr const char *LBIP_PIN_PATH   = "/sys/fs/bpf/lb_lbip";
static constexpr const char *DEFAULT_OBJ     = "src/xdp_lb.o";
static constexpr __u32       XDP_FLAGS       = XDP_FLAGS_SKB_MODE;

// ── Helpers ───────────────────────────────────────────────────────────────────

static bool parse_mac(const char *s, __u8 mac[6])
{
    unsigned v[6];
    if (sscanf(s, "%x:%x:%x:%x:%x:%x",         // NOLINT
               &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]) != 6)
        return false;
    for (int i = 0; i < 6; i++)
        mac[i] = static_cast<__u8>(v[i]);
    return true;
}

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage:\n"
        "  %s attach <iface> [bpf_obj]            load XDP program (default: %s)\n"
        "  %s detach <iface>                       detach XDP program\n"
        "  %s setlbip <ip>                         set LB source IP for DSR tunnels\n"
        "  %s add <vip> <port> <backend_ip> <mac>  add backend\n"
        "  %s del <vip> <port>                     remove VIP entry\n"
        "  %s list                                 show all active VIP entries\n",
        prog, DEFAULT_OBJ, prog, prog, prog, prog, prog);
}

// Write val to map_fd at key, logging errors with label.
static bool map_write(int map_fd, const vip_key *key,
                      const backends_val *val, const char *label)
{
    if (bpf_map_update_elem(map_fd, key, val, BPF_ANY)) {
        fprintf(stderr, "bpf_map_update_elem(%s): %s\n", label, strerror(errno));
        return false;
    }
    return true;
}

static bool map_delete(int map_fd, const vip_key *key, const char *label)
{
    if (bpf_map_delete_elem(map_fd, key)) {
        fprintf(stderr, "bpf_map_delete_elem(%s): %s\n", label, strerror(errno));
        return false;
    }
    return true;
}

// ── LbController: thin RAII wrapper around a libbpf bpf_object ───────────────

class LbController {
public:
    explicit LbController(const char *obj_path) : obj_(nullptr)
    {
        obj_ = bpf_object__open_file(obj_path, nullptr);
        if (libbpf_get_error(obj_)) {
            fprintf(stderr, "bpf_object__open_file(%s): %s\n",
                    obj_path, strerror(errno));
            obj_ = nullptr;
        }
    }

    ~LbController() { if (obj_) bpf_object__close(obj_); }

    bool load()
    {
        if (!obj_) return false;
        if (bpf_object__load(obj_)) {
            fprintf(stderr, "bpf_object__load: %s\n", strerror(errno));
            return false;
        }
        return true;
    }

    bool attach(const char *prog_name, int ifindex)
    {
        struct bpf_program *prog =
            bpf_object__find_program_by_name(obj_, prog_name);
        if (!prog) {
            fprintf(stderr, "program '%s' not found in object\n", prog_name);
            return false;
        }

        if (bpf_xdp_attach(ifindex, bpf_program__fd(prog), XDP_FLAGS, nullptr)) {
            fprintf(stderr, "bpf_xdp_attach: %s\n", strerror(errno));
            return false;
        }

        // Pin the XDP-facing active map.
        struct bpf_map *active_map =
            bpf_object__find_map_by_name(obj_, "backends_map");
        if (!active_map) {
            fprintf(stderr, "map 'backends_map' not found in object\n");
            bpf_xdp_detach(ifindex, XDP_FLAGS, nullptr);
            return false;
        }
        remove(MAP_PIN_PATH);
        if (bpf_obj_pin(bpf_map__fd(active_map), MAP_PIN_PATH)) {
            fprintf(stderr, "bpf_obj_pin(backends_map → %s): %s\n",
                    MAP_PIN_PATH, strerror(errno));
            bpf_xdp_detach(ifindex, XDP_FLAGS, nullptr);
            return false;
        }

        // Pin the DSR LB-IP map.
        struct bpf_map *lbip_map =
            bpf_object__find_map_by_name(obj_, "lbip_map");
        if (!lbip_map) {
            fprintf(stderr, "map 'lbip_map' not found in object\n");
            bpf_xdp_detach(ifindex, XDP_FLAGS, nullptr);
            remove(MAP_PIN_PATH);
            return false;
        }
        remove(LBIP_PIN_PATH);
        if (bpf_obj_pin(bpf_map__fd(lbip_map), LBIP_PIN_PATH)) {
            fprintf(stderr, "bpf_obj_pin(lbip_map → %s): %s\n",
                    LBIP_PIN_PATH, strerror(errno));
            bpf_xdp_detach(ifindex, XDP_FLAGS, nullptr);
            remove(MAP_PIN_PATH);
            return false;
        }

        // Create and pin the config map (userspace-only; not in the BPF object).
        // lb_healthd reads this as the authoritative backend list.
        remove(CONFIG_PIN_PATH);
        LIBBPF_OPTS(bpf_map_create_opts, copts);
        int cfg_fd = bpf_map_create(BPF_MAP_TYPE_HASH, "config_map",
                                    sizeof(vip_key), sizeof(backends_val),
                                    256, &copts);
        if (cfg_fd < 0) {
            fprintf(stderr, "bpf_map_create(config_map): %s\n", strerror(errno));
            bpf_xdp_detach(ifindex, XDP_FLAGS, nullptr);
            remove(MAP_PIN_PATH);
            return false;
        }
        if (bpf_obj_pin(cfg_fd, CONFIG_PIN_PATH)) {
            fprintf(stderr, "bpf_obj_pin(config_map → %s): %s\n",
                    CONFIG_PIN_PATH, strerror(errno));
            bpf_xdp_detach(ifindex, XDP_FLAGS, nullptr);
            remove(MAP_PIN_PATH);
            return false;
        }

        return true;
    }

    bool valid() const { return obj_ != nullptr; }

private:
    struct bpf_object *obj_;
};

// ── Command implementations ───────────────────────────────────────────────────

static int cmd_attach(const char *iface, const char *obj_path)
{
    int ifindex = static_cast<int>(if_nametoindex(iface));
    if (!ifindex) {
        fprintf(stderr, "interface '%s' not found\n", iface);
        return 1;
    }
    LbController ctrl(obj_path);
    if (!ctrl.valid() || !ctrl.load()) return 1;
    if (!ctrl.attach("xdp_lb", ifindex)) return 1;

    printf("xdp_lb attached to %s\n", iface);
    printf("  active map : %s\n", MAP_PIN_PATH);
    printf("  config map : %s\n", CONFIG_PIN_PATH);
    printf("  lbip map   : %s  (run 'setlbip' to configure)\n", LBIP_PIN_PATH);
    return 0;
}

static int cmd_detach(const char *iface)
{
    int ifindex = static_cast<int>(if_nametoindex(iface));
    if (!ifindex) {
        fprintf(stderr, "interface '%s' not found\n", iface);
        return 1;
    }
    if (bpf_xdp_detach(ifindex, XDP_FLAGS, nullptr)) {
        fprintf(stderr, "bpf_xdp_detach: %s\n", strerror(errno));
        return 1;
    }
    remove(MAP_PIN_PATH);
    remove(CONFIG_PIN_PATH);
    remove(LBIP_PIN_PATH);
    printf("xdp_lb detached from %s\n", iface);
    return 0;
}

static int cmd_add(const char *vip_s, const char *port_s,
                   const char *ip_s,  const char *mac_s)
{
    int active_fd = bpf_obj_get(MAP_PIN_PATH);
    int config_fd = bpf_obj_get(CONFIG_PIN_PATH);
    if (active_fd < 0 || config_fd < 0) {
        fprintf(stderr, "cannot open maps (run 'attach' first)\n");
        return 1;
    }

    vip_key key{};
    if (!inet_pton(AF_INET, vip_s, &key.vip)) {
        fprintf(stderr, "invalid VIP: %s\n", vip_s);
        return 1;
    }
    key.port = static_cast<__u16>(atoi(port_s));

    // Load existing pool from config_map as the source of truth.
    backends_val val{};
    bpf_map_lookup_elem(config_fd, &key, &val);

    if (val.count >= MAX_BACKENDS) {
        fprintf(stderr, "backend pool full (%d entries)\n", MAX_BACKENDS);
        return 1;
    }

    backend_entry *be = &val.backends[val.count];
    if (!inet_pton(AF_INET, ip_s, &be->ip)) {
        fprintf(stderr, "invalid backend IP: %s\n", ip_s);
        return 1;
    }
    if (!parse_mac(mac_s, be->mac)) {
        fprintf(stderr, "invalid MAC '%s' (expected aa:bb:cc:dd:ee:ff)\n", mac_s);
        return 1;
    }
    val.count++;

    if (!map_write(config_fd, &key, &val, "config_map")) return 1;
    if (!map_write(active_fd, &key, &val, "backends_map")) return 1;

    printf("added backend %s (%s) → VIP %s:%s  [pool size %u]\n",
           ip_s, mac_s, vip_s, port_s, val.count);
    return 0;
}

static int cmd_del(const char *vip_s, const char *port_s)
{
    int active_fd = bpf_obj_get(MAP_PIN_PATH);
    int config_fd = bpf_obj_get(CONFIG_PIN_PATH);
    if (active_fd < 0 || config_fd < 0) {
        fprintf(stderr, "cannot open maps (run 'attach' first)\n");
        return 1;
    }

    vip_key key{};
    if (!inet_pton(AF_INET, vip_s, &key.vip)) {
        fprintf(stderr, "invalid VIP: %s\n", vip_s);
        return 1;
    }
    key.port = static_cast<__u16>(atoi(port_s));

    map_delete(config_fd, &key, "config_map");
    map_delete(active_fd,  &key, "backends_map");
    printf("removed VIP %s:%s\n", vip_s, port_s);
    return 0;
}

static int cmd_setlbip(const char *ip_s)
{
    int fd = bpf_obj_get(LBIP_PIN_PATH);
    if (fd < 0) {
        fprintf(stderr, "cannot open %s (run 'attach' first)\n", LBIP_PIN_PATH);
        return 1;
    }
    __u32 key = 0, ip = 0;
    if (!inet_pton(AF_INET, ip_s, &ip)) {
        fprintf(stderr, "invalid IP: %s\n", ip_s);
        return 1;
    }
    if (bpf_map_update_elem(fd, &key, &ip, BPF_ANY)) {
        fprintf(stderr, "bpf_map_update_elem(lbip_map): %s\n", strerror(errno));
        return 1;
    }
    printf("LB source IP set to %s\n", ip_s);
    return 0;
}

static int cmd_list()
{
    int active_fd = bpf_obj_get(MAP_PIN_PATH);
    if (active_fd < 0) {
        fprintf(stderr, "cannot open %s: %s\n", MAP_PIN_PATH, strerror(errno));
        return 1;
    }

    vip_key      key{}, next_key{};
    backends_val val{};
    char         vip_s[INET_ADDRSTRLEN], ip_s[INET_ADDRSTRLEN];
    bool         first = true;
    int          count = 0;

    while (!bpf_map_get_next_key(active_fd, first ? nullptr : &key, &next_key)) {
        first = false;
        key   = next_key;
        if (bpf_map_lookup_elem(active_fd, &key, &val)) continue;

        inet_ntop(AF_INET, &key.vip, vip_s, sizeof(vip_s));
        printf("VIP %s:%u  (%u active backend(s))\n", vip_s, key.port, val.count);
        for (__u32 i = 0; i < val.count; i++) {
            inet_ntop(AF_INET, &val.backends[i].ip, ip_s, sizeof(ip_s));
            const __u8 *m = val.backends[i].mac;
            printf("  [%u] %s  %02x:%02x:%02x:%02x:%02x:%02x\n",
                   i, ip_s, m[0], m[1], m[2], m[3], m[4], m[5]);
        }
        count++;
    }

    if (!count) printf("(no active VIP entries)\n");
    return 0;
}

// ── Entry point ───────────────────────────────────────────────────────────────

int main(int argc, char **argv)
{
    if (argc < 2) { usage(argv[0]); return 1; }

    const char *cmd = argv[1];

    if (!strcmp(cmd, "attach")) {
        if (argc < 3) { usage(argv[0]); return 1; }
        return cmd_attach(argv[2], argc >= 4 ? argv[3] : DEFAULT_OBJ);
    }
    if (!strcmp(cmd, "detach")) {
        if (argc < 3) { usage(argv[0]); return 1; }
        return cmd_detach(argv[2]);
    }
    if (!strcmp(cmd, "setlbip")) {
        if (argc < 3) { usage(argv[0]); return 1; }
        return cmd_setlbip(argv[2]);
    }
    if (!strcmp(cmd, "add")) {
        if (argc < 6) { usage(argv[0]); return 1; }
        return cmd_add(argv[2], argv[3], argv[4], argv[5]);
    }
    if (!strcmp(cmd, "del")) {
        if (argc < 4) { usage(argv[0]); return 1; }
        return cmd_del(argv[2], argv[3]);
    }
    if (!strcmp(cmd, "list")) {
        return cmd_list();
    }

    usage(argv[0]);
    return 1;
}
