// Health-checker daemon for the XDP load balancer — step 4.
//
// Periodically probes every backend in config_map with a non-blocking TCP
// connect.  If a backend accumulates <fail_threshold> consecutive failures
// it is removed from backends_map (which the XDP program reads).  When it
// recovers it is automatically restored.
//
// Usage:
//   sudo lb_healthd [--interval <ms>] [--fail-threshold <n>] [--timeout <ms>]
//
// Defaults: interval=2000 ms, fail-threshold=3, timeout=500 ms
//
// Depends on two pinned maps created by `lb_ctrl attach`:
//   /sys/fs/bpf/lb_backends  — active map (written here, read by XDP)
//   /sys/fs/bpf/lb_config    — config map (source of truth, read-only here)

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <future>
#include <string>
#include <unordered_map>
#include <vector>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "lb_common.h"

static constexpr const char *MAP_PIN_PATH    = "/sys/fs/bpf/lb_backends";
static constexpr const char *CONFIG_PIN_PATH = "/sys/fs/bpf/lb_config";

static std::atomic<bool> g_running{true};

static void on_signal(int) { g_running = false; }

// ── TCP health probe ──────────────────────────────────────────────────────────
// Returns true if the backend accepts a TCP connection within timeout_ms.

static bool probe_tcp(__u32 ip_net, __u16 port_host, int timeout_ms)
{
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (fd < 0) return false;

    sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = ip_net;          // already network byte order
    addr.sin_port        = htons(port_host);

    int ret = connect(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr));
    if (ret == 0) {
        close(fd);
        return true;    // immediate connect (loopback / same host)
    }
    if (errno != EINPROGRESS) {
        close(fd);
        return false;
    }

    pollfd pfd{ fd, POLLOUT, 0 };
    ret = poll(&pfd, 1, timeout_ms);
    if (ret <= 0) {
        close(fd);
        return false;   // timeout or poll error
    }

    int err = 0;
    socklen_t len = sizeof(err);
    getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len);
    close(fd);
    return err == 0;
}

// ── BackendId: unique key for tracking per-backend health state ───────────────

struct BackendId {
    __u32 vip;
    __u16 port;
    __u32 backend_ip;

    bool operator==(const BackendId &o) const
    {
        return vip == o.vip && port == o.port && backend_ip == o.backend_ip;
    }
};

struct BackendIdHash {
    std::size_t operator()(const BackendId &b) const
    {
        std::size_t h = b.vip;
        h ^= static_cast<std::size_t>(b.port)       << 16;
        h ^= static_cast<std::size_t>(b.backend_ip) << 3;
        return h;
    }
};

// ── HealthChecker ─────────────────────────────────────────────────────────────

class HealthChecker {
public:
    HealthChecker(int active_fd, int config_fd,
                  int fail_threshold, int probe_timeout_ms)
        : active_fd_(active_fd),
          config_fd_(config_fd),
          fail_threshold_(fail_threshold),
          probe_timeout_ms_(probe_timeout_ms)
    {}

    // One full health-check cycle: probe all backends, update backends_map.
    void run_once()
    {
        // Collect all VIP entries from the config map.
        struct Entry { vip_key key; backends_val val; };
        std::vector<Entry> entries;

        vip_key key{}, next_key{};
        backends_val val{};
        bool first = true;

        while (!bpf_map_get_next_key(config_fd_,
                                     first ? nullptr : &key, &next_key)) {
            first = false;
            key   = next_key;
            if (!bpf_map_lookup_elem(config_fd_, &key, &val))
                entries.push_back({key, val});
        }

        // Probe every backend concurrently using std::async.
        for (auto &e : entries) {
            // One future per backend in this VIP pool.
            struct ProbeResult { std::size_t idx; bool healthy; };
            std::vector<std::future<ProbeResult>> futures;
            futures.reserve(e.val.count);

            for (__u32 i = 0; i < e.val.count; i++) {
                __u32 ip   = e.val.backends[i].ip;
                __u16 port = e.key.port;
                int   tmo  = probe_timeout_ms_;
                futures.push_back(
                    std::async(std::launch::async, [=]() -> ProbeResult {
                        return { i, probe_tcp(ip, port, tmo) };
                    })
                );
            }

            // Collect results and update fail streaks.
            backends_val active{};
            active.count = 0;

            for (auto &f : futures) {
                auto res = f.get();
                __u32 i  = static_cast<__u32>(res.idx);

                BackendId bid{ e.key.vip, e.key.port, e.val.backends[i].ip };
                int &streak = fail_streaks_[bid];

                if (res.healthy) {
                    bool was_down = (streak >= fail_threshold_);
                    streak = 0;
                    if (was_down) {
                        char ip_s[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, &bid.backend_ip, ip_s, sizeof(ip_s));
                        printf("[healthd] backend %s recovered, restoring to active map\n",
                               ip_s);
                    }
                } else {
                    streak++;
                    if (streak == fail_threshold_) {
                        char ip_s[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, &bid.backend_ip, ip_s, sizeof(ip_s));
                        printf("[healthd] backend %s failed %d checks, removing from active map\n",
                               ip_s, fail_threshold_);
                    }
                }

                // Include in active pool only if fail streak is below threshold.
                if (fail_streaks_[bid] < fail_threshold_) {
                    if (active.count < MAX_BACKENDS)
                        active.backends[active.count++] = e.val.backends[i];
                }
            }

            // Rewrite the active map entry (or remove if all backends are down).
            if (active.count > 0) {
                bpf_map_update_elem(active_fd_, &e.key, &active, BPF_ANY);
            } else {
                // All backends down: remove VIP so XDP passes packets through.
                bpf_map_delete_elem(active_fd_, &e.key);

                char vip_s[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &e.key.vip, vip_s, sizeof(vip_s));
                printf("[healthd] all backends down for VIP %s:%u, passing traffic\n",
                       vip_s, e.key.port);
            }
        }
    }

private:
    int  active_fd_;
    int  config_fd_;
    int  fail_threshold_;
    int  probe_timeout_ms_;
    std::unordered_map<BackendId, int, BackendIdHash> fail_streaks_;
};

// ── Entry point ───────────────────────────────────────────────────────────────

static void parse_int_arg(int argc, char **argv, int i,
                           const char *name, int &out)
{
    if (i + 1 >= argc) {
        fprintf(stderr, "missing value for %s\n", name);
        exit(1);
    }
    out = atoi(argv[i + 1]);
    if (out <= 0) {
        fprintf(stderr, "%s must be > 0\n", name);
        exit(1);
    }
}

int main(int argc, char **argv)
{
    int interval_ms      = 2000;
    int fail_threshold   = 3;
    int probe_timeout_ms = 500;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--interval"))
            parse_int_arg(argc, argv, i++, "--interval", interval_ms);
        else if (!strcmp(argv[i], "--fail-threshold"))
            parse_int_arg(argc, argv, i++, "--fail-threshold", fail_threshold);
        else if (!strcmp(argv[i], "--timeout"))
            parse_int_arg(argc, argv, i++, "--timeout", probe_timeout_ms);
        else {
            fprintf(stderr,
                "Usage: lb_healthd [--interval <ms>] "
                "[--fail-threshold <n>] [--timeout <ms>]\n");
            return 1;
        }
    }

    int active_fd = bpf_obj_get(MAP_PIN_PATH);
    if (active_fd < 0) {
        fprintf(stderr, "cannot open %s (run 'lb_ctrl attach' first): %s\n",
                MAP_PIN_PATH, strerror(errno));
        return 1;
    }
    int config_fd = bpf_obj_get(CONFIG_PIN_PATH);
    if (config_fd < 0) {
        fprintf(stderr, "cannot open %s (run 'lb_ctrl attach' first): %s\n",
                CONFIG_PIN_PATH, strerror(errno));
        return 1;
    }

    signal(SIGINT,  on_signal);
    signal(SIGTERM, on_signal);

    printf("[healthd] started  interval=%dms  fail-threshold=%d  probe-timeout=%dms\n",
           interval_ms, fail_threshold, probe_timeout_ms);

    HealthChecker hc(active_fd, config_fd, fail_threshold, probe_timeout_ms);

    while (g_running) {
        hc.run_once();
        // Sleep in short increments so SIGINT is handled promptly.
        for (int i = 0; i < interval_ms / 100 && g_running; i++)
            usleep(100 * 1000);
    }

    printf("[healthd] shutting down\n");
    return 0;
}
