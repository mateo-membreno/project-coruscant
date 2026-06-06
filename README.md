# Project Coruscant — XDP Load Balancer

A from-scratch L4 load balancer built on Linux XDP (eXpress Data Path).
Packets are intercepted at the NIC driver layer — before the kernel network
stack — and their L2/L3 destination is rewritten in place.  A C++ controller
manages the backend pool via eBPF shared-memory maps; no program reload is
ever needed to add, remove, or recover a backend.

**need to add caching for connections that remap while open**

## Architecture

```
Client
  │  TCP/UDP packet → VIP:port
  ▼
┌─────────────────────────────────────────────────────┐
│  NIC  (XDP hook — runs xdp_lb.o at line rate)       │
│                                                     │
│  1. Parse Eth / IP / TCP|UDP headers                │
│  2. Lookup {dst_ip, dst_port} in backends_map       │
│  3. Pick backend: idx = maglev_table[FNV1a(4-tuple) % 251] │
│  4. Rewrite dst MAC + dst IP, fix IP checksum       │
│  5. XDP_TX → out the same interface                 │
└─────────────────────────────────────────────────────┘
          │  reads
          ▼
    backends_map  (/sys/fs/bpf/lb_backends)
          ▲  writes (health-filtered)
          │
     lb_healthd ──── probes backends ──── config_map
          ▲                                    ▲
          │                                    │
     lb_ctrl add/del ────────────────────────────
```

## Project layout

```
src/
  xdp_lb.c        — eBPF XDP kernel program (steps 1–3)
  lb_common.h     — shared structs: vip_key, backend_entry, backends_val
  maglev.h        — Maglev table builder (userspace only): maglev_build()
  lb_ctrl.cpp     — C++ controller: attach/detach, add/del backends
  lb_healthd.cpp  — health-checker daemon: async TCP probes, auto remove/restore

tests/
  test_xdp_lb.c   — portable unit tests (no kernel required, macOS + Linux)

scripts/
  install_deps.sh — install all build deps on a fresh Ubuntu EC2 instance
  load.sh         — low-level manual attach (lb_ctrl supersedes this)
  unload.sh       — low-level manual detach

spec              — step-by-step implementation guide
```

## Quick start

```bash
# 1. Install dependencies (Ubuntu 26.04, EC2 t3.micro)
sudo ./scripts/install_deps.sh

# 2. Build everything
mkdir -p build && cd build && cmake .. && make

# 3. Load XDP onto your interface (creates both maps)
sudo ./build/lb_ctrl attach enp0s5

# 4. Set the LB's own IP (used as outer IPIP source address)
sudo ./build/lb_ctrl setlbip <lb-private-ip>

# 5. Register backends
sudo ./build/lb_ctrl add <vip-ip> <port> <backend-ip> <backend-mac>

# 6. Start the health checker
sudo ./build/lb_healthd &

# 7. Inspect active state at any time
sudo ./build/lb_ctrl list

# 8. Tear down
sudo pkill lb_healthd
sudo ./build/lb_ctrl detach enp0s5
```

## Deployment

Tested on three AWS EC2 t3.micro instances (Ubuntu 26.04, us-east-2, same VPC subnet):

```
┌─────────────────┐        ┌──────────────────────────────────┐
│  Client EC2     │──────▶│  Load Balancer EC2               │
│  (iperf3 -c)   │        │  <lb-private-ip>  enp0s5            │
└─────────────────┘        │  XDP attached: xdp_lb.o          │
                           │  lb_healthd running              │
                           └──────────────┬───────────────────┘
                                          │ IPIP encapsulation
                                          ▼
                           ┌──────────────────────────────────┐
                           │  Backend EC2                     │
                           │  iperf3 -s / python3 http.server │
                           └──────────────────────────────────┘
```

All three instances in the same subnet so `XDP_TX` can reach backends over L2.
The LB instance's security group allows inbound from the client instance's
private IP and from the developer's laptop for SSH.

### Setup commands used

```bash
# On LB instance
sudo ./build/lb_ctrl attach enp0s5
sudo ./build/lb_ctrl setlbip <lb-private-ip>
sudo ./build/lb_ctrl add <lb-private-ip> 5201 <backend-private-ip> <backend-mac>
sudo ./build/lb_healthd &
```

## Benchmarks

### EC2 client → LB (same subnet, private IPs)

```
[ ID] Interval           Transfer     Bitrate
[  5]   0.00-10.00  sec  5.52 GBytes  4.74 Gbits/sec    (LB receiver)
[  5]   0.00-10.00  sec  5.39 GBytes  4.63 Gbits/sec    (client sender)
```

**4.74 Gbits/sec** — approaching the t3.micro burst NIC cap of 5 Gbits/sec.
XDP processes packets entirely in the kernel driver layer with zero copies,
so the NIC is the bottleneck, not the load balancer.

### Laptop → LB (over public internet, ~60ms RTT)

```
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-10.01  sec  14.1 MBytes  11.8 Mbits/sec  1956
```

**11.8 Mbits/sec** with 1956 retransmits — limited entirely by home internet
upload bandwidth and cross-country latency, not XDP.

### Key takeaway

XDP overhead is negligible at these packet rates. At ~4.7 Gbits/sec the LB
forwards ~390,000 packets/sec (assuming ~1500 byte MTU) while consuming
a fraction of one CPU core — the packet processing runs in the NIC driver
interrupt context before any kernel networking code runs.

## Unit tests (no kernel / no root needed)

```bash
cd build && ./test_xdp_lb
```

Output:
```
xdp_lb tests (step 5: maglev consistent hashing)

map / pass-through:
  tcp_with_map_entry_returns_xdp_tx          PASS
  ...

rewrite correctness:
  dst_mac_rewritten_from_selected_backend    PASS
  ...

consistent hashing:
  same_flow_always_picks_same_backend        PASS
  single_backend_pool_always_index_0         PASS
  hash_picks_computed_index                  PASS
  different_src_port_can_pick_different_backend  PASS
  udp_consistent_hash_matches_tcp_formula    PASS

maglev table properties:
  maglev_even_distribution                   PASS
  maglev_minimal_disruption_on_remove        PASS
```

## lb_healthd options

```
sudo lb_healthd [--interval <ms>] [--fail-threshold <n>] [--timeout <ms>]

--interval        ms between health-check cycles  (default: 2000)
--fail-threshold  consecutive failures before removal  (default: 3)
--timeout         TCP connect timeout per probe  (default: 500)
```
