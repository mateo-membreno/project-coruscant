# Project Coruscant — XDP Load Balancer

A from-scratch L4 load balancer built on Linux XDP (eXpress Data Path).
Packets are intercepted at the NIC driver layer — before the kernel network
stack — and their L2/L3 destination is rewritten in place.  A C++ controller
manages the backend pool via eBPF shared-memory maps; no program reload is
ever needed to add, remove, or recover a backend.

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
│  3. Pick backend: idx = FNV1a(4-tuple) % pool_size  │
│  4. Rewrite dst MAC + dst IP, fix IP checksum        │
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

## Steps

| Step | What it adds | README |
|------|-------------|--------|
| 1 | Single hardcoded backend — proves XDP rewrite works | [README-step1.md](README-step1.md) |
| 2 | eBPF hash map + C++ controller — live backend updates | [README-step2.md](README-step2.md) |
| 3 | 4-tuple consistent hashing — connection pinning | [README-step3.md](README-step3.md) |
| 4 | Health-checker daemon — auto remove/restore backends | [README-step4.md](README-step4.md) |
| 5 *(planned)* | LRU connection table for DSR / encapsulation | — |

## Quick start

```bash
# 1. Install dependencies (Ubuntu 26.04, EC2 t3.micro)
sudo ./scripts/install_deps.sh

# 2. Build everything
mkdir -p build && cd build && cmake .. && make

# 3. Load XDP onto your interface (creates both maps)
sudo ./build/lb_ctrl attach eth0

# 4. Register backends
sudo ./build/lb_ctrl add 10.0.0.1 80 10.0.0.2 aa:bb:cc:dd:ee:ff
sudo ./build/lb_ctrl add 10.0.0.1 80 10.0.0.3 bb:cc:dd:ee:ff:00

# 5. Start the health checker
sudo ./build/lb_healthd &

# 6. Inspect active state at any time
sudo ./build/lb_ctrl list

# 7. Tear down
sudo kill %1
sudo ./build/lb_ctrl detach eth0
```

## Unit tests (no kernel / no root needed)

```bash
cd build && ./test_xdp_lb
```

Output:
```
xdp_lb tests (step 3: consistent hashing)

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
```

## lb_healthd options

```
sudo lb_healthd [--interval <ms>] [--fail-threshold <n>] [--timeout <ms>]

--interval        ms between health-check cycles  (default: 2000)
--fail-threshold  consecutive failures before removal  (default: 3)
--timeout         TCP connect timeout per probe  (default: 500)
```
