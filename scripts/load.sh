#!/usr/bin/env bash
# Attach xdp_lb to a network interface.
# Usage: sudo ./scripts/load.sh <interface>   (e.g. eth0, ens3)
set -euo pipefail

DEV="${1:?usage: $0 <interface>}"
OBJ="src/xdp_lb.o"

if [[ ! -f "$OBJ" ]]; then
    echo "Object file not found. Run 'make' first." >&2
    exit 1
fi

ip link set dev "$DEV" xdp obj "$OBJ" sec xdp
echo "xdp_lb loaded on $DEV"
