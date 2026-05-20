#!/usr/bin/env bash
# Detach the XDP program from a network interface.
# Usage: sudo ./scripts/unload.sh <interface>
set -euo pipefail

DEV="${1:?usage: $0 <interface>}"
ip link set dev "$DEV" xdp off
echo "XDP program removed from $DEV"
