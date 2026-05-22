#!/usr/bin/env bash
# Install build and runtime dependencies for project-coruscant.
# Target: Ubuntu 26.04 (Resolute) amd64, EC2 t3.micro
# Usage: sudo ./scripts/install_deps.sh
set -euo pipefail

apt-get update -y
apt-get install -y \
    clang \
    llvm \
    cmake \
    make \
    gcc \
    g++ \
    linux-headers-$(uname -r) \
    libbpf-dev \
    libelf-dev \
    zlib1g-dev \
    iproute2 \
    git

echo ""
echo "All dependencies installed. To build:"
echo "  mkdir -p build && cd build && cmake .. && make"
echo "Then to load the XDP program:"
echo "  sudo ./scripts/load.sh <interface>"
