// SPDX-License-Identifier: GPL-2.0
//
// Shared data structures between the XDP kernel program and the userspace
// controller.  Both sides include this header; types are chosen to be
// compatible with BPF kernel code (linux/types.h) and portable C++.

#pragma once

#ifdef __linux__
#  include <linux/types.h>
#else
// macOS / non-Linux build hosts (unit-test only path)
#  include <stdint.h>
typedef uint8_t  __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
#endif

#define MAX_BACKENDS 16

// Hash-map key: the virtual IP + destination port the load balancer owns.
// vip is in network byte order; port is in host byte order.
struct vip_key {
    __u32 vip;
    __u16 port;
    __u16 _pad;
};

// One physical backend: the IP and MAC that the XDP program rewrites into
// the packet's L3/L2 destination fields.
struct backend_entry {
    __u32 ip;       // network byte order
    __u8  mac[6];
    __u8  _pad[2];
};

// Map value: the pool of backends registered for a given VIP+port.
// Only indices [0, count) are valid.
struct backends_val {
    __u32               count;
    struct backend_entry backends[MAX_BACKENDS];
};
