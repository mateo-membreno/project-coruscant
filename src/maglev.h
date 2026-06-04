// Maglev consistent hash table builder (userspace only — not included by xdp_lb.c).
//
// Call maglev_build(val) after any change to val->backends / val->count.
// The XDP program then selects a backend with a single array lookup:
//   idx = val->maglev_table[hash_4tuple(...) % MAGLEV_M]
//
// Removing one backend from a pool of N remaps ~1/N table slots — the
// theoretical minimum, vs ~(N-1)/N for plain modulo hashing.

#pragma once

#include <string.h>
#include "lb_common.h"

// Two independent FNV-1a based hash functions.  Different seeds ensure the
// per-backend permutations are uncorrelated, which gives even slot ownership.

static inline __u32 _maglev_h1(__u32 ip)
{
    __u32 h = 2166136261u;
    h ^= (ip & 0xff);         h *= 16777619u;
    h ^= ((ip >> 8) & 0xff);  h *= 16777619u;
    h ^= ((ip >> 16) & 0xff); h *= 16777619u;
    h ^= ((ip >> 24) & 0xff); h *= 16777619u;
    return h;
}

static inline __u32 _maglev_h2(__u32 ip)
{
    __u32 h = 2246822519u;
    h ^= (ip & 0xff);         h *= 2246822519u;
    h ^= ((ip >> 8) & 0xff);  h *= 2246822519u;
    h ^= ((ip >> 16) & 0xff); h *= 2246822519u;
    h ^= ((ip >> 24) & 0xff); h *= 2246822519u;
    return h;
}

// Fill val->maglev_table using the Maglev greedy fill algorithm.
// val->backends[0..val->count-1] must already be set before calling.
// Table entries are backend indices in [0, count-1].
// If count == 0, the table is filled with 0xff (no valid backend).

static inline void maglev_build(struct backends_val *val)
{
    __u32 count = val->count;
    __u8  *table = val->maglev_table;

    if (count == 0) {
        memset(table, 0xff, MAGLEV_M);
        return;
    }

    // Per-backend offset and skip in [1, MAGLEV_M-1].
    // Since MAGLEV_M is prime, any skip value is coprime to M, guaranteeing
    // the permutation visits all M slots before repeating.
    __u32 offset[MAX_BACKENDS];
    __u32 skip[MAX_BACKENDS];
    __u32 i;
    for (i = 0; i < count; i++) {
        __u32 ip  = val->backends[i].ip;
        offset[i] = _maglev_h1(ip) % MAGLEV_M;
        skip[i]   = (_maglev_h2(ip) % (MAGLEV_M - 1)) + 1;
    }

    memset(table, 0xff, MAGLEV_M);

    __u32 next[MAX_BACKENDS];
    memset(next, 0, sizeof(__u32) * MAX_BACKENDS);
    __u32 filled = 0;

    // Round-robin across backends: each claims its next preferred empty slot.
    while (filled < MAGLEV_M) {
        for (i = 0; i < count; i++) {
            __u32 slot = (offset[i] + next[i] * skip[i]) % MAGLEV_M;
            while (table[slot] != 0xff) {
                next[i]++;
                slot = (offset[i] + next[i] * skip[i]) % MAGLEV_M;
            }
            table[slot] = (__u8)i;
            next[i]++;
            filled++;
            if (filled == MAGLEV_M)
                break;
        }
    }
}
