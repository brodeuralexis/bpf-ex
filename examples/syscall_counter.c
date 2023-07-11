#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, int);
    __type(value, uint64_t);
    __uint(max_entries, 512);
} syscall_counts SEC(".maps");

typedef struct syscall_test {
    uint64_t t1;
    double t2;
} syscall_test_t;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, int);
    __type(value, syscall_test_t);
    __uint(max_entries, 1);
} meta_map SEC(".maps");

SEC("tracepoint/raw_syscalls/sys_enter")
int do_sys_enter(struct syscall_trace_enter* ctx)
{
    uint32_t key = ctx->nr;
    uint64_t* count = bpf_map_lookup_elem((void*)&syscall_counts, &key);
    if (!count)
        return 0;
    __sync_fetch_and_add(count, (uint64_t)1);
    return 0;
}
