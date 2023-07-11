#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct {
    uint64_t success_counts;
    uint64_t failure_counts;
} syscall_counts_t;

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, int);
    __type(value, syscall_counts_t);
    __uint(max_entries, 512);
} syscall_counts SEC(".maps");

SEC("tracepoint/raw_syscalls/sys_exit")
int do_sys_enter(struct syscall_trace_exit* ctx)
{
    uint32_t key = ctx->nr;
    syscall_counts_t* counts = bpf_map_lookup_elem((void*)&syscall_counts, &key);
    if (!counts)
        return 0;

    if (ctx->ret < 0) {
        __sync_fetch_and_add(&counts->failure_counts, (uint64_t)1);
    } else {
        __sync_fetch_and_add(&counts->success_counts, (uint64_t)1);
    }

    return 0;
}
