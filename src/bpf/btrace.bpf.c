#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "btrace.h"

struct blocked_thread {
    u64 timestamp;
    u32 tgid;
    long prev_state;
    int ustack_id;
    int kstack_id;
    char comm[COMM_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(max_entries, MAX_STACK_MAP);
    __uint(key_size, sizeof(u32));
    __uint(value_size, MAX_STACK_DEPTH * sizeof(u64));
} stack_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_BLOCKED_MAP);
    __type(key, u32);
    __type(value, struct blocked_thread);
} blocked_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
} target_map SEC(".maps");

static __always_inline u32 get_target_tgid(void)
{
    u32 key = 0;
    u32 *val = bpf_map_lookup_elem(&target_map, &key);
    return val ? *val : 0;
}

SEC("tp/sched/sched_switch")
int handle_sched_switch(struct trace_event_raw_sched_switch *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 prev_tgid = pid_tgid >> 32;
    u32 prev_pid = (u32)pid_tgid;
    long prev_state = ctx->prev_state;

    if (prev_state == TASK_RUNNING)
        return 0;

    u32 target = get_target_tgid();
    if (prev_tgid != target)
        return 0;

    struct blocked_thread bt = {};
    bt.timestamp = bpf_ktime_get_ns();
    bt.tgid = prev_tgid;
    bt.prev_state = prev_state;
    bt.ustack_id = bpf_get_stackid(ctx, &stack_map, BPF_F_USER_STACK);
    bt.kstack_id = bpf_get_stackid(ctx, &stack_map, 0);
    bpf_get_current_comm(&bt.comm, sizeof(bt.comm));

    bpf_map_update_elem(&blocked_map, &prev_pid, &bt, BPF_ANY);
    return 0;
}

SEC("tp/sched/sched_waking")
int handle_sched_waking(struct trace_event_raw_sched_wakeup_template *ctx)
{
    u32 target_pid = ctx->pid;

    struct blocked_thread *bt = bpf_map_lookup_elem(&blocked_map, &target_pid);
    if (!bt)
        return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 waker_tgid = pid_tgid >> 32;
    u32 waker_pid = (u32)pid_tgid;

    struct block_wake_event evt = {};
    evt.timestamp = bpf_ktime_get_ns();
    evt.block_timestamp = bt->timestamp;
    evt.blocked_tid = target_pid;
    evt.blocked_tgid = bt->tgid;
    evt.waker_tid = waker_pid;
    evt.waker_tgid = waker_tgid;
    evt.prev_state = (u64)bt->prev_state;
    evt.blocked_ustack_id = bt->ustack_id;
    evt.blocked_kstack_id = bt->kstack_id;
    evt.waker_ustack_id = bpf_get_stackid(ctx, &stack_map, BPF_F_USER_STACK);
    evt.waker_kstack_id = bpf_get_stackid(ctx, &stack_map, 0);
    __builtin_memcpy(evt.blocked_comm, bt->comm, COMM_LEN);
    bpf_get_current_comm(&evt.waker_comm, sizeof(evt.waker_comm));

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
                          &evt, sizeof(evt));
    bpf_map_delete_elem(&blocked_map, &target_pid);
    return 0;
}

SEC("tp/sched/sched_process_fork")
int handle_fork(struct trace_event_raw_sched_process_fork *ctx)
{
    u32 target = get_target_tgid();
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 parent_tgid = pid_tgid >> 32;

    if (parent_tgid != target)
        return 0;

    /* Thread creation events are intentionally ignored in userspace.
     * We keep this tracepoint attached so the skeleton is stable,
     * but we do not emit any perf event here. */
    return 0;
}

SEC("tp/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tid = (u32)pid_tgid;
    u32 tgid = pid_tgid >> 32;

    u32 target = get_target_tgid();
    if (tgid != target)
        return 0;

    bpf_map_delete_elem(&blocked_map, &tid);

    /* Thread exit events are intentionally ignored in userspace.
     * We only keep the tracepoint to clean up orphaned blocked_map entries. */
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
