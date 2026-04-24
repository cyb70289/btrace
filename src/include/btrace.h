#ifndef BTRACE_H
#define BTRACE_H

#ifdef __BPF__
typedef unsigned char      u8;
typedef unsigned short     u16;
typedef unsigned int       u32;
typedef unsigned long long u64;
typedef int                s32;
typedef long               long_t;
#else
#include <stdint.h>
typedef uint8_t   u8;
typedef uint16_t  u16;
typedef uint32_t  u32;
typedef uint64_t  u64;
typedef int32_t   s32;
typedef int64_t   long_t;
#endif

#define BTRACE_MAGIC      "BTR1"
#define BTRACE_VERSION    1
#define BTRACE_HDR_SIZE   256
#define COMM_LEN          16
#define MAX_STACK_DEPTH   127
#define MAX_STACK_MAP     16384
#define MAX_BLOCKED_MAP   4096
#define PERF_BUF_PAGES    64

#define EVENT_MAGIC       0x37815325

#define TASK_RUNNING         0x00000000
#define TASK_INTERRUPTIBLE   0x00000001
#define TASK_UNINTERRUPTIBLE 0x00000002

struct btrace_header {
    char    magic[4];
    u32     version;
    u32     target_pid;
    u64     start_time_ns;
    u64     end_time_ns;
    u64     num_events;
    u32     num_stacks;
    u32     num_threads;
    u64     events_off;
    u64     stacks_off;
    u64     threads_off;
    u64     maps_off;
    u64     kallsyms_off;
    u8      reserved[168];
};

struct block_wake_event {
    u64   timestamp;
    u64   block_timestamp;
    u64   prev_state;
    u32   blocked_tid;
    u32   blocked_tgid;
    u32   waker_tid;
    u32   waker_tgid;
    s32   blocked_ustack_id;
    s32   blocked_kstack_id;
    s32   waker_ustack_id;
    s32   waker_kstack_id;
    char  blocked_comm[COMM_LEN];
    char  waker_comm[COMM_LEN];
};

struct block_only_event {
    u64   timestamp;
    u64   prev_state;
    u32   tid;
    u32   tgid;
    s32   ustack_id;
    s32   kstack_id;
    char  comm[COMM_LEN];
};

struct thread_create_event {
    u64   timestamp;
    u32   parent_tid;
    u32   child_tid;
    u32   child_tgid;
    u32   _pad0;
    char  child_comm[COMM_LEN];
};

struct thread_exit_event {
    u64   timestamp;
    u32   tid;
    u32   tgid;
};

struct bt_stack_entry {
    s32   stack_id;
    u32   num_frames;
};

struct thread_entry {
    u32   tid;
    u32   tgid;
    char  comm[COMM_LEN];
};

#define CAT_FUTEX     1
#define CAT_DISK_IO   2
#define CAT_NET_IO    3
#define CAT_EPOLL     4
#define CAT_SLEEP     5
#define CAT_PGFAULT   6
#define CAT_IO_URING  7
#define CAT_WAITPID   8
#define CAT_SIGNAL    9
#define CAT_OTHER     10

#ifndef __BPF__
_Static_assert(sizeof(struct btrace_header) == BTRACE_HDR_SIZE,
               "btrace_header size mismatch with BTRACE_HDR_SIZE");
#endif

#define WCAT_THREAD   1
#define WCAT_DISK_IO  2
#define WCAT_NET_RX   3
#define WCAT_TIMER    4
#define WCAT_SIGNAL   5
#define WCAT_OTHER    6

#ifndef __BPF__
const char *block_cat_name(int cat);
const char *waker_cat_name(int cat);
int classify_block_reason(int kstack_id, int num_frames, u64 *frames,
                          const char **syms);
int classify_waker_reason(int kstack_id, int num_frames, u64 *frames,
                          const char **syms);
#endif

#endif
