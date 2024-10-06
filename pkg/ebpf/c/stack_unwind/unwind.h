#ifndef __STACK_UNWIND_H__
#define __STACK_UNWIND_H__

#include <bpf/bpf_helpers.h>

#include "tracemgmt.h"

#define MAX_CONCURRENT_STACK_UNWINDS 128

#define E2BIG 7

//
// Prototypes
//

statfunc bool stack_trace_selected_for_event(u32 event_id);
statfunc bool stack_trace_selected_for_scope(void *ctx);
statfunc void generate_stack_trace(program_data_t *p);
statfunc event_data_t *get_saved_event(void *ctx);
statfunc StackTrace *get_stack_trace_from_event(event_data_t *event);
statfunc stack_unwind_state_t *get_stack_unwind_state(StackTrace *trace, bool interrupted_kernel);
statfunc void delete_saved_event(void);
statfunc void delete_stack_unwind_state(void);
statfunc void apply_saved_stack_trace(program_data_t *p);

//
// Maps
//

struct stack_unwind_tail {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, MAX_EVENT_ID);
    __type(key, u32);
    __type(value, u32);
};

struct stack_unwind_tail su_tail_kp SEC(".maps");
struct stack_unwind_tail su_tail_tp SEC(".maps");

struct stack_unwind_enabled_events {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_EVENT_ID);
    __type(key, u32);
    __type(value, u32);
} su_enabled_evts SEC(".maps");

struct stack_unwind_saved_events {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_CONCURRENT_STACK_UNWINDS);
    __type(key, pid_t);
    __type(value, event_data_t);
} su_saved_evts SEC(".maps");

struct stack_unwind_state_map {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_CONCURRENT_STACK_UNWINDS);
    __type(key, pid_t);
    __type(value, stack_unwind_state_t);
} su_state SEC(".maps");

struct stack_unwind_state_tmp_storage {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, stack_unwind_state_t);
} su_state_tmp SEC(".maps");

struct stack_unwind_stack_trace_temp_events {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 64);
    __type(key, pid_t);
    __type(value, event_data_t);
} su_st_tmp_evts SEC(".maps");

//
// Functions
//

statfunc bool stack_trace_selected_for_event(u32 event_id)
{
    return bpf_map_lookup_elem(&su_enabled_evts, &event_id) != NULL;
}

statfunc void generate_stack_trace(program_data_t *p)
{
    // save event data
    pid_t pid = bpf_get_current_pid_tgid();
    int ret = (int) bpf_map_update_elem(&su_saved_evts, &pid, p->event, BPF_NOEXIST);
    if (ret == -E2BIG) {
        // map full (reached maximum number of concurrent stack unwinds)
        p->event->context.stack_unwind_error = ERR_MAX_CONCURRENT;
        return;
    }
    else if (ret != 0) {
        // unexpected error
        DEBUG_PRINT("can't save event data");
        p->event->context.stack_unwind_error = ERR_UNKNOWN;
        return;
    }
    
    // tail call into unwinder program according to program type
    switch (p->prog_type) {
        // krpobe, kretprobe, uprobe
        case BPF_PROG_TYPE_KPROBE:
            bpf_tail_call(p->ctx, &su_tail_kp, p->event->context.eventid);
            break;
        case BPF_PROG_TYPE_RAW_TRACEPOINT:
            bpf_tail_call(p->ctx, &su_tail_tp, p->event->context.eventid);
            break;
        default:
            p->event->context.stack_unwind_error = ERR_INVALID_PROGRAM_TYPE;
            return;
    }

    // if we reached this point then the tail call failed
    DEBUG_PRINT("failed tail call to unwind program");
    p->event->context.stack_unwind_error = ERR_UNKNOWN;
}

statfunc event_data_t *get_saved_event(void *ctx)
{
    pid_t pid = bpf_get_current_pid_tgid();
    event_data_t *event = (event_data_t *) bpf_map_lookup_elem(&su_saved_evts, &pid);

    // the event was lost somehow o_o
    if (unlikely(event == NULL))
        tracee_log(ctx, BPF_LOG_LVL_ERROR, BPF_LOG_ID_STACK_UNWIND_LOST_EVENT, 0);

    return event;
}

// Retrieve the StackTrace data structure from an event.
// The event structure has enough space to hold both a full args buffer
// and a full stack trace structure.
// To reduce the size of the data sent to userspace, the stack trace is
// appended to the end of the used portion of the args buffer.
//
// WARNING: the stack trace structure placement that this function calculates
// assumes that no more arguments will be added to the event.
// TODO: enforce 8-byte alignment
statfunc StackTrace *get_stack_trace_from_event(event_data_t *event)
{
    u32 offset = sizeof(args_metadata_t) + event->args_buf.metadata.offset;

    // satisfy the verifier
    if (offset > sizeof(args_buffer_t))
        return NULL;
    
    return (StackTrace *) &event->dynamic_data[offset];
}

statfunc stack_unwind_state_t *get_stack_unwind_state(StackTrace *trace, bool interrupted_kernel)
{
    stack_unwind_state_t *state;

    // try getting an existing unwind state
    pid_t tid = bpf_get_current_pid_tgid();
    if ((state = (stack_unwind_state_t *) bpf_map_lookup_elem(&su_state, &tid)) != NULL)
        return state;
    
    // no existing state, create a new one
    u32 zero = 0;
    if (unlikely((state = bpf_map_lookup_elem(&su_state_tmp, &zero)) == NULL))
        return NULL;
    
    // reset the state
    init_stack_trace(trace);
    init_unwind_state(state, interrupted_kernel);
    
    // update the states map with the newly created state
    if (unlikely(bpf_map_update_elem(&su_state, &tid, state, BPF_NOEXIST)) != 0)
        return NULL;
    
    // return the copy from the from the states map that we just inserted
    if (unlikely(((state = bpf_map_lookup_elem(&su_state, &tid))) == NULL))
        return NULL;
    
    return state;
}

statfunc void delete_saved_event(void)
{
    u32 pid = bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&su_saved_evts, &pid);
}

statfunc void delete_stack_unwind_state(void)
{
    u32 pid = bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&su_state, &pid);
}

statfunc void save_stack_trace_event(event_data_t *event)
{
    // Check if we are currently in an exec syscall.
    // If so, we should use the TGID instead of PID as the key, because the calling
    // thread may change its PID during the exec (see de_thread function in the kernel).
    // We take a risk that another thread in this process will call exec before this one
    // reaches the point of no return, but the chances of this happennig are very slim.
    bool is_exec = false;
    int syscall_id = get_current_task_syscall_id();
    if (syscall_id == SYSCALL_EXECVE || syscall_id == SYSCALL_EXECVEAT)
        is_exec = true;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 key;
    if (is_exec)
        key = pid_tgid >> 32;
    else
        key = (u32) pid_tgid;
    
    bpf_map_update_elem(&su_st_tmp_evts, &key, event, BPF_ANY);
}

statfunc void apply_saved_stack_trace(program_data_t *p)
{
    if (!stack_trace_selected_for_event(p->event->context.eventid))
        return;
    
    // Check if we are currently in an exec syscall.
    // If so, we should use the TGID instead of PID as the key.
    bool is_exec = false;
    int syscall_id = p->event->context.syscall;
    if (syscall_id == SYSCALL_EXECVE || syscall_id == SYSCALL_EXECVEAT)
        is_exec = true;
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 key;
    if (is_exec)
        key = pid_tgid >> 32;
    else
        key = (u32) pid_tgid;

    event_data_t *stack_trace_event = bpf_map_lookup_elem(&su_st_tmp_evts, &key);
    if (stack_trace_event == NULL)
        return;
    bpf_map_delete_elem(&su_st_tmp_evts, &key);
    
    StackTrace *src = get_stack_trace_from_event(stack_trace_event);
    if (src == NULL)
        return;
    
    StackTrace *dst = get_stack_trace_from_event(p->event);
    if (dst == NULL)
        return;
    
    if (bpf_probe_read(dst, sizeof(StackTrace), src) != 0)
        return;
    
    p->event->context.has_stack_trace = true;
    p->event->context.stack_unwind_error = stack_trace_event->context.stack_unwind_error;
}

#define stack_unwind_step(ctx, func, prog_type, interrupted_kernel) ({                          \
    event_data_t *event = get_saved_event(ctx);                                                 \
    if (likely(event != NULL)) {                                                                \
        event->context.has_stack_trace = true;                                                  \
        StackTrace *trace = get_stack_trace_from_event(event);                                  \
        if (likely(trace != NULL)) {                                                            \
            stack_unwind_state_t *state = get_stack_unwind_state(trace, interrupted_kernel);    \
            if (likely(state != NULL)) {                                                        \
                /* this should tail call into the next unwinder or the unwind stop program */   \
                func(ctx, state, trace, prog_type);                                             \
                                                                                                \
                /* if we reached this point, then the stack trace failed, finalize the trace */ \
                unwind_stop(ctx, state, trace, prog_type);                                      \
                event->context.stack_unwind_error = state->unwind_error;                        \
            }                                                                                   \
        }                                                                                       \
        /* Delete the saved state, and submit the event. */                                     \
        delete_saved_event();                                                                   \
        delete_stack_unwind_state();                                                            \
        if (event->context.eventid == STACK_TRACE)                                              \
            /* stack trace pseudo event, save it until another event picks it up */             \
            save_stack_trace_event(event);                                                      \
        else                                                                                    \
            do_submit_event(ctx, event);                                                        \
    }                                                                                           \
})

#endif /* __STACK_UNWIND_H__ */