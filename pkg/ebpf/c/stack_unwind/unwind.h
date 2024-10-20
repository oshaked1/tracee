#ifndef __STACK_UNWIND_H__
#define __STACK_UNWIND_H__

#include <bpf/bpf_helpers.h>

#include "tracemgmt.h"
#include "native.h"

#define E2BIG 7

//
// Prototypes
//

statfunc bool stack_trace_selected_for_event(u32 event_id);
statfunc bool stack_trace_selected_for_scope(void *ctx);
statfunc void generate_stack_trace(program_data_t *p);
statfunc StackTrace *get_stack_trace_from_event(event_data_t *event);
statfunc stack_unwind_state_t *get_stack_unwind_state(StackTrace *trace, bool interrupted_kernel);
statfunc void apply_saved_stack_trace(program_data_t *p);

//
// Maps
//

struct stack_unwind_enabled_events {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_EVENT_ID);
    __type(key, u32);
    __type(value, u32);
} su_enabled_evts SEC(".maps");

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
    StackTrace *trace;
    stack_unwind_state_t *state;

    trace = get_stack_trace_from_event(p->event);
    if (trace == NULL)
        return;
    
    init_stack_trace(trace);
    p->event->context.has_stack_trace = true;

    // Get the kernel stack trace
    // TODO: stacks with the same ID may result in a race condition where the stack is cleared from user space
    // after another event reuses the ID, so the stack is not available to user space when processing the second event.
    // To get around this we should probably use `bpf_get_stack` and save it to the event buffer.
    trace->metadata.kernel_stack_id = bpf_get_stackid(p->ctx, &su_kern_stacks, BPF_F_REUSE_STACKID);
    DEBUG_PRINT("kernel stack id = %d", trace->metadata.kernel_stack_id);

    if (!bpf_core_type_exists(struct bpf_iter_num)) {
        p->event->context.stack_unwind_error = ERR_BPF_ITER_NUM_MISSING;
        return;
    }

    // Get stack unwind state
    state = get_stack_unwind_state(trace, true /* TODO: set this to false for uprobes */);
    if (unlikely(state == NULL)) {
        p->event->context.stack_unwind_error = ERR_UNKNOWN;
        return;
    }

    // Prepare stack unwinding
    unwind_start(state, trace);
    int unwinder;
    state->unwind_error = get_next_unwinder_after_native_frame(state, trace, &unwinder);

    // Unwind the stack, one frame per iteration.
    // The exit condition is when unwinder == PROG_UNWIND_STOP.
    struct bpf_iter_num it;
    bpf_iter_num_new(&it, 0, MAX_FRAME_UNWINDS);
    int *i;

    while ((i = bpf_iter_num_next(&it)) != NULL) {
        // Using any kind of control flow modifications like break, continue, goto or even modifying
        // the loop condition results in the complete inability of the verifier to accept this loop.
        // As a workaround, we continue iterating and doing nothing when the exit condition is met.
        if (unwinder == PROG_UNWIND_STOP) {}
        // Previous frame had an error
        else if (state->unwind_error != ERR_OK)
            unwinder = PROG_UNWIND_STOP;
        // Unwind native frame
        else if (unwinder == PROG_UNWIND_NATIVE) {
            unwinder = unwind_native(state, trace);
            
            // This isn't the last frame, get the next unwinder
            if (unwinder != PROG_UNWIND_STOP)
                state->unwind_error = get_next_unwinder_after_native_frame(state, trace, &unwinder);
        }
        // Invalid unwinder
        else {
            bpf_printk("invalid unwinder %d", unwinder);
            unwinder = PROG_UNWIND_STOP;
        }
    }

    bpf_iter_num_destroy(&it);

    p->event->context.stack_unwind_error = state->unwind_error;
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
    
    // no existing state, create a new one
    u32 zero = 0;
    if (unlikely((state = bpf_map_lookup_elem(&su_state_tmp, &zero)) == NULL))
        return NULL;
    
    // reset the state
    init_unwind_state(state, interrupted_kernel);
    
    return state;
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

#endif /* __STACK_UNWIND_H__ */