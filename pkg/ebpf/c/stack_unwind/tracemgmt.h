#ifndef __STACK_UNWIND_TRACEMGMT_H__
#define __STACK_UNWIND_TRACEMGMT_H__

#include <common/common.h>
#include <common/arch.h>

#include "types.h"
#include "utils.h"

//
// Prototypes
//

statfunc void mark_process_forked(pid_t tgid);
statfunc void mark_process_execed(pid_t tgid);
statfunc bool process_had_no_exec(pid_t tgid);
statfunc void stack_unwind_mark_process_tracked(void);
statfunc void stack_unwind_mark_process_untracked(void);
statfunc bool stack_unwind_process_is_tracked(void);
statfunc void init_unwind_state(stack_unwind_state_t *state, bool interrupted_kernel);
statfunc void init_stack_trace(StackTrace *trace);
statfunc ErrorCode _push_with_return_address(StackTrace *trace, u64 pc, u64 file, u64 line, u8 frame_type, bool return_address);
statfunc ErrorCode get_next_unwinder_after_native_frame(stack_unwind_state_t *state, StackTrace *trace, int *unwinder);
statfunc void unwind_stop(void *ctx, stack_unwind_state_t *state, StackTrace *trace, enum bpf_prog_type prog_type);
statfunc ErrorCode unwind_tail_call(void *ctx, int unwinder, enum bpf_prog_type prog_type);

//
// Maps
//

// map for tracking TGIDs that had no exec
struct stack_unwind_noexec_tgids {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 2048);
    __type(key, pid_t);
    __type(value, bool);
} su_noexec_tgids SEC(".maps");

struct stack_unwind_enabled_unwinders {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, NUM_TRACER_PROGS);
    __type(key, u32);
    __type(value, u32);
} su_enbld_unwnd SEC(".maps");

struct stack_unwind_progs {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, NUM_TRACER_PROGS);
    __type(key, u32);
    __type(value, u32);
};

struct stack_unwind_progs su_progs_kp SEC(".maps");
struct stack_unwind_progs su_progs_tp SEC(".maps");

// defined in include/uapi/linux/perf_event.h
#define PERF_MAX_STACK_DEPTH 127

// This contains the kernel PCs as returned by bpf_get_stackid(). Unfortunately the ebpf
// program cannot read the contents, so we return the stackid in the event directly, and
// make userspace read the kernel mode stack trace portion from this map.
struct stack_unwind_kernel_stackmap {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(max_entries, 1024);
    __type(key, u32);
    __uint(value_size, PERF_MAX_STACK_DEPTH * sizeof(u64));
} su_kern_stacks SEC(".maps");

// The native unwinder needs to be able to determine how each mapping should be unwound.
//
// This map contains data to help the native unwinder translate from a virtual address in a given
// process. It contains information of the unwinder program to use, how to convert the virtual
// address to relative address, and what executable file is in question.
struct stack_unwind_pid_page_to_mapping_info {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 524288); // 2^19
    __type(key, PIDPage);
    __type(value, PIDPageMappingInfo);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} su_pid_pg_to_mp SEC(".maps");

// The decision whether to unwind native stacks or interpreter stacks is made by checking if a given
// PC address falls into the "interpreter loop" of an interpreter. This map helps identify such
// loops: The keys are those executable section IDs that contain interpreter loops, the values
// identify the offset range within this executable section that contains the interpreter loop.
struct stack_unwind_interpreter_offsets {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32);
    __type(key, u64);
    __type(value, OffsetRange);
} su_interp_offs SEC(".maps");

//
// Functions
//

statfunc void mark_process_forked(pid_t tgid)
{
    u32 val = 1;
    bpf_map_update_elem(&su_noexec_tgids, &tgid, &val, BPF_ANY);
}

statfunc void mark_process_execed(pid_t tgid)
{
    bpf_map_delete_elem(&su_noexec_tgids, &tgid);
}

statfunc bool process_had_no_exec(pid_t tgid)
{
    return bpf_map_lookup_elem(&su_noexec_tgids, &tgid) != NULL;
}

// Mark a process as tracked by inserting a fake PID Page mapping for address 0
statfunc void stack_unwind_mark_process_tracked(void)
{
    PIDPage key = {
        .prefixLen = BIT_WIDTH_PID + BIT_WIDTH_PAGE,
        .pid = __constant_cpu_to_be32(bpf_get_current_pid_tgid() >> 32),
        .page = 0
    };

    PIDPageMappingInfo val = {0};

    bpf_map_update_elem(&su_pid_pg_to_mp, &key, &val, BPF_ANY);
}

statfunc void stack_unwind_mark_process_untracked(void)
{
    PIDPage key = {
        .prefixLen = BIT_WIDTH_PID + BIT_WIDTH_PAGE,
        .pid = __constant_cpu_to_be32(bpf_get_current_pid_tgid() >> 32),
        .page = 0
    };

    bpf_map_delete_elem(&su_pid_pg_to_mp, &key);
}

statfunc bool stack_unwind_process_is_tracked(void)
{
    PIDPage key = {
        .prefixLen = BIT_WIDTH_PID + BIT_WIDTH_PAGE,
        .pid = __constant_cpu_to_be32(bpf_get_current_pid_tgid() >> 32),
        .page = 0
    };

    return bpf_map_lookup_elem(&su_pid_pg_to_mp, &key) != NULL;
}

statfunc void init_unwind_state(stack_unwind_state_t *state, bool interrupted_kernel)
{
    state->interrupted_kernel = interrupted_kernel;
    state->native_state.pc = 0;
    state->native_state.sp = 0;
    state->native_state.fp = 0;
#if defined(bpf_target_x86)
    state->native_state.r13 = 0;
#elif defined(bpf_target_arm64)
    state->state.lr = 0;
    state->state.r22 = 0;
#endif
    state->unwind_error = ERR_OK;
    state->native_state.return_address = false;
    //state->native_state.error_metric = -1;
    /*state->perlUnwindState.stackinfo = 0;
    state->perlUnwindState.cop = 0;
    state->pythonUnwindState.py_frame = 0;
    state->phpUnwindState.zend_execute_data = 0;
    state->rubyUnwindState.stack_ptr = 0;
    state->rubyUnwindState.last_stack_frame = 0;*/
    state->unwindersDone = 0;
    //state->tailCalls = 0;
}

statfunc void init_stack_trace(StackTrace *trace)
{
    trace->metadata.kernel_stack_id = -1;
    trace->metadata.stack_len = 0;
    //trace->metadata.pid = 0;
    //trace->metadata.tid = 0;
}

// Push the file ID, line number and frame type into FrameList with a user-defined
// maximum stack size.
//
// NOTE: The line argument is used for a lot of different purposes, depending on
//       the frame type. For example error frames use it to store the error number,
//       and hotspot puts a subtype and BCI indices, amongst other things (see
//       calc_line). This should probably be renamed to something like "frame type
//       specific data".
statfunc ErrorCode _push_with_max_frames(StackTrace *trace, u64 pc, u64 file, u64 line, u8 frame_type, u8 return_address, u32 max_frames) {
    if (trace->metadata.stack_len >= max_frames) {
        DEBUG_PRINT("unable to push frame: stack is full");
        return ERR_STACK_LENGTH_EXCEEDED;
    }

    trace->frames[trace->metadata.stack_len++] = (StackFrame) {
        .pc = pc,
        .file_id = file,
        .addr_or_line = line,
        .kind = frame_type,
        .return_address = return_address,
    };

    return ERR_OK;
}

// Push the file ID, line number and frame type into FrameList
statfunc ErrorCode _push_with_return_address(StackTrace *trace, u64 pc, u64 file, u64 line, u8 frame_type, bool return_address) {
    return _push_with_max_frames(trace, pc, file, line, frame_type, return_address, MAX_NON_ERROR_FRAME_UNWINDS);
}

// is_kernel_address checks if the given address looks like virtual address to kernel memory.
statfunc bool is_kernel_address(u64 addr) {
  return addr & 0xFF00000000000000UL;
}

// resolve_unwind_mapping decodes the current PC's mapping and prepares unwinding information.
// The state text_section_id and text_section_offset are updated accordingly. The unwinding program
// index that should be used is written to the given `unwinder` pointer.
statfunc ErrorCode resolve_unwind_mapping(stack_unwind_state_t *state, int *unwinder) {
    pid_t tgid = bpf_get_current_pid_tgid() >> 32;
    u64 pc = state->native_state.pc;

    if (is_kernel_address(pc)) {
        // This should not happen as we should only be unwinding usermode stacks.
        // Seeing PC point to a kernel address indicates a bad unwind.
        DEBUG_PRINT("PC value %lx is a kernel address", (unsigned long) pc);
        return ERR_NATIVE_UNEXPECTED_KERNEL_ADDRESS;
    }

    if (pc < 0x1000) {
        // The kernel will always return a start address for user space memory mappings that is
        // above the value defined in /proc/sys/vm/mmap_min_addr.
        // As such small PC values happens regularly (e.g. by handling or extracting the
        // PC value incorrectly) we track them but don't proceed with unwinding.
        DEBUG_PRINT("small pc value %lx, ignoring", (unsigned long) pc);
        return ERR_NATIVE_SMALL_PC;
    }

    PIDPage key = {};
    key.prefixLen = BIT_WIDTH_PID + BIT_WIDTH_PAGE;
    key.pid = __constant_cpu_to_be32((u32) tgid);
    key.page = __constant_cpu_to_be64(pc);

    // Check if we have the data for this virtual address
    PIDPageMappingInfo* val = bpf_map_lookup_elem(&su_pid_pg_to_mp, &key);
    if (!val) {
        // If this process had no exec yet, try again with the parent PID as the key,
        // as it may have reported this mapping and this process inherited it when forked.
        if (process_had_no_exec(tgid)) {
            DEBUG_PRINT("PID %d had no exec yet, trying to fetch information from parent", tgid);
            struct task_struct *task = (struct task_struct *) bpf_get_current_task();
            if (task != NULL) {
                pid_t parent_tgid = get_task_ppid(task);
                key.pid = __constant_cpu_to_be32((u32) parent_tgid);
                val = bpf_map_lookup_elem(&su_pid_pg_to_mp, &key);
            }
        }
    }
    if (!val) {
        DEBUG_PRINT("Failure to look up interval memory mapping for PC 0x%lx",
                    (unsigned long) pc);
        return ERR_NATIVE_NO_PID_PAGE_MAPPING;
    }

    decode_bias_and_unwind_program(val->bias_and_unwind_program, &state->native_state.text_section_bias, unwinder);
    state->native_state.text_section_id = val->file_id;
    state->native_state.text_section_offset = pc - state->native_state.text_section_bias;
    DEBUG_PRINT("Text section id for PC %lx is %llx (unwinder %d)",
        (unsigned long) pc, state->native_state.text_section_id, *unwinder);
    DEBUG_PRINT("Text section bias is %llx, and offset is %llx",
        state->native_state.text_section_bias, state->native_state.text_section_offset);

    return ERR_OK;
}

// unwinder_is_done checks if a given unwinder program is done for the trace
// extraction round.
statfunc bool unwinder_is_done(const stack_unwind_state_t *state, int unwinder) {
    return (state->unwindersDone & (1U << unwinder)) != 0;
}

// get_next_interpreter tries to get the next interpreter unwinder from the section id.
// If the section id happens to be within the range of a known interpreter it will
// return the interpreter unwinder otherwise the native unwinder.
statfunc int get_next_interpreter(stack_unwind_state_t *state) {
    u64 section_id = state->native_state.text_section_id;
    u64 section_offset = state->native_state.text_section_offset;
    // Check if the section id happens to be in the interpreter map.
    OffsetRange *range = bpf_map_lookup_elem(&su_interp_offs, &section_id);
    if (range != 0) {
        if ((section_offset >= range->lower_offset) && (section_offset <= range->upper_offset)) {
        DEBUG_PRINT("interpreter_offsets match %d", range->program_index);
        if (!unwinder_is_done(state, range->program_index))
            return range->program_index;
        DEBUG_PRINT("interpreter unwinder done");
        }
    }
    return PROG_UNWIND_NATIVE;
}

// get_next_unwinder_after_native_frame determines the next unwinder program to run
// after a native stack frame has been unwound.
statfunc ErrorCode get_next_unwinder_after_native_frame(stack_unwind_state_t *state, StackTrace *trace, int *unwinder) {
    *unwinder = PROG_UNWIND_STOP;

    if (state->native_state.pc == 0) {
        DEBUG_PRINT("Stopping unwind due to unwind failure (PC == 0)");
        return ERR_NATIVE_ZERO_PC;
    }

    DEBUG_PRINT("==== Resolve next frame unwinder: frame %d ====", trace->metadata.stack_len);
    ErrorCode error = resolve_unwind_mapping(state, unwinder);
    if (error) {
        return error;
    }

    if (*unwinder == PROG_UNWIND_NATIVE) {
        *unwinder = get_next_interpreter(state);
    }

    return ERR_OK;
}

statfunc void unwind_stop(void *ctx, stack_unwind_state_t *state, StackTrace *trace, enum bpf_prog_type prog_type)
{
    DEBUG_PRINT("reached unwind_stop");
}

statfunc ErrorCode unwind_tail_call(void *ctx, int unwinder, enum bpf_prog_type prog_type)
{
    // nonexistent or disabled unwinder
    u32 *unwinder_entry = bpf_map_lookup_elem(&su_enbld_unwnd, &unwinder);
    if (unwinder_entry == NULL)
        return ERR_BAD_UNWINDER;
    if (*unwinder_entry != 1)
        return ERR_UNWINDER_DISABLED;
    
    // perform the tail call according to the program type
    switch (prog_type) {
        // krpobe, kretprobe, uprobe
        case BPF_PROG_TYPE_KPROBE:
            bpf_tail_call(ctx, &su_progs_kp, unwinder);
            break;
        case BPF_PROG_TYPE_RAW_TRACEPOINT:
            bpf_tail_call(ctx, &su_progs_tp, unwinder);
            break;
        default:
            return ERR_INVALID_PROGRAM_TYPE;
    }

    // the tail call failed, assume we reached the limit
    return ERR_MAX_TAIL_CALLS;
}

#endif /* __STACK_UNWIND_TRACEMGMT_H__ */