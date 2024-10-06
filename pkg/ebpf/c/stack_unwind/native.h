#include <bpf/bpf_helpers.h>
#include "types.h"

#ifndef __USER32_CS
// defined in arch/x86/include/asm/segment.h
#define GDT_ENTRY_DEFAULT_USER32_CS  4
#define __USER32_CS (GDT_ENTRY_DEFAULT_USER32_CS*8 + 3)
#endif

// The number of native frames to unwind per frame-unwinding eBPF program.
#ifdef STACK_UNWIND_DEBUG
#define NATIVE_FRAMES_PER_PROGRAM 22
#else
#define NATIVE_FRAMES_PER_PROGRAM 20
#endif

//
// Prototypes
//

statfunc ErrorCode copy_state_regs(NativeUnwindState *state, struct pt_regs *regs, bool interrupted_kernel);
statfunc void unwind_native(void *ctx, stack_unwind_state_t *state, StackTrace *trace, enum bpf_prog_type prog_type);
statfunc void unwind_start(void *ctx, stack_unwind_state_t *state, StackTrace *trace, enum bpf_prog_type prog_type);

//
// Maps
//

struct stack_unwind_exe_id_to_stack_deltas {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __uint(max_entries, 4096);
    __type(key, u64);
    __type(value, u32);
    __array(values, struct stack_unwind_exe_id_to_stack_deltas_entry);
};

// Macro to create a map named exe_id_to_X_stack_deltas that is a nested maps with a fileID for the
// outer map and an array as inner map that holds up to 2^X stack delta entries for the given fileID.
#define STACK_DELTA_BUCKET(X)                                                               \
    struct stack_unwind_exe_id_to_##X##_stack_deltas_entry_template {                       \
        __uint(type, BPF_MAP_TYPE_ARRAY);                                                   \
        __uint(max_entries, 1 << X);                                                        \
        __type(key, u32);                                                                   \
        __type(value, StackDelta);                                                          \
    } su_sd_in_##X##_tmpl SEC(".maps");                                                     \
    struct {                                                                                \
        __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);                                            \
        __uint(max_entries, 4096);                                                          \
        __type(key, u64);                                                                   \
        __type(value, u32);                                                                 \
        __array(values, struct stack_unwind_exe_id_to_##X##_stack_deltas_entry_template);   \
    } su_exe_to_##X##_sd SEC(".maps");

// Create buckets to hold the stack delta information for the executables.
STACK_DELTA_BUCKET(8);
STACK_DELTA_BUCKET(9);
STACK_DELTA_BUCKET(10);
STACK_DELTA_BUCKET(11);
STACK_DELTA_BUCKET(12);
STACK_DELTA_BUCKET(13);
STACK_DELTA_BUCKET(14);
STACK_DELTA_BUCKET(15);
STACK_DELTA_BUCKET(16);
STACK_DELTA_BUCKET(17);
STACK_DELTA_BUCKET(18);
STACK_DELTA_BUCKET(19);
STACK_DELTA_BUCKET(20);
STACK_DELTA_BUCKET(21);

// Unwind info value for invalid stack delta
#define STACK_DELTA_INVALID (STACK_DELTA_COMMAND_FLAG | UNWIND_COMMAND_INVALID)
#define STACK_DELTA_STOP    (STACK_DELTA_COMMAND_FLAG | UNWIND_COMMAND_STOP)

// An array of unwind info contains the all the different UnwindInfo instances
// needed system wide. Individual stack delta entries refer to this array.
struct stack_unwind_info_array {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  // Maximum number of unique stack deltas needed on a system. This is based on
  // normal desktop /usr/bin/* and /usr/lib/*.so having about 9700 unique deltas.
  __uint(max_entries, 16384);
  __type(key, u32);
  __type(value, UnwindInfo);
} su_info_arr SEC(".maps");

// Maps fileID and page to information of stack deltas associated with that page.
struct stack_unwind_stack_delta_page_to_info {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 40000);
    __type(key, StackDeltaPageKey);
    __type(value, StackDeltaPageInfo);
} su_sd_pg_to_info SEC(".maps");

//
// Functions
//

#if defined(bpf_target_arm64)
// Strips the PAC tag from a pointer.
//
// While all pointers can contain PAC tags, we only apply this function to code pointers, because
// that's where normalization is required to make the stack delta lookups work. Note that if that
// should ever change, we'd need a different mask for the data pointers, because it might diverge
// from the mask for code pointers.
statfunc u64 normalize_pac_ptr(u64 ptr) {
    // Retrieve PAC mask from the system config.
    u32 key = 0;
    SystemConfig* syscfg = bpf_map_lookup_elem(&system_config, &key);
    if (!syscfg) {
        // Unreachable: array maps are always fully initialized.
        return ptr;
    }

    // Mask off PAC bits. Since we're always applying this to usermode pointers that should have all
    // the high bits set to 0, we don't need to consider the case of having to fill up the resulting
    // hole with 1s (like we'd have to for kernel ptrs).
    ptr &= syscfg->inverse_pac_mask;
    return ptr;
}
#endif

// Record a native frame
statfunc ErrorCode push_native(StackTrace *trace, u64 pc, u64 file, u64 line, bool return_address) {
    return _push_with_return_address(trace, pc, file, line, FRAME_MARKER_NATIVE, return_address);
}

// Get the outer map based on the number of stack delta entries.
statfunc void *get_stack_delta_map(int mapID) {
    switch (mapID) {
        case  8: return &su_exe_to_8_sd;
        case  9: return &su_exe_to_9_sd;
        case 10: return &su_exe_to_10_sd;
        case 11: return &su_exe_to_11_sd;
        case 12: return &su_exe_to_12_sd;
        case 13: return &su_exe_to_13_sd;
        case 14: return &su_exe_to_14_sd;
        case 15: return &su_exe_to_15_sd;
        case 16: return &su_exe_to_16_sd;
        case 17: return &su_exe_to_17_sd;
        case 18: return &su_exe_to_18_sd;
        case 19: return &su_exe_to_19_sd;
        case 20: return &su_exe_to_20_sd;
        case 21: return &su_exe_to_21_sd;
        default: return NULL;
    }
}

// A single step for the bsearch into the big_stack_deltas array. This is really a textbook bsearch
// step, built in a way to update the value of *lo and *hi. This function will be called repeatedly
// (since we cannot do loops). The return value signals whether the bsearch came to an end / found
// the right element or whether it needs to continue.
statfunc bool bsearch_step(void* inner_map, u32* lo, u32* hi, u16 page_offset) {
    u32 pivot = (*lo + *hi) >> 1;
    StackDelta *delta = bpf_map_lookup_elem(inner_map, &pivot);
    if (!delta) {
        *hi = 0;
        return false;
    }
    if (page_offset >= delta->addrLow)
        *lo = pivot + 1;
    else
        *hi = pivot;
    return *lo < *hi;
}

// Get the stack offset of the given instruction.
statfunc ErrorCode get_stack_delta(NativeUnwindState *state, int *addrDiff, u32 *unwindInfo) {
    u64 exe_id = state->text_section_id;

    // Look up the stack delta page information for this address.
    StackDeltaPageKey key = { };
    key.fileID = state->text_section_id;
    key.page = state->text_section_offset & ~STACK_DELTA_PAGE_MASK;
    DEBUG_PRINT("Look up stack delta for %lx:%lx",
        (unsigned long)state->text_section_id, (unsigned long)state->text_section_offset);
    StackDeltaPageInfo *info = bpf_map_lookup_elem(&su_sd_pg_to_info, &key);
    if (!info) {
        DEBUG_PRINT("Failure to look up stack delta page fileID %lx, page %lx",
                    (unsigned long)key.fileID, (unsigned long)key.page);
        return ERR_NATIVE_LOOKUP_TEXT_SECTION;
    }

    void *outer_map = get_stack_delta_map(info->mapID);
    if (!outer_map) {
        DEBUG_PRINT("Failure to look up outer map for text section %lx in mapID %d",
                    (unsigned long) exe_id, (int) info->mapID);
        return ERR_NATIVE_LOOKUP_STACK_DELTA_OUTER_MAP;
    }

    void *inner_map = bpf_map_lookup_elem(outer_map, &exe_id);
    if (!inner_map) {
        DEBUG_PRINT("Failure to look up inner map for text section %lx",
                    (unsigned long) exe_id);
        return ERR_NATIVE_LOOKUP_STACK_DELTA_INNER_MAP;
    }

    // Preinitialize the idx for the index to use for page without any deltas.
    u32 idx = info->firstDelta;
    u16 page_offset = state->text_section_offset & STACK_DELTA_PAGE_MASK;
    if (info->numDeltas) {
        // Page has deltas, so find the correct one to use using binary search.
        u32 lo = info->firstDelta;
        u32 hi = lo + info->numDeltas;

        DEBUG_PRINT("Intervals should be from %lu to %lu (mapID %d)",
            (unsigned long) lo, (unsigned long) hi, (int)info->mapID);

        // Do the binary search, up to 16 iterations. Deltas are paged to 64kB pages.
        // They can contain at most 64kB deltas even if everything is single byte opcodes.
        int i;
#pragma unroll
        for (i = 0; i < 16; i++) {
            if (!bsearch_step(inner_map, &lo, &hi, page_offset))
                break;
        }
        if (i >= 16 || hi == 0) {
            DEBUG_PRINT("Failed bsearch in 16 steps. Corrupt data?");
            return ERR_NATIVE_EXCEEDED_DELTA_LOOKUP_ITERATIONS;
        }
        // After bsearch, 'hi' points to the first entry greater than the requested.
        idx = hi;
    }

    // The code above found the first entry with greater address than requested,
    // so it needs to be decremented by one to get the entry with equal-or-less.
    // This makes also the logic work cross-pages: if the first entry in within
    // the page is too large, this actually gets the entry from the previous page.
    idx--;

    StackDelta *delta = bpf_map_lookup_elem(inner_map, &idx);
    if (!delta)
        return ERR_NATIVE_LOOKUP_RANGE;

    DEBUG_PRINT("delta index %d, addrLow 0x%x, unwindInfo %d",
        idx, delta->addrLow, delta->unwindInfo);

    // Calculate PC delta from stack delta for merged delta comparison
    int deltaOffset = (int)page_offset - (int)delta->addrLow;
    if (idx < info->firstDelta) {
        // PC is below the first delta of the corresponding page. This means that
        // delta->addrLow contains address relative to one page before the page_offset.
        // Fix up the deltaOffset with this difference of base pages.
        deltaOffset += 1 << STACK_DELTA_PAGE_BITS;
    }

    *addrDiff = deltaOffset;
    *unwindInfo = delta->unwindInfo;

    if (delta->unwindInfo == STACK_DELTA_INVALID) {
        DEBUG_PRINT("invalid stack delta");
        return ERR_NATIVE_STACK_DELTA_INVALID;
    }

    return ERR_OK;
}

// unwind_register_address calculates the given expression ('opcode'/'param') to get
// the CFA (canonical frame address, to recover PC and be used in further calculations),
// or the address where a register is stored (FP currently), so that the value of
// the register can be recovered.
//
// Currently the following expressions are supported:
//   1. Not recoverable -> NULL is returned.
//   2. When UNWIND_OPCODEF_DEREF is not set:
//      BASE + param
//   3. When UNWIND_OPCODEF_DEREF is set:
//      *(BASE + preDeref) + postDeref
statfunc u64 unwind_register_address(NativeUnwindState *state, u64 cfa, u8 opcode, s32 param) {
    unsigned long addr, val;
    s32 preDeref = param, postDeref = 0;

    if (opcode & UNWIND_OPCODEF_DEREF) {
        // For expressions that dereference the base expression, the parameter is constructed
        // of pre-dereference and post-derefence operands. Unpack those.
        preDeref &= ~UNWIND_DEREF_MASK;
        postDeref = (param & UNWIND_DEREF_MASK) * UNWIND_DEREF_MULTIPLIER;
    }

    // Resolve the 'BASE' register, and fetch the CFA/FP/SP value.
    switch (opcode & ~UNWIND_OPCODEF_DEREF) {
        case UNWIND_OPCODE_BASE_CFA:
            addr = cfa;
            break;
        case UNWIND_OPCODE_BASE_FP:
            addr = state->fp;
            break;
        case UNWIND_OPCODE_BASE_SP:
            addr = state->sp;
            break;
#if defined(bpf_target_arm64)
        case UNWIND_OPCODE_BASE_LR:
            DEBUG_PRINT("unwind: lr");

            if (state->lr == 0) {
                DEBUG_PRINT("Failure to unwind frame: zero LR at %llx", state->pc);
                return 0;
            }

            return state->lr;
#endif
#if defined(bpf_target_x86)
        case UNWIND_OPCODE_BASE_REG:
            val = (param & ~UNWIND_REG_MASK) >> 1;
            DEBUG_PRINT("unwind: r%d+%lu", param & UNWIND_REG_MASK, val);
            switch (param & UNWIND_REG_MASK) {
                case 0: // rax
                    addr = state->rax;
                    break;
                case 9: // r9
                    addr = state->r9;
                    break;
                case 11: // r11
                    addr = state->r11;
                    break;
                case 15: // r15
                    addr = state->r15;
                    break;
                default:
                    return 0;
            }
            return addr + val;
#endif
        default:
            return 0;
    }

#ifdef STACK_UNWIND_DEBUG
    switch (opcode) {
        case UNWIND_OPCODE_BASE_CFA:
            DEBUG_PRINT("unwind: cfa+%d", preDeref);
            break;
        case UNWIND_OPCODE_BASE_FP:
            DEBUG_PRINT("unwind: fp+%d", preDeref);
            break;
        case UNWIND_OPCODE_BASE_SP:
            DEBUG_PRINT("unwind: sp+%d", preDeref);
            break;
        case UNWIND_OPCODE_BASE_CFA | UNWIND_OPCODEF_DEREF:
            DEBUG_PRINT("unwind: *(cfa+%d)+%d", preDeref, postDeref);
            break;
        case UNWIND_OPCODE_BASE_FP | UNWIND_OPCODEF_DEREF:
            DEBUG_PRINT("unwind: *(fp+%d)+%d", preDeref, postDeref);
            break;
        case UNWIND_OPCODE_BASE_SP | UNWIND_OPCODEF_DEREF:
            DEBUG_PRINT("unwind: *(sp+%d)+%d", preDeref, postDeref);
            break;
    }
#endif

    // Adjust based on parameter / preDereference adder.
    addr += preDeref;
    if ((opcode & UNWIND_OPCODEF_DEREF) == 0)
        // All done: return "BASE + param"
        return addr;

    // Dereference, and add the postDereference adder.
    if (bpf_probe_read_user(&val, sizeof(val), (void*) addr)) {
        DEBUG_PRINT("unwind failed to dereference address 0x%lx", addr);
        return 0;
    }
    // Return: "*(BASE + preDeref) + postDeref"
    return val + postDeref;
}

// Stack unwinding in the absence of frame pointers can be a bit involved, so
// this comment explains what the following code does.
//
// One begins unwinding a frame somewhere in the middle of execution.
// On x86_64, registers RIP (PC), RSP (SP), and RBP (FP) are available.
//
// This function resolves a "stack delta" command from from our internal maps.
// This stack delta refers to a rule on how to unwind the state. In the simple
// case it just provides SP delta and potentially offset from where to recover
// FP value. See unwind_register_address() on the expressions supported.
//
// The function sets the bool pointed to by the given `stop` pointer to `false`
// if the main ebpf unwinder should exit. This is the case if the current PC
// is marked with UNWIND_COMMAND_STOP which marks entry points (main function,
// thread spawn function, signal handlers, ...).
#if defined(bpf_target_x86)
statfunc ErrorCode unwind_one_frame(u32 frame_idx, NativeUnwindState *state, bool *stop) {
    *stop = false;

    u32 unwindInfo = 0;
    u64 rt_regs[18];
    int addrDiff = 0;
    u64 cfa = 0;

    // The relevant executable is compiled with frame pointer omission, so
    // stack deltas need to be retrieved from the relevant map.
    ErrorCode error = get_stack_delta(state, &addrDiff, &unwindInfo);
    if (error)
        return error;

    if (unwindInfo & STACK_DELTA_COMMAND_FLAG) {
        switch (unwindInfo & ~STACK_DELTA_COMMAND_FLAG) {
            case UNWIND_COMMAND_PLT:
                // The toolchains routinely emit a fixed DWARF expression to unwind the full
                // PLT table with one expression to reduce .eh_frame size.
                // This is the hard coded implementation of this expression. For further details,
                // see https://hal.inria.fr/hal-02297690/document, page 4. (DOI: 10.1145/3360572)
                cfa = state->sp + 8 + ((((state->pc & 15) >= 11) ? 1 : 0) << 3);
                DEBUG_PRINT("PLT, cfa=0x%lx", (unsigned long)cfa);
                break;
            case UNWIND_COMMAND_SIGNAL:
                // The rt_sigframe is defined at:
                // https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/arch/x86/include/asm/sigframe.h?h=v6.4#n59
                // https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/arch/x86/include/uapi/asm/sigcontext.h?h=v6.4#n238
                // offsetof(struct rt_sigframe, uc.uc_mcontext) = 40
                if (bpf_probe_read_user(&rt_regs, sizeof(rt_regs), (void*)(state->sp + 40)))
                    goto err_native_pc_read;
                state->rax = rt_regs[13];
                state->r9 = rt_regs[1];
                state->r11 = rt_regs[3];
                state->r13 = rt_regs[5];
                state->r15 = rt_regs[7];
                state->fp = rt_regs[10];
                state->sp = rt_regs[15];
                state->pc = rt_regs[16];
                state->return_address = false;
                DEBUG_PRINT("signal frame");
                goto frame_ok;
            case UNWIND_COMMAND_STOP:
                *stop = true;
                return ERR_OK;
            default:
                return ERR_UNREACHABLE;
        }
    } 
    else {
        UnwindInfo *info = bpf_map_lookup_elem(&su_info_arr, &unwindInfo);
        if (!info) {
            DEBUG_PRINT("Giving up due to invalid unwind info array index");
            return ERR_NATIVE_BAD_UNWIND_INFO_INDEX;
        }

        s32 param = info->param;
        if (info->mergeOpcode) {
            DEBUG_PRINT("AddrDiff %d, merged delta %#02x", addrDiff, info->mergeOpcode);
            if (addrDiff >= (info->mergeOpcode & ~MERGEOPCODE_NEGATIVE)) {
                param += (info->mergeOpcode & MERGEOPCODE_NEGATIVE) ? -8 : 8;
                DEBUG_PRINT("Merged delta match: cfaDelta=%d", unwindInfo);
            }
        }

        // Resolve the frame's CFA (previous PC is fixed to CFA) address, and
        // the previous FP address if any.
        cfa = unwind_register_address(state, 0, info->opcode, param);
        u64 fpa = unwind_register_address(state, cfa, info->fpOpcode, info->fpParam);

        if (fpa)
            bpf_probe_read_user(&state->fp, sizeof(state->fp), (void*)fpa);
        else if (info->opcode == UNWIND_OPCODE_BASE_FP)
            // FP used for recovery, but no new FP value received, clear FP
            state->fp = 0;
    }

    if (!cfa || bpf_probe_read_user(&state->pc, sizeof(state->pc), (void*)(cfa - 8))) {
err_native_pc_read:
        return ERR_NATIVE_PC_READ;
    }
    state->sp = cfa;
    state->return_address = true;
frame_ok:
    return ERR_OK;
}

#elif defined(bpf_target_arm64)
statfunc ErrorCode unwind_one_frame(u32 frame_idx, struct UnwindState *state, bool *stop) {
    *stop = false;

    u32 unwindInfo = 0;
    int addrDiff = 0;
    u64 rt_regs[34];
    u64 cfa = 0;

    // The relevant executable is compiled with frame pointer omission, so
    // stack deltas need to be retrieved from the relevant map.
    ErrorCode error = get_stack_delta(state, &addrDiff, &unwindInfo);
    if (error)
        return error;

    if (unwindInfo & STACK_DELTA_COMMAND_FLAG) {
        switch (unwindInfo & ~STACK_DELTA_COMMAND_FLAG) {
            case UNWIND_COMMAND_SIGNAL:
                // On aarch64 the struct rt_sigframe is at:
                // https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/arch/arm64/kernel/signal.c?h=v6.4#n39
                // https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/arch/arm64/include/uapi/asm/sigcontext.h?h=v6.4#n28
                // offsetof(struct rt_sigframe, uc.uc_mcontext.regs[0]) = 312
                //   offsetof(struct rt_sigframe, uc)       128 +
                //   offsetof(struct ucontext, uc_mcontext) 176 +
                //   offsetof(struct sigcontext, regs[0])   8
                if (bpf_probe_read_user(&rt_regs, sizeof(rt_regs), (void*)(state->sp + 312)))
                    goto err_native_pc_read;
                state->pc = normalize_pac_ptr(rt_regs[32]);
                state->sp = rt_regs[31];
                state->fp = rt_regs[29];
                state->lr = normalize_pac_ptr(rt_regs[30]);
                state->r22 = rt_regs[22];
                state->return_address = false;
                DEBUG_PRINT("signal frame");
                goto frame_ok;
            case UNWIND_COMMAND_STOP:
                *stop = true;
                return ERR_OK;
            default:
                return ERR_UNREACHABLE;
        }
    }

    UnwindInfo *info = bpf_map_lookup_elem(&su_info_arr, &unwindInfo);
    if (!info) {
        DEBUG_PRINT("Giving up due to invalid unwind info array index");
        return ERR_NATIVE_BAD_UNWIND_INFO_INDEX;
    }

    s32 param = info->param;
    if (info->mergeOpcode) {
        DEBUG_PRINT("AddrDiff %d, merged delta %#02x", addrDiff, info->mergeOpcode);
        if (addrDiff >= (info->mergeOpcode & ~MERGEOPCODE_NEGATIVE)) {
            param += (info->mergeOpcode & MERGEOPCODE_NEGATIVE) ? -8 : 8;
            DEBUG_PRINT("Merged delta match: cfaDelta=%d", unwindInfo);
        }
    }

    // Resolve the frame CFA (previous PC is fixed to CFA) address
    cfa = unwind_register_address(state, 0, info->opcode, param);

    // Resolve Return Address, it is either the value of link register or
    // stack address where RA is stored
    u64 ra = unwind_register_address(state, cfa, info->fpOpcode, info->fpParam);
    if (ra) {
        if (info->fpOpcode == UNWIND_OPCODE_BASE_LR) {
            // Allow LR unwinding only if it's known to be valid: either because
            // it's the topmost user-mode frame, or recovered by signal trampoline.
            if (state->return_address)
                return ERR_NATIVE_LR_UNWINDING_MID_TRACE;

            // set return address location to link register
            state->pc = ra;
        }
        else {
            DEBUG_PRINT("RA: %016llX", (u64)ra);

            // read the value of RA from stack
            if (bpf_probe_read_user(&state->pc, sizeof(state->pc), (void*)ra))
                // error reading memory, mark RA as invalid
                ra = 0;
        }

        state->pc = normalize_pac_ptr(state->pc);
    }

    if (!ra) {
err_native_pc_read:
        // report failure to resolve RA and stop unwinding
        DEBUG_PRINT("Giving up due to failure to resolve RA");
        return ERR_NATIVE_PC_READ;
    }

    // Try to resolve frame pointer
    // simple heuristic for FP based frames
    // the GCC compiler usually generates stack frame records in such a way,
    // so that FP/RA pair is at the bottom of a stack frame (stack frame
    // record at lower addresses is followed by stack vars at higher ones)
    // this implies that if no other changes are applied to the stack such
    // as alloca(), following the prolog SP/FP points to the frame record
    // itself, in such a case FP offset will be equal to 8
    if (info->fpParam == 8) {
        // we can assume the presence of frame pointers
        if (info->fpOpcode != UNWIND_OPCODE_BASE_LR)
            // FP precedes the RA on the stack (Aarch64 ABI requirement)
            bpf_probe_read_user(&state->fp, sizeof(state->fp), (void*)(ra - 8));
    }

    state->sp = cfa;
    state->return_address = true;
frame_ok:
    return ERR_OK;
}
#else
#error unsupported architecture
#endif

statfunc void unwind_native(void *ctx, stack_unwind_state_t *state, StackTrace *trace, enum bpf_prog_type prog_type)
{
    int unwinder;
    ErrorCode error;

#pragma unroll
    for (int i = 0; i < NATIVE_FRAMES_PER_PROGRAM; i++) {
        unwinder = PROG_UNWIND_STOP;

        // Unwind native code
        u32 frame_idx = trace->metadata.stack_len;
        DEBUG_PRINT("==== unwind_native %d ====", frame_idx);

        // Push frame first. The PC is valid because a text section mapping was found.
        DEBUG_PRINT("Pushing %llx %llx to position %u on stack",
                    state->native_state.text_section_id, state->native_state.text_section_offset,
                    trace->metadata.stack_len);
        error = push_native(trace, state->native_state.pc, state->native_state.text_section_id, state->native_state.text_section_offset,
            state->native_state.return_address);
        if (error) {
            DEBUG_PRINT("failed to push native frame");
            break;
        }

        // Unwind the native frame using stack deltas. Stop if no next frame.
        bool stop;
        error = unwind_one_frame(frame_idx, &state->native_state, &stop);
        if (error || stop)
            break;
        
        // Continue unwinding
        DEBUG_PRINT(" pc: %llx sp: %llx fp: %llx", state->native_state.pc, state->native_state.sp, state->native_state.fp);
        error = get_next_unwinder_after_native_frame(state, trace, &unwinder);
        if (error || unwinder != PROG_UNWIND_NATIVE)
            break;
    }

    // Tail call needed for recursion, switching to interpreter unwinder, or reporting
    // trace due to end-of-trace or error. The unwinder program index is set accordingly.
    state->unwind_error = error;
    error = unwind_tail_call(ctx, unwinder, prog_type);
    DEBUG_PRINT("tail call failed for %d in unwind_native: %u", unwinder, error);

    // if the tail call failed, override any previous error
    state->unwind_error = error;
}

statfunc ErrorCode copy_state_regs(NativeUnwindState *state, struct pt_regs *regs, bool interrupted_kernel)
{
#if defined(bpf_target_x86)
    // Check if the process is running in 32-bit mode on the x86_64 system.
    // This check follows the Linux kernel implementation of user_64bit_mode() in
    // arch/x86/include/asm/ptrace.h.
    if (regs->cs == __USER32_CS) {
        return ERR_NATIVE_X64_32BIT_COMPAT_MODE;
    }
    state->pc = regs->ip;
    state->sp = regs->sp;
    state->fp = regs->bp;
    state->rax = regs->ax;
    state->r9 = regs->r9;
    state->r11 = regs->r11;
    state->r13 = regs->r13;
    state->r15 = regs->r15;

    // Treat syscalls as return addresses, but not IRQ handling, page faults, etc..
    // https://github.com/torvalds/linux/blob/2ef5971ff3/arch/x86/include/asm/syscall.h#L31-L39
    // https://github.com/torvalds/linux/blob/2ef5971ff3/arch/x86/entry/entry_64.S#L847
    state->return_address = interrupted_kernel && regs->orig_ax != -1;
#elif defined(bpf_target_arm64)
    // For backwards compatibility aarch64 can run 32-bit code.
    // Check if the process is running in this 32-bit compat mod.
    if (regs->pstate & PSR_MODE32_BIT) {
        return ERR_NATIVE_AARCH64_32BIT_COMPAT_MODE;
    }
    state->pc = normalize_pac_ptr(regs->pc);
    state->sp = regs->sp;
    state->fp = regs->regs[29];
    state->lr = normalize_pac_ptr(regs->regs[30]);
    state->r22 = regs->regs[22];

    // Treat syscalls as return addresses, but not IRQ handling, page faults, etc..
    // https://github.com/torvalds/linux/blob/2ef5971ff3/arch/arm64/include/asm/ptrace.h#L118
    // https://github.com/torvalds/linux/blob/2ef5971ff3/arch/arm64/include/asm/ptrace.h#L206-L209
    state->return_address = interrupted_kernel && regs->syscallno != -1;
#endif

  return ERR_OK;
}

statfunc void unwind_start(void *ctx, stack_unwind_state_t *state, StackTrace *trace, enum bpf_prog_type prog_type)
{   
    ErrorCode error = ERR_OK;
    int unwinder = PROG_UNWIND_STOP;

    // Get the kernel stack trace first
    // TODO: stacks with the same ID may result in a race condition where the stack is cleared from user space
    // after another event reuses the ID, so the stack is not available to user space when processing the second event.
    // To get around this we should probably use `bpf_get_stack` and save it to the event buffer.
    trace->metadata.kernel_stack_id = bpf_get_stackid(ctx, &su_kern_stacks, BPF_F_REUSE_STACKID);
    DEBUG_PRINT("kernel stack id = %d", trace->metadata.kernel_stack_id);

    // not in task context
    if ((bpf_get_current_pid_tgid() >> 32) == 0) {
        error = ERR_CONTEXT;
        goto exit;
    }

    // this is kernel thread, no user stack unwinding needs to be performed
    struct task_struct *task = (struct task_struct *) bpf_get_current_task();
    if (task == NULL) {
        DEBUG_PRINT("can't get task");
        error = ERR_UNKNOWN;
        goto exit;
    }
    if (get_task_flags(task) & PF_KTHREAD)
        goto exit;

    // Recursive unwind frames
    struct pt_regs *user_regs = get_current_task_pt_regs();
    if (user_regs == NULL) {
        DEBUG_PRINT("can't get user regs");
        error = ERR_UNKNOWN;
        goto exit;
    }

    error = copy_state_regs(&state->native_state, user_regs, state->interrupted_kernel);
    if (error != ERR_OK) {
        goto exit;
    }

    error = get_next_unwinder_after_native_frame(state, trace, &unwinder);

exit:
    state->unwind_error = error;
    error = unwind_tail_call(ctx, unwinder, prog_type);
    DEBUG_PRINT("tail call failed for %d in unwind_start: %u", unwinder, error);

    // if the tail call failed, override any previous error
    state->unwind_error = error;
}