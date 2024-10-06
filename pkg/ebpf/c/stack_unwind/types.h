#ifndef __STACK_UNWIND_TYPES_H__
#define __STACK_UNWIND_TYPES_H__

#include <vmlinux.h>

#include <common/common.h>

#include "errors.h"

// TracePrograms provide the offset for each eBPF trace program in the
// map that holds them.
// The values of this enum must fit in a single byte.
typedef enum TracePrograms {
    PROG_UNWIND_STOP = 0,
    PROG_UNWIND_NATIVE,
    PROG_UNWIND_HOTSPOT,
    PROG_UNWIND_PERL,
    PROG_UNWIND_PYTHON,
    PROG_UNWIND_PHP,
    PROG_UNWIND_RUBY,
    PROG_UNWIND_V8,
    PROG_UNWIND_DOTNET,
    NUM_TRACER_PROGS,
} TracePrograms;

// MAX_FRAME_UNWINDS defines the maximum number of frames per
// Trace we can unwind and respect the limit of eBPF instructions,
// limit of tail calls and limit of stack size per eBPF program.
#define MAX_FRAME_UNWINDS 128

// MAX_NON_ERROR_FRAME_UNWINDS defines the maximum number of frames
// to be pushed by unwinders while still leaving space for an error frame.
// This is used to make sure that there is always space for an error
// frame reporting that we ran out of stack space.
#define MAX_NON_ERROR_FRAME_UNWINDS (MAX_FRAME_UNWINDS - 1)

typedef struct stack_trace_metadata {
    // The kernel stack ID.
    s32 kernel_stack_id;
    // The number of frames in the stack.
    u32 stack_len;
} stack_trace_metadata_t;

// Type to represent a globally-unique file id to be used as key for a BPF hash map
typedef u64 FileID;

// Individual frame in a stack-trace.
typedef struct StackFrame {
    // Instruction pointer / program counter
    u64 pc;
    // IDs that uniquely identify a file combination
    FileID file_id;
    // For PHP this is the line numbers, corresponding to the files in `stack`.
    // For Python, each value provides information to allow for the recovery of
    // the line number associated with its corresponding offset in `stack`.
    // The lower 32 bits provide the co_firstlineno value and the upper 32 bits
    // provide the f_lasti value. Other interpreter handlers use the field in
    // a similarly domain-specific fashion.
    u64 addr_or_line;
    // Indicates the type of the frame (Python, PHP, native etc.).
    u8 kind;
    // Indicates that the address is a return address.
    u8 return_address;
    // Explicit padding bytes that the compiler would have inserted anyway.
    // Here to make it clear to readers that there are spare bytes that could
    // be put to work without extra cost in case an interpreter needs it.
    u8 pad[6];
} StackFrame;

_Static_assert(sizeof(StackFrame) == 4 * 8, "frame padding not working as expected");

// Container for a stack trace
typedef struct StackTrace {
    stack_trace_metadata_t metadata;
    // The frames of the stack trace.
    StackFrame frames[MAX_FRAME_UNWINDS];
    // NOTE: frames must be the last element
} StackTrace;

// Container for unwinding state
typedef struct NativeUnwindState {
    // Current register value for Program Counter
    u64 pc;
    // Current register value for Stack Pointer
    u64 sp;
    // Current register value for Frame Pointer
    u64 fp;

#if defined(bpf_target_x86)
    // Current register values for named registers
    u64 rax, r9, r11, r13, r15;
#elif defined(bpf_target_arm64)
    // Current register values for named registers
    u64 lr, r22;
#endif

    // The executable ID/hash associated with PC
    u64 text_section_id;
    // PC converted into the offset relative to the executables text section
    u64 text_section_offset;
    // The current mapping load bias
    u64 text_section_bias;

    // Set if the PC is a return address. That is, it points to the next instruction
    // after a CALL instruction, and requires to be adjusted during symbolization.
    // On aarch64, this additionally means that LR register can not be used.
    bool return_address;
} NativeUnwindState;

// Container for unwinding state needed by the Perl unwinder. Keeping track of
// current stackinfo, first seen COP, and the info about current context stack.
typedef struct PerlUnwindState {
    /*// Pointer to the next stackinfo to unwind
    const void *stackinfo;
    // First Control OP seen for the frame filename/linenumber info for next function frame
    const void *cop;
    // Current context state, pointer to the base and current entries
    const void *cxbase, *cxcur;*/
} PerlUnwindState;

// Container for unwinding state needed by the Python unwinder. At the moment
// the only thing we need to pass between invocations of the unwinding programs
// is the pointer to the next PyFrameObject to unwind.
typedef struct PythonUnwindState {
    /*// Pointer to the next PyFrameObject to unwind
    void *py_frame;*/
} PythonUnwindState;

// Container for unwinding state needed by the PHP unwinder. At the moment
// the only thing we need to pass between invocations of the unwinding programs
// is the pointer to the next zend_execute_data to unwind.
typedef struct PHPUnwindState {
    /*// Pointer to the next zend_execute_data to unwind
    const void *zend_execute_data;*/
} PHPUnwindState;

// Container for unwinding state needed by the Ruby unwinder.
typedef struct RubyUnwindState {
    /*// Pointer to the next control frame struct in the Ruby VM stack we want to unwind.
    void *stack_ptr;
    // Pointer to the last control frame struct in the Ruby VM stack we want to handle.
    void *last_stack_frame;*/
} RubyUnwindState;

// Container for additional scratch space needed by the HotSpot unwinder.
typedef struct DotnetUnwindScratchSpace {
    /*// Buffer to read nibble map to locate code start. One map entry allows seeking backwards
    // 32*8 = 256 bytes of code. This defines the maximum size for a JITted function we
    // can recognize: 256 bytes/element * 128 elements = 32kB function size.
    u32 map[128];
    // Extra space to read to map fixed amount of bytes, but to dynamic offset.
    u32 extra[128];*/
} DotnetUnwindScratchSpace;

// Container for additional scratch space needed by the HotSpot unwinder.
typedef struct HotspotUnwindScratchSpace {
    /*// Read buffer for storing the codeblob. It's not needed across calls, but the buffer is too
    // large to be allocated on stack. With my debug build of JDK17, the largest possible variant of
    // codeblob that we care about (nmethod) is 376 bytes in size. 512 bytes should thus be plenty.
    u8 codeblob[512];*/
} HotspotUnwindScratchSpace;

// The number of bytes read from frame pointer for V8 context
#define V8_FP_CONTEXT_SIZE 64

// Container for additional scratch space needed by the V8 unwinder.
typedef struct V8UnwindScratchSpace {
    /*// Read buffer for storing the V8 FP stored context. Needs to be in non-stack
    // area to allow variable indexing.
    u8 fp_ctx[V8_FP_CONTEXT_SIZE];
    // Read buffer for V8 Code object. Currently we need about 60 bytes to get
    // code instruction_size and flags.
    u8 code[96];*/
} V8UnwindScratchSpace;

// Container for additional scratch space needed by the Python unwinder.
typedef struct PythonUnwindScratchSpace {
    /*// Read buffer for storing the PyInterpreterFrame (PyFrameObject).
    // Python 3.11 is about 80 bytes, but Python 3.7 has larger requirement.
    u8 frame[128];
    // Read buffer for storing the PyCodeObject. Currently we need 148 bytes of the header. But
    // the structure is 192 bytes in Python 3.11.
    u8 code[192];*/
} PythonUnwindScratchSpace;

// Per-CPU info for the stack being built. This contains the stack as well as
// meta-data on the number of eBPF tail-calls used so far to construct it.
typedef struct stack_unwind_state {
    // Whether this probe was triggered in kernel context or user context (uprobe)
    bool interrupted_kernel;
    // The current unwind state.
    NativeUnwindState native_state;
    // The current Perl unwinder state
    PerlUnwindState perlUnwindState;
    // The current Python unwinder state.
    PythonUnwindState pythonUnwindState;
    // The current PHP unwinder state.
    PHPUnwindState phpUnwindState;
    // The current Ruby unwinder state.
    RubyUnwindState rubyUnwindState;
    union {
        // Scratch space for the Dotnet unwinder.
        DotnetUnwindScratchSpace dotnetUnwindScratch;
        // Scratch space for the HotSpot unwinder.
        HotspotUnwindScratchSpace hotspotUnwindScratch;
        // Scratch space for the V8 unwinder
        V8UnwindScratchSpace v8UnwindScratch;
        // Scratch space for the Python unwinder
        PythonUnwindScratchSpace pythonUnwindScratch;
    };
    // Mask to indicate which unwinders are complete
    u32 unwindersDone;

    // tailCalls tracks the number of calls to bpf_tail_call().
    //u8 tailCalls;

    // If unwinding was aborted due to an error, this contains the reason why.
    ErrorCode unwind_error;
} stack_unwind_state_t;

// UnwindInfo contains the unwind information needed to unwind one frame
// from a specific address.
typedef struct UnwindInfo {
    u8 opcode;       // main opcode to unwind CFA
    u8 fpOpcode;     // opcode to unwind FP
    u8 mergeOpcode;  // opcode for generating next stack delta, see below
    s32 param;       // parameter for the CFA expression
    s32 fpParam;     // parameter for the FP expression
} UnwindInfo;

// The 8-bit mergeOpcode consists of two separate fields:
//  1 bit   the adjustment to 'param' is negative (-8), if not set positive (+8)
//  7 bits  the difference to next 'addrLow'
#define MERGEOPCODE_NEGATIVE 0x80

// An array entry that we will bsearch into that keeps address and stack unwind
// info, per executable.
typedef struct StackDelta {
    u16 addrLow;    // the low 16-bits of the ELF virtual address to which this stack delta applies
    u16 unwindInfo; // index of UnwindInfo, or UNWIND_COMMAND_* if STACK_DELTA_COMMAND_FLAG is set
} StackDelta;

// unwindInfo flag indicating that the value is UNWIND_COMMAND_* value and not an index to
// the unwind info array. When UnwindInfo.opcode is UNWIND_OPCODE_COMMAND the 'param' gives
// the UNWIND_COMMAND_* which describes the exact handling for this stack delta (all
// CFA/PC/FP recovery, or stop condition), and the eBPF code needs special code to handle it.
// This basically serves as a minor optimization to not take a slot from unwind info array,
// nor require a table lookup for these special cased stack deltas.
#define STACK_DELTA_COMMAND_FLAG 0x8000

// Command without arguments, the argument is instead an UNWIND_COMMAND_* value
#define UNWIND_OPCODE_COMMAND   0x00
// Expression with base value being the Canonical Frame Address (CFA)
#define UNWIND_OPCODE_BASE_CFA  0x01
// Expression with base value being the Stack Pointer
#define UNWIND_OPCODE_BASE_SP   0x02
// Expression with base value being the Frame Pointer
#define UNWIND_OPCODE_BASE_FP   0x03
// Expression with base value being the Link Register (ARM64)
#define UNWIND_OPCODE_BASE_LR	0x04
// Expression with base value being a Generic Register
#define UNWIND_OPCODE_BASE_REG	0x05
// An opcode flag to indicate that the value should be dereferenced
#define UNWIND_OPCODEF_DEREF    0x80

// Unsupported or no value for the register
#define UNWIND_COMMAND_INVALID  0
// For CFA: stop unwinding, this function is a stack root function
#define UNWIND_COMMAND_STOP     1
// Unwind a PLT entry
#define UNWIND_COMMAND_PLT      2
// Unwind a signal frame
#define UNWIND_COMMAND_SIGNAL   3

// If opcode has UNWIND_OPCODEF_DEREF set, the lowest bits of 'param' are used
// as second adder as post-deref operation. This contains the mask for that.
// This assumes that stack and CFA are aligned to register size, so that the
// lowest bits of the offsets are always unset.
#define UNWIND_DEREF_MASK       7

// The argument after dereference is multiplied by this to allow some range.
// This assumes register size offsets are used.
#define UNWIND_DEREF_MULTIPLIER 8

// For the UNWIND_OPCODE_BASE_REG, the bitmask reserved for the register
// number. Remaining bits are the offset.
#define UNWIND_REG_MASK         15

// StackDeltaPageKey is the look up key for stack delta page map.
typedef struct StackDeltaPageKey {
    u64 fileID;
    u64 page;
} StackDeltaPageKey;

// StackDeltaPageInfo contains information of stack delta page so the correct map
// and range of StackDelta entries can be found.
typedef struct StackDeltaPageInfo {
    u32 firstDelta;
    u16 numDeltas;
    u16 mapID;
} StackDeltaPageInfo;

// Keep stack deltas in 64kB pages to limit search space and to fit the low address
// bits into the addrLow field of struct StackDelta.
#define STACK_DELTA_PAGE_BITS 16

// The binary mask for STACK_DELTA_PAGE_BITS, which can be used to and/nand an address
// for its page number and offset within that page.
#define STACK_DELTA_PAGE_MASK ((1 << STACK_DELTA_PAGE_BITS) - 1)

// In order to determine whether a given PC falls into the main interpreter loop
// of an interpreter, we need to store some data: The lower boundary of the loop,
// the upper boundary of the loop, and the relevant index to call in the prog
// array.
typedef struct OffsetRange {
    u64 lower_offset;
    u64 upper_offset;
    u16 program_index;  // The interpreter-specific program index to call.
} OffsetRange;

// PIDPage represents the key of the eBPF map pid_page_to_mapping_info.
typedef struct PIDPage {
    u32 prefixLen;    // Number of bits for pid and page that defines the
                        // longest prefix.

    __be32 pid;       // Unique ID of the process.
    __be64 page;      // Address to a certain part of memory within PID.
} PIDPage;

// BIT_WIDTH_PID defines the number of bits used in the value pid of the PIDPage struct.
#define BIT_WIDTH_PID  32
// BIT_WIDTH_PAGE defines the number of bits used in the value page of the PIDPage struct.
#define BIT_WIDTH_PAGE 64

// PIDPageMappingInfo represents the value of the eBPF map pid_page_to_mapping_info.
typedef struct PIDPageMappingInfo {
    u64 file_id;                  // Unique identifier for the executable file

        // Load bias (7 bytes) + unwinding program to use (1 byte, shifted 7 bytes to the left), encoded in a u64.
        // We can do so because the load bias is for userspace addresses, for which the most significant byte is always 0 on
        // relevant architectures.
        // This encoding may have to be changed if bias can be negative.
    u64 bias_and_unwind_program;
} PIDPageMappingInfo;

// Reads a bias_and_unwind_program value from PIDPageMappingInfo
statfunc void decode_bias_and_unwind_program(u64 bias_and_unwind_program, u64 *bias, int *unwind_program) {
    *bias = bias_and_unwind_program & 0x00FFFFFFFFFFFFFF;
    *unwind_program = bias_and_unwind_program >> 56;
}

// Defines the bit mask that, when ORed with it, turn any of the below
// frame types into an error frame.
#define FRAME_MARKER_ERROR_BIT     0x80

// Indicates that the interpreter/runtime this frame belongs to is unknown.
#define FRAME_MARKER_UNKNOWN       0x0
// Indicates a Python frame
#define FRAME_MARKER_PYTHON        0x1
// Indicates a PHP frame
#define FRAME_MARKER_PHP           0x2
// Indicates a native frame
#define FRAME_MARKER_NATIVE        0x3
// Indicates a kernel frame
#define FRAME_MARKER_KERNEL        0x4
// Indicates a HotSpot frame
#define FRAME_MARKER_HOTSPOT       0x5
// Indicates a Ruby frame
#define FRAME_MARKER_RUBY          0x6
// Indicates a Perl frame
#define FRAME_MARKER_PERL          0x7
// Indicates a V8 frame
#define FRAME_MARKER_V8            0x8
// Indicates a PHP JIT frame
#define FRAME_MARKER_PHP_JIT       0x9
// Indicates a Dotnet frame
#define FRAME_MARKER_DOTNET        0xA

// Indicates a frame containing information about a critical unwinding error
// that caused further unwinding to be aborted.
#define FRAME_MARKER_ABORT         (0x7F | FRAME_MARKER_ERROR_BIT)

// HotSpot frame subtypes stored in a bitfield of the trace->lines[]
#define FRAME_HOTSPOT_STUB         0
#define FRAME_HOTSPOT_VTABLE       1
#define FRAME_HOTSPOT_INTERPRETER  2
#define FRAME_HOTSPOT_NATIVE       3

#endif /* __STACK_UNWIND_TYPES_H__ */