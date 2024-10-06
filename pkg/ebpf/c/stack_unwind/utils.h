#ifndef __STACK_UNWIND_UTILS_H__
#define __STACK_UNWIND_UTILS_H__

//#define STACK_UNWIND_DEBUG

#ifdef STACK_UNWIND_DEBUG
#define DEBUG_PRINT(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)
#else
#define DEBUG_PRINT(fmt, ...)
#endif

// The following works with clang and gcc.
// Checked with
//    clang -dM -E -x c /dev/null | grep ENDI
//      gcc -dM -E -x c /dev/null | grep ENDI
#if defined __BYTE_ORDER__ && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define __constant_cpu_to_be32(x) __builtin_bswap32(x)
#define __constant_cpu_to_be64(x) __builtin_bswap64(x)
#elif defined __BYTE_ORDER__ && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define __constant_cpu_to_be32(x) (x)
#define __constant_cpu_to_be64(x) (x)
#else
#error "Unknown endianness"
#endif

#endif /* __STACK_UNWIND_UTILS_H__ */