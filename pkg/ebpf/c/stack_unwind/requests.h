#ifndef __STACK_UNWIND_REQUESTS_H__
#define __STACK_UNWIND_REQUESTS_H__

#include <common/common.h>
#include <common/task.h>
#include <common/filesystem.h>

#include <bpf/bpf_helpers.h>

#define MAX_FILE_PATH_SIZE 4096

//
// Prototypes
//

statfunc void stack_unwind_request_add_mapping(void *ctx, struct file *file, u64 address, u64 length, u64 prot, u64 file_offset);
statfunc void stack_unwind_request_remove_mapping(void *ctx, u64 address);
statfunc void stack_unwind_request_remove_process(void *ctx);

//
// Structs
//

enum stack_unwind_request_type {
    REQUEST_ADD_FILE_MAPPING,
    REQUEST_ADD_ANONYMOUS_MAPPING,
    REQUEST_REMOVE_MAPPING,
    REQUEST_REMOVE_PROCESS,
    MAX_REQUEST = REQUEST_REMOVE_PROCESS
};

struct file_mapping_metadata {
    u64 file_offset;
    u32 mnt_ns;
    u32 dev;
    u64 ino;
    u64 mtime;
    u32 path_len;
} __attribute__((packed));

_Static_assert(sizeof(struct file_mapping_metadata) == 36, "struct file_mapping_metadata not expeceted size");

struct request_info_file_mapping {
    struct file_mapping_metadata metadata;
    char file_path[MAX_FILE_PATH_SIZE];
};

// Contains information supplied by stack unwind management requests.
struct stack_unwind_request {
    // Used by all requests
    u32 type;
    pid_t tgid;
    // Used by REQUEST_ADD_FILE_MAPPING, REQUEST_ADD_ANONYMOUS_MAPPING, REQUEST_REMOVE_MAPPING
    u64 address;
    // Used by REQUEST_ADD_FILE_MAPPING, REQUEST_ADD_ANONYMOUS_MAPPING
    u64 length;
    // Used by REQUEST_ADD_FILE_MAPPING
    // WARNING: this must be last, as it ends with a buffer that is not sent in its entirety
    struct request_info_file_mapping file_mapping;
};

//
// Maps
//

// Map for holding a temporary `struct stack_unwind_request`
// because it's too big to fit on the bpf stack
struct stack_unwind_request_tmp_storage {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct stack_unwind_request);
} su_request_tmp SEC(".maps");

struct stack_unwind_requests {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, /*1024*/32);
    __type(key, s32);
    __type(value, u32);
} su_requests SEC(".maps");

//
// Functions
//

statfunc void send_stack_unwind_request(void *ctx, struct stack_unwind_request *request)
{
    u32 req = request->type;
    if (req > MAX_REQUEST)
        return;
    
    // Calculate request size
    u64 size = sizeof(request->type) + sizeof(request->tgid);
    if (req == REQUEST_REMOVE_PROCESS)
        goto send;
    size += sizeof(request->address);
    if (req == REQUEST_REMOVE_MAPPING)
        goto send;
    size += sizeof(request->length);
    if (req == REQUEST_ADD_ANONYMOUS_MAPPING)
        goto send;
    size += sizeof(request->file_mapping.metadata) + request->file_mapping.metadata.path_len;

send:
    // inline bounds check to force compiler to use the register of size
    asm volatile("if %[size] < %[max_size] goto +1;\n"
                 "%[size] = %[max_size];\n"
                 :
                 : [size] "r"(size), [max_size] "i"(sizeof(*request)));
    bpf_perf_event_output(ctx, &su_requests, BPF_F_CURRENT_CPU, request, size);
}

statfunc void stack_unwind_request_add_mapping(void *ctx, struct file *file, u64 address, u64 length, u64 prot, u64 file_offset)
{
    if ((prot & VM_EXEC) == 0)
        // Not an executable mapping
        return;
    
    struct task_struct *task = (struct task_struct *) bpf_get_current_task();
    if (unlikely(task == NULL))
        return;
    
    int zero = 0;
    struct stack_unwind_request *request = bpf_map_lookup_elem(&su_request_tmp, &zero);
    if (unlikely(request == NULL))
        return;
    
    request->tgid = bpf_get_current_pid_tgid() >> 32;
    request->address = address;
    request->length = length;

    if (file == NULL)
        //request->type = REQUEST_ADD_ANONYMOUS_MAPPING;
        return;
    else {
        request->type = REQUEST_ADD_FILE_MAPPING;
        request->file_mapping.metadata.file_offset = file_offset;
        request->file_mapping.metadata.mnt_ns = get_task_mnt_ns_id(task);
        request->file_mapping.metadata.dev = get_dev_from_file(file);
        request->file_mapping.metadata.ino = get_inode_nr_from_file(file);
        request->file_mapping.metadata.mtime = get_mtime_nanosec_from_file(file);
        void *file_path = get_path_str(__builtin_preserve_access_index(&file->f_path));
        long len = bpf_probe_read_str(&request->file_mapping.file_path, sizeof(request->file_mapping.file_path), file_path);
        if (len == sizeof(request->file_mapping.file_path))
            // The destination buffer was filled, assume that the actual path is longer which makes this request invalid
            return;
        request->file_mapping.metadata.path_len = (u32) len;
    }

    send_stack_unwind_request(ctx, request);
}

statfunc void stack_unwind_request_remove_mapping(void *ctx, u64 address)
{
    int zero = 0;
    struct stack_unwind_request *request = bpf_map_lookup_elem(&su_request_tmp, &zero);
    if (unlikely(request == NULL))
        return;
    
    request->type = REQUEST_REMOVE_MAPPING;
    request->tgid = bpf_get_current_pid_tgid() >> 32;
    request->address = address;

    send_stack_unwind_request(ctx, request);
}

statfunc void stack_unwind_request_remove_process(void *ctx)
{
    int zero = 0;
    struct stack_unwind_request *request = bpf_map_lookup_elem(&su_request_tmp, &zero);
    if (unlikely(request == NULL))
        return;
    
    request->type = REQUEST_REMOVE_PROCESS;
    request->tgid = bpf_get_current_pid_tgid() >> 32;

    send_stack_unwind_request(ctx, request);
}

#endif /* __STACK_UNWIND_REQUESTS_H__ */