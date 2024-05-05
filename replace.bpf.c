#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, size_t);
    __type(value, unsigned int);
} map_fds SEC(".maps");

#define MAX_FILENAME_LEN 256
const int filename_len = 15; 
const char filename[] = "/etc/aaabbb.txt";

const int pid_target = 0; 

SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint__syscalls__sys_enter_openat(struct trace_event_raw_sys_enter* ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;

    if (pid_target && pid_target != pid)
        return 0;

    char check_filename[MAX_FILENAME_LEN];
    bpf_probe_read_user(&check_filename, filename_len, (char*)ctx->args[1]);

    // Check if the filename matches
    for(int i = 0; i <= filename_len; i++){  
        if (check_filename[i] != filename[i])
            return 0;
    }

    unsigned int zero = 0;
    bpf_map_update_elem(&map_fds, &id, &zero, BPF_ANY);
    bpf_printk("Match found for PID %d and filename %s\n", pid, check_filename);

    return 0;
}

SEC("tp/syscalls/sys_exit_openat")
int handle_openat_exit(struct trace_event_raw_sys_exit *ctx)
{
        size_t id = bpf_get_current_pid_tgid();
    unsigned int* check = bpf_map_lookup_elem(&map_fds, &id);
    if (check == 0) {
        return 0;
    }
    int pid = id >> 32;

    unsigned int fd = (unsigned int)ctx->ret;
    bpf_map_update_elem(&map_fds, &id, &fd, BPF_ANY);

    return 0;
}

SEC("tp/syscalls/sys_enter_read")
int handle_read_enter(struct trace_event_raw_sys_enter *ctx)
{
    size_t id = bpf_get_current_pid_tgid();
    unsigned int* check = bpf_map_lookup_elem(&map_fds, &id);
    if (check == 0) {
        return 0;
    }
    int pid = id >> 32;

    unsigned int fd = *check;
    if (fd != (unsigned int)ctx->args[0]) {
        return 0;
    }

    bpf_printk("Read syscall by PID %d on FD %d\n", pid, fd);

    return 0;

}

// modify the file so i can read the content of the file in the printk
SEC("tp/syscalls/sys_exit_read")
int handle_read_exit(struct trace_event_raw_sys_exit *ctx)
{
    size_t id = bpf_get_current_pid_tgid();
    unsigned int* check = bpf_map_lookup_elem(&map_fds, &id);
    if (check == 0) {
        return 0;
    }
    int pid = id >> 32;

    unsigned int fd = *check;

    const char replacement[] = "Replacement text";
    int ret = bpf_probe_write_user((void*)ctx->ret, replacement, sizeof(replacement));
    if (ret != 0) {
        bpf_printk("Failed to write replaced content for PID %d and FD %d\n", pid, fd);
        return 0;
    }

    bpf_printk("Read syscall by PID %d on FD %d returned %d bytes\n", pid, fd, (int)ctx->ret);
    bpf_printk("Replaced content: %s\n", replacement);

    return 0;
}


char LICENSE[] SEC("license") = "GPL";
