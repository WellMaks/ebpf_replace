#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);    // PID as key
    __type(value, int);  // File descriptor as value
    __uint(max_entries, 256);
} pid_fd_map SEC(".maps");

static __always_inline int strncmp(const char *s1, const char *s2, int n) {
    for (int i = 0; i < n; ++i) {
        if (s1[i] != s2[i] || s1[i] == '\0')
            return s1[i] - s2[i];
    }
    return 0;
}

const volatile int pid_target = 0;
const volatile char target_filename[] = "/etc/passwd";

SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint__syscalls__sys_enter_openat(struct trace_event_raw_sys_enter* ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    char filename[256] = {};

    if (pid_target && pid_target != pid)
        return 0;

    bpf_probe_read_user(&filename, sizeof(filename), (void*)ctx->args[1]);

    if (strncmp(filename, target_filename, sizeof(target_filename) - 1) == 0) {
        // Save the fd to the map, using PID as the key
        int fd = ctx->args[0]; // The file descriptor is the first argument of sys_openat
        bpf_map_update_elem(&pid_fd_map, &pid, &fd, BPF_ANY);
        bpf_printk("PID %d opened target file: %s with fd %d\n", pid, filename, fd);
    }

    return 0;
}

SEC("kretprobe/__x64_sys_write")
int kretprobe__sys_write(struct pt_regs *ctx) {
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    ssize_t ret = PT_REGS_RC(ctx);

    if (ret > 0) {
        int* fd_ptr = bpf_map_lookup_elem(&pid_fd_map, &pid);
        if (fd_ptr) {
            bpf_printk("PID %d wrote %ld bytes using fd %d\n", pid, ret, *fd_ptr);
        }
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";