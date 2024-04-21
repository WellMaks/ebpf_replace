#include <stdio.h>
#include <unistd.h>
#include "replace.skel.h"
#include <bpf/libbpf.h>

int main() {
    struct replace_bpf *skel;
    int err;

    skel = replace_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    err = replace_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton\n");
        return 1;
    }

    err = replace_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        return 1;
    }

    printf("Successfully started! Press CTRL+C to stop.\n");
    while (1) {
        sleep(1);
    }

    replace_bpf__destroy(skel);
    return 0;
}
