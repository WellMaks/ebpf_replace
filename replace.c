#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "replace.skel.h"
#include <stdio.h>

int main(int argc, char **argv)
{
    struct replace_bpf *skel;
    int err;

    // Open BPF application 
    skel = replace_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    // Load & verify BPF programs 
    err = replace_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        return 1;
    }

    // Attach tracepoint handler 
    err = replace_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        return 1;
    }
    printf("Successfully started! Please press CTRL+C to stop.\n");
    while(1){
        sleep(1);
    }
    // Cleanup
    replace_bpf__destroy(skel);
    return 0;
}