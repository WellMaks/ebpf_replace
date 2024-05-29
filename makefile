KERNEL_VERSION=$(shell uname -r)

BPF_INCLUDE_PATH=/usr/include/linux
LIBBPF_INCLUDE_PATH=/usr/src/linux-headers-$(KERNEL_VERSION)/tools/bpf/resolve_btfids/libbpf/include/bpf

LIB_PATH=/usr/lib64

CLANG=clang
CLANG_FLAGS=-g -O2 -target bpf -D__TARGET_ARCH_x86
CLANG_INCLUDES=-I$(BPF_INCLUDE_PATH) -I$(LIBBPF_INCLUDE_PATH)

BPFTOOL=bpftool

GCC=gcc
GCC_FLAGS=-O2 -Wall -g
GCC_LIBS=-L$(LIB_PATH) -lbpf -lelf -lz
GCC_RPATH=-Wl,-rpath,$(LIB_PATH)

TARGET=replace

all: $(TARGET)

replace.bpf.o: replace.bpf.c
	$(CLANG) $(CLANG_FLAGS) $(CLANG_INCLUDES) -c $< -o $@

replace.skel.h: replace.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

$(TARGET): replace.c replace.skel.h
	$(GCC) $(GCC_FLAGS) -o $@ replace.c $(GCC_LIBS) $(GCC_RPATH)

clean:
	rm -f $(TARGET) replace.bpf.o replace.skel.h

.PHONY: all clean
