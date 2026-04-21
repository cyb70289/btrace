PREFIX    ?= /usr/local
CC        ?= gcc
CLANG     ?= clang
ARCH      := $(shell uname -m)
KDIR      := /lib/modules/$(shell uname -r)/build

CFLAGS    := -Wall -Wextra -O2 -g
CFLAGS    += -I src/include
CFLAGS    += $(shell pkg-config --cflags libbpf 2>/dev/null)
CFLAGS    += $(shell pkg-config --cflags libelf 2>/dev/null)

LDFLAGS   := -lbpf -lelf -lz

BPF_C     := src/bpf/btrace.bpf.c
BPF_OBJ   := src/bpf/btrace.bpf.o
SKEL_H    := src/include/btrace.skel.h

BPF_CFLAGS := -target bpf -g -O2 -D__TARGET_ARCH_$(ARCH) -D__BPF__
BPF_CFLAGS += -I src/include
BPF_CFLAGS += -Wall -Wno-address-of-packed-member -Wno-unknown-attributes -Wno-visibility

SRCS      := src/main.c src/record.c src/report.c src/storage.c src/sym.c src/dot.c
OBJS      := $(SRCS:.c=.o)
TARGET    := btrace

TEST_SRCS := $(wildcard tests/cases/test_*.c)
TEST_BINS := $(patsubst tests/cases/%.c,tests/cases/%,$(TEST_SRCS))

.PHONY: all clean bpf skeleton btrace test-cases check vmlinux install

all: btrace

vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/include/vmlinux.h

$(SKEL_H): $(BPF_OBJ)
	bpftool gen skeleton $< > $@

$(BPF_OBJ): $(BPF_C) src/include/btrace.h src/include/vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

bpf: $(BPF_OBJ)

skeleton: $(SKEL_H)

%.o: %.c $(SKEL_H) src/include/btrace.h
	$(CC) $(CFLAGS) -c $< -o $@

btrace: $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) $(LDFLAGS) -o $@

tests/cases/%: tests/cases/%.c
	$(CC) -Wall -O2 -pthread -o $@ $<

test-cases: $(TEST_BINS)

check: btrace test-cases
	bash tests/run_test.sh

clean:
	rm -f $(BPF_OBJ) $(SKEL_H) $(OBJS) $(TARGET)
	rm -f src/include/vmlinux.h
	rm -f $(TEST_BINS)
	rm -f *.btrace

install: btrace
	install -m 755 $(TARGET) $(PREFIX)/bin/$(TARGET)
