CC := clang -target bpf -I. -Wall -O2 -g -c

examples := syscall_counter

$(info $(examples:%=%.o))

.PHONY: all
all: $(examples:%=%.o)

.PHONY: clean
clean:
	rm -rf *.o
	rm -rf vmlinux.h

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

%.o: %.c vmlinux.h
	$(CC) -o $@ $<
