ERLANG_PATH ?= $(shell erl -eval 'io:format("~s", [lists:concat([code:root_dir(), "/erts-", erlang:system_info(version), "/include"])])' -s init stop -noshell)
CFLAGS := -Wall -O3 -fPIC -pthread -std=c11
CPPFLAGS := -I$(ERLANG_PATH) $(shell pkg-config --cflags libbpf)
LDFLAGS := $(shell pkg-config --libs libbpf)

sources := $(wildcard c_src/*.c)
headers := $(wildcard c_src/*.h)
objects := $(sources:%.c=%.o)

.PHONY: all
all: priv/bpf_sys.so

.PHONY: clean
clean:
	$(RM) c_src/*.o
	$(RM) c_src/*.d
	$(RM) priv/bpf_sys.so

c_src/%.o: c_src/%.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -MMD -c -o $@ $<

priv/bpf_sys.so: $(objects)
	$(CC) -shared -o $@ $(objects) $(LDFLAGS)

-include $(wildcard c_src/*.d)
