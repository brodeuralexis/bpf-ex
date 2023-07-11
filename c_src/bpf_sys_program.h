#ifndef __BPF_SYS_PROGRAM__
#define __BPF_SYS_PROGRAM__

#include <stdbool.h>

#include <bpf/libbpf.h>

#include "bpf_sys.h"

extern ErlNifResourceType* BPF_SYS_PROGRAM_TYPE;

typedef struct bpf_sys_program {
    struct bpf_program* handle;
} bpf_sys_program_t;

int bpf_sys_program_load(ErlNifEnv* env, void** priv, ERL_NIF_TERM info_term);

#define BPF_SYS_PROGRAM_FUNCS                                           \
    { "program_set_ifindex", 2, program_set_ifindex_nif, 0 },           \
        { "program_name", 1, program_name_nif, 0 },                     \
        { "program_section_name", 1, program_section_name_nif, 0 },     \
        { "program_autoload", 1, program_autoload_nif, 0 },             \
        { "program_set_autoload", 2, program_set_autoload_nif, 0 },     \
        { "program_autoattach", 1, program_autoattach_nif, 0 },         \
        { "program_set_autoattach", 2, program_set_autoattach_nif, 0 }, \
        { "program_insns", 1, program_insns_nif, 0 },                   \
        { "program_set_insns", 2, program_set_insns_nif, 0 },           \
        { "program_pin", 2, program_pin_nif, 0 },                       \
        { "program_unpin", 2, program_unpin_nif, 0 },                   \
        { "program_unload", 1, program_unload_nif, 0 },                 \
        { "program_attach", 1, program_attach_nif, 0 },

NIF(program_set_ifindex_nif);
NIF(program_name_nif);
NIF(program_section_name_nif);
NIF(program_autoload_nif);
NIF(program_set_autoload_nif);
NIF(program_autoattach_nif);
NIF(program_set_autoattach_nif);
NIF(program_insns_nif);
NIF(program_set_insns_nif);
NIF(program_pin_nif);
NIF(program_unpin_nif);
NIF(program_unload_nif);
NIF(program_attach_nif);

#endif
