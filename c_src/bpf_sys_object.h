#ifndef __BPF_SYS_OBJECT__
#define __BPF_SYS_OBJECT__

#include <stddef.h>

#include <bpf/libbpf.h>

#include "bpf_sys.h"

extern ErlNifResourceType* BPF_SYS_OBJECT_TYPE;

typedef struct bpf_sys_program bpf_sys_program_t; // FWD: bpf_sys_program.h
typedef struct bpf_sys_map bpf_sys_map_t; // FWD: bpf_sys_map.h
typedef struct bpf_sys_btf bpf_sys_btf_t; // FWD: bpf_sys_btf.h

typedef struct bpf_sys_object {
    struct bpf_object* handle;
    bpf_sys_map_t** maps;
    bpf_sys_program_t** programs;
    size_t num_maps;
    size_t num_programs;
    bpf_sys_btf_t* btf;
    char* log_buffer;
    size_t log_size;
} bpf_sys_object_t;

int bpf_sys_object_load(ErlNifEnv* env, void** priv, ERL_NIF_TERM info_term);

#define BPF_SYS_OBJECT_FUNCS                                          \
    { "object_open_file", 2, object_open_file_nif, 0 },               \
        { "object_load", 1, object_load_nif, 0 },                     \
        { "object_pin_maps", 2, object_pin_maps_nif, 0 },             \
        { "object_unpin_maps", 2, object_unpin_maps_nif, 0 },         \
        { "object_pin_programs", 2, object_pin_programs_nif, 0 },     \
        { "object_unpin_programs", 2, object_unpin_programs_nif, 0 }, \
        { "object_name", 1, object_name_nif, 0 },                     \
        { "object_kversion", 1, object_kversion_nif, 0 },             \
        { "object_set_kversion", 2, object_set_kversion_nif, 0 },     \
        { "object_btf", 1, object_btf_nif, 0 },                       \
        { "object_maps", 1, object_maps_nif, 0 },                     \
        { "object_programs", 1, object_programs_nif, 0 },

NIF(object_open_file_nif);
NIF(object_load_nif);
NIF(object_pin_maps_nif);
NIF(object_unpin_maps_nif);
NIF(object_pin_programs_nif);
NIF(object_unpin_programs_nif);
NIF(object_name_nif);
NIF(object_kversion_nif);
NIF(object_set_kversion_nif);
NIF(object_btf_nif);
NIF(object_maps_nif);
NIF(object_programs_nif);

#endif
