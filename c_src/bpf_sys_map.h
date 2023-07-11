#ifndef __BPF_SYS_MAP__
#define __BPF_SYS_MAP__

#include <bpf/libbpf.h>
#include <erl_nif.h>

#include "bpf_sys.h"

extern ErlNifResourceType* BPF_SYS_MAP_TYPE;

typedef struct bpf_sys_map {
    struct bpf_map* handle;
} bpf_sys_map_t;

int bpf_sys_map_load(ErlNifEnv* env, void** priv, ERL_NIF_TERM info_term);

#define BPF_SYS_MAP_FUNCS                                         \
    { "map_name", 1, map_name_nif, 0 },                           \
        { "map_type", 1, map_type_nif, 0 },                       \
        { "map_lookup_elem", 2, map_lookup_elem_nif, 0 },         \
        { "map_update_elem", 4, map_update_elem_nif, 0 },         \
        { "map_btf_key_type_id", 1, map_btf_key_type_id_nif, 0 }, \
        { "map_btf_value_type_id", 1, map_btf_value_type_id_nif, 0 },

NIF(map_name_nif);
NIF(map_type_nif);
NIF(map_lookup_elem_nif);
NIF(map_update_elem_nif);
NIF(map_btf_key_type_id_nif);
NIF(map_btf_value_type_id_nif);

#endif
