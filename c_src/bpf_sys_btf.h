#ifndef __BPF_SYS_BTF__
#define __BPF_SYS_BTF__

#include "bpf_sys.h"

extern ErlNifResourceType* BPF_SYS_BTF_TYPE;

typedef struct bpf_sys_btf {
    struct btf* handle;
    bool owned;
} bpf_sys_btf_t;

int bpf_sys_btf_load(ErlNifEnv* env, void** priv, ERL_NIF_TERM info_term);

#define BPF_SYS_BTF_FUNCS                               \
    { "btf_find_by_name", 2, btf_find_by_name_nif, 0 }, \
        { "btf_find_by_id", 2, btf_find_by_id_nif, 0 }, \
        { "btf_endianness", 1, btf_endianness_nif, 0 },

NIF(btf_find_by_name_nif);
NIF(btf_find_by_id_nif);
NIF(btf_endianness_nif);

#endif
