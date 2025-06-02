#ifndef __BPF_SYS_LINK__
#define __BPF_SYS_LINK__

#include <bpf/libbpf.h>
#include <erl_nif.h>

#include "bpf_sys.h"

extern ErlNifResourceType* BPF_SYS_LINK_TYPE;

typedef struct bpf_sys_link {
    struct bpf_link* handle;
} bpf_sys_link_t;

int bpf_sys_link_load(ErlNifEnv* env, void** priv, ERL_NIF_TERM info_term);

#define BPF_SYS_LINK_FUNCS                                \
    { "link_open", 1, link_open_nif, 0 },                 \
        { "link_disconnect", 1, link_disconnect_nif, 0 }, \
        { "link_detach", 1, link_detach_nif, 0 },         \
        { "link_pin_path", 1, link_pin_path_nif, 0 },     \
        { "link_pin", 2, link_pin_nif, 0 },               \
        { "link_unpin", 1, link_unpin_nif, 0 },

NIF(link_open_nif);
NIF(link_disconnect_nif);
NIF(link_detach_nif);
NIF(link_pin_path_nif);
NIF(link_pin_nif);
NIF(link_unpin_nif);

#endif
