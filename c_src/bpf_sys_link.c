#include "bpf_sys_link.h"

ErlNifResourceType* BPF_SYS_LINK_TYPE;

static void bpf_sys_link_dtor(ErlNifEnv* env, void* resource)
{
    bpf_sys_link_t* link = resource;
    bpf_link__destroy(link->handle);
}

int bpf_sys_link_load(ErlNifEnv* env, void** priv, ERL_NIF_TERM info_term)
{
    BPF_SYS_LINK_TYPE = enif_open_resource_type(env, NULL, "bpf_sys_link", bpf_sys_link_dtor, ERL_NIF_RT_CREATE, NULL);

    return 0;
}

NIF(link_open_nif)
{
    ERL_NIF_TERM result;

    const char* path;
    if (!bpf_sys_get_string(env, argv[0], &path)) {
        return enif_make_badarg(env);
    }

    struct bpf_link* handle = bpf_link__open(path);
    if (!handle) {
        result = enif_make_badarg(env);
        goto cleanup_path;
    }

    bpf_sys_link_t* link = enif_alloc_resource(BPF_SYS_LINK_TYPE, sizeof(*link));
    link->handle = handle;
    result = enif_make_resource(env, link);
    enif_release_resource(link);

cleanup_path:
    enif_free((void*)path);
    return result;
}
