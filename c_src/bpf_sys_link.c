#include "bpf_sys_link.h"
#include "bpf_sys_error.h"
#include "erl_nif.h"
#include <bpf/libbpf.h>

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
        result = errno_to_result(env);
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

NIF(link_disconnect_nif)
{
    bpf_sys_link_t* link;
    if (!enif_get_resource(env, argv[0], BPF_SYS_LINK_TYPE, (void**)&link)) {
        return enif_make_badarg(env);
    }

    bpf_link__disconnect(link->handle);

    return ATOM_OK;
}

NIF(link_detach_nif)
{
    bpf_sys_link_t* link;
    if (!enif_get_resource(env, argv[0], BPF_SYS_LINK_TYPE, (void**)&link)) {
        return enif_make_badarg(env);
    }

    if (bpf_link__detach(link->handle) < 0) {
        return errno_to_result(env);
    }

    return ATOM_OK;
}

NIF(link_pin_path_nif)
{
    bpf_sys_link_t* link;
    if (!enif_get_resource(env, argv[0], BPF_SYS_LINK_TYPE, (void**)&link)) {
        return enif_make_badarg(env);
    }

    const char* pin_path = bpf_link__pin_path(link->handle);

    if (pin_path == NULL) {
        return ATOM_NIL;
    }

    return bpf_sys_make_string(env, pin_path);
}

NIF(link_pin_nif)
{
    ERL_NIF_TERM result;

    bpf_sys_link_t* link;
    if (!enif_get_resource(env, argv[0], BPF_SYS_LINK_TYPE, (void**)&link)) {
        return enif_make_badarg(env);
    }

    const char* path;
    if (!bpf_sys_get_string(env, argv[0], &path)) {
        return enif_make_badarg(env);
    }

    if (bpf_link__pin(link->handle, path) < 0) {
        result = errno_to_result(env);
        goto cleanup_path;
    }

    result = ATOM_OK;

cleanup_path:
    enif_free((void*)path);
    return result;
}

NIF(link_unpin_nif)
{
    bpf_sys_link_t* link;
    if (!enif_get_resource(env, argv[0], BPF_SYS_LINK_TYPE, (void**)&link)) {
        return enif_make_badarg(env);
    }

    if (bpf_link__unpin(link->handle) < 0) {
        return errno_to_result(env);
    }

    return ATOM_OK;
}
