#include "bpf_sys_program.h"

#include "bpf_sys_error.h"
#include "bpf_sys_link.h"

ErlNifResourceType* BPF_SYS_PROGRAM_TYPE;

int bpf_sys_program_load(ErlNifEnv* env, void** priv, ERL_NIF_TERM info_term)
{
    BPF_SYS_PROGRAM_TYPE = enif_open_resource_type(env, NULL, "bpf_sys_program", NULL, ERL_NIF_RT_CREATE, NULL);

    return 0;
}

NIF(program_set_ifindex_nif)
{
    bpf_sys_program_t* program;
    if (!enif_get_resource(env, argv[0], BPF_SYS_PROGRAM_TYPE, (void**)&program)) {
        return enif_make_badarg(env);
    }

    unsigned int ifindex;
    if (!enif_get_uint(env, argv[1], &ifindex)) {
        return enif_make_badarg(env);
    }

    bpf_program__set_ifindex(program->handle, ifindex);

    return ATOM_OK;
}

NIF(program_name_nif)
{
    bpf_sys_program_t* program;
    if (!enif_get_resource(env, argv[0], BPF_SYS_PROGRAM_TYPE, (void**)&program)) {
        return enif_make_badarg(env);
    }

    const char* name = bpf_program__name(program->handle);
    return bpf_sys_make_string(env, name);
}

NIF(program_section_name_nif)
{
    bpf_sys_program_t* program;
    if (!enif_get_resource(env, argv[0], BPF_SYS_PROGRAM_TYPE, (void**)&program)) {
        return enif_make_badarg(env);
    }

    const char* section_name = bpf_program__section_name(program->handle);
    return bpf_sys_make_string(env, section_name);
}

NIF(program_autoload_nif)
{
    bpf_sys_program_t* program;
    if (!enif_get_resource(env, argv[0], BPF_SYS_PROGRAM_TYPE, (void**)&program)) {
        return enif_make_badarg(env);
    }

    bool autoload = bpf_program__autoload(program->handle);
    return autoload ? ATOM_TRUE : ATOM_FALSE;
}

NIF(program_set_autoload_nif)
{
    bpf_sys_program_t* program;
    if (!enif_get_resource(env, argv[0], BPF_SYS_PROGRAM_TYPE, (void**)&program)) {
        return enif_make_badarg(env);
    }

    if (!bpf_sys_is_boolean(argv[1])) {
        return enif_make_badarg(env);
    }

    bool autoload = bpf_sys_is_true(argv[1]);

    if (bpf_program__set_autoload(program->handle, autoload) < 0) {
        return errno_to_result(env);
    }

    return ATOM_OK;
}

NIF(program_autoattach_nif)
{
    bpf_sys_program_t* program;
    if (!enif_get_resource(env, argv[0], BPF_SYS_PROGRAM_TYPE, (void**)&program)) {
        return enif_make_badarg(env);
    }

    bool autoattach = bpf_program__autoattach(program->handle);
    return autoattach ? ATOM_TRUE : ATOM_FALSE;
}

NIF(program_set_autoattach_nif)
{
    bpf_sys_program_t* program;
    if (!enif_get_resource(env, argv[0], BPF_SYS_PROGRAM_TYPE, (void**)&program)) {
        return enif_make_badarg(env);
    }

    if (!bpf_sys_is_boolean(argv[1])) {
        return enif_make_badarg(env);
    }

    bool autoattach = bpf_sys_is_true(argv[1]);

    bpf_program__set_autoattach(program->handle, autoattach);

    return ATOM_OK;
}

NIF(program_insns_nif)
{
    bpf_sys_program_t* program;
    if (!enif_get_resource(env, argv[0], BPF_SYS_PROGRAM_TYPE, (void**)&program)) {
        return enif_make_badarg(env);
    }

    size_t insn_cnt = bpf_program__insn_cnt(program->handle);
    const struct bpf_insn* insns = bpf_program__insns(program->handle);

    ERL_NIF_TERM data_term;
    unsigned char* data = enif_make_new_binary(env, insn_cnt * sizeof(*insns), &data_term);
    memcpy(data, insns, sizeof(*insns) * insn_cnt);

    return data_term;
}

NIF(program_set_insns_nif)
{
    bpf_sys_program_t* program;
    if (!enif_get_resource(env, argv[0], BPF_SYS_PROGRAM_TYPE, (void**)&program)) {
        return enif_make_badarg(env);
    }

    ErlNifBinary insns;
    if (!enif_inspect_binary(env, argv[1], &insns)) {
        return enif_make_badarg(env);
    }

    if (insns.size % sizeof(struct bpf_insn) != 0) {
        return bpf_sys_make_error(env, enif_make_atom(env, "einval"));
    }

    if (bpf_program__set_insns(program->handle, (struct bpf_insn*)insns.data, insns.size / sizeof(struct bpf_insn)) < 0) {
        return errno_to_result(env);
    }

    return ATOM_OK;
}

NIF(program_pin_nif)
{
    ERL_NIF_TERM result;

    bpf_sys_program_t* program;
    if (!enif_get_resource(env, argv[0], BPF_SYS_PROGRAM_TYPE, (void**)&program)) {
        return enif_make_badarg(env);
    }

    const char* path = NULL;
    if (!bpf_sys_get_string(env, argv[1], &path)) {
        return enif_make_badarg(env);
    }

    if (bpf_program__pin(program->handle, path) < 0) {
        result = errno_to_result(env);
        goto cleanup_path;
    }

    result = ATOM_OK;

cleanup_path:
    enif_free((void*)path);
    return result;
}

NIF(program_unpin_nif)
{
    ERL_NIF_TERM result;

    bpf_sys_program_t* program;
    if (!enif_get_resource(env, argv[0], BPF_SYS_PROGRAM_TYPE, (void**)&program)) {
        return enif_make_badarg(env);
    }

    const char* path = NULL;
    if (!bpf_sys_get_string(env, argv[1], &path)) {
        return enif_make_badarg(env);
    }

    if (bpf_program__unpin(program->handle, path) < 0) {
        result = errno_to_result(env);
        goto cleanup_path;
    }

    result = ATOM_OK;

cleanup_path:
    enif_free((void*)path);
    return result;
}

NIF(program_unload_nif)
{
    bpf_sys_program_t* program;
    if (!enif_get_resource(env, argv[0], BPF_SYS_PROGRAM_TYPE, (void**)&program)) {
        return enif_make_badarg(env);
    }

    bpf_program__unload(program->handle);

    return ATOM_OK;
}

NIF(program_attach_nif)
{
    bpf_sys_program_t* program;
    if (!enif_get_resource(env, argv[0], BPF_SYS_PROGRAM_TYPE, (void**)&program)) {
        return enif_make_badarg(env);
    }

    struct bpf_link* handle = bpf_program__attach(program->handle);
    if (!handle) {
        return errno_to_result(env);
    }

    bpf_sys_link_t* link = enif_alloc_resource(BPF_SYS_LINK_TYPE, sizeof(*link));
    link->handle = handle;
    ERL_NIF_TERM link_term = enif_make_resource(env, link);
    enif_release_resource(link);
    return bpf_sys_make_ok(env, link_term);
}

NIF(program_attach_xdp_nif)
{
    bpf_sys_program_t* program;
    if (!enif_get_resource(env, argv[0], BPF_SYS_PROGRAM_TYPE, (void**)&program)) {
        return enif_make_badarg(env);
    }

    unsigned int ifindex;
    if (!enif_get_uint(env, argv[1], &ifindex)) {
        return enif_make_badarg(env);
    }

    struct bpf_link* link_handle = bpf_program__attach_xdp(program->handle, ifindex);
    if (!link_handle) {
        return errno_to_result(env);
    }

    bpf_sys_link_t* link = enif_alloc_resource(BPF_SYS_LINK_TYPE, sizeof(*link));
    link->handle = link_handle;
    ERL_NIF_TERM link_term = enif_make_resource(env, link);
    enif_release_resource(link);
    return bpf_sys_make_ok(env, link_term);
}
