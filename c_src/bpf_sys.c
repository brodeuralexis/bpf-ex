#include <bpf/libbpf.h>
#include <erl_nif.h>

#include "bpf_sys.h"
#include "bpf_sys_btf.h"
#include "bpf_sys_enum.h"
#include "bpf_sys_error.h"
#include "bpf_sys_link.h"
#include "bpf_sys_map.h"
#include "bpf_sys_object.h"
#include "bpf_sys_program.h"

static bool get_list_string(ErlNifEnv* env, ERL_NIF_TERM term, const char** str)
{
    if (!enif_is_list(env, term)) {
        return false;
    }

    unsigned int str_len;
    if (!enif_get_list_length(env, term, &str_len)) {
        return false;
    }

    char* _str = enif_alloc(sizeof(*_str) * (str_len + 1));
    if (!enif_get_string(env, term, _str, str_len + 1, ERL_NIF_LATIN1)) {
        enif_free(_str);
        return false;
    }

    *str = _str;
    return true;
}

static bool get_binary_string(ErlNifEnv* env, ERL_NIF_TERM term, const char** str)
{
    if (!enif_is_binary(env, term)) {
        return false;
    }

    ErlNifBinary str_bin;
    if (!enif_inspect_binary(env, term, &str_bin)) {
        return false;
    }

    char* _str = enif_alloc(sizeof(*_str) * (str_bin.size + 1));
    memcpy(_str, str_bin.data, str_bin.size);
    _str[str_bin.size] = 0;
    *str = _str;
    return true;
}

bool bpf_sys_get_string(ErlNifEnv* env, ERL_NIF_TERM term, const char** str)
{
    if (enif_is_list(env, term)) {
        return get_list_string(env, term, str);
    } else if (enif_is_binary(env, term)) {
        return get_binary_string(env, term, str);
    } else {
        return false;
    }
}

ERL_NIF_TERM bpf_sys_make_string(ErlNifEnv* env, const char* str)
{
    ERL_NIF_TERM result;
    char* copy = (char*)enif_make_new_binary(env, strlen(str), &result);
    strcpy(copy, str);
    return result;
}

ERL_NIF_TERM ATOM_OK;
ERL_NIF_TERM ATOM_ERROR;
ERL_NIF_TERM ATOM_TRUE;
ERL_NIF_TERM ATOM_FALSE;
ERL_NIF_TERM ATOM_UNDEFINED;
ERL_NIF_TERM ATOM_NIL;

static int bpf_sys_load(ErlNifEnv* env, void** priv, ERL_NIF_TERM info_term)
{
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(NULL);

    ATOM_OK = enif_make_atom(env, "ok");
    ATOM_ERROR = enif_make_atom(env, "error");
    ATOM_TRUE = enif_make_atom(env, "true");
    ATOM_FALSE = enif_make_atom(env, "false");
    ATOM_UNDEFINED = enif_make_atom(env, "undefined");
    ATOM_NIL = enif_make_atom(env, "nil");

    int err = 0;
    err = err ? err : bpf_sys_btf_load(env, priv, info_term);
    err = err ? err : bpf_sys_enum_load(env, priv, info_term);
    err = err ? err : bpf_sys_map_load(env, priv, info_term);
    err = err ? err : bpf_sys_object_load(env, priv, info_term);
    err = err ? err : bpf_sys_program_load(env, priv, info_term);
    err = err ? err : bpf_sys_link_load(env, priv, info_term);

    return 0;
}

static NIF(major_version_nif)
{
    unsigned int major = libbpf_major_version();

    return enif_make_uint(env, major);
}

static NIF(minor_version_nif)
{
    unsigned int minor = libbpf_minor_version();

    return enif_make_uint(env, minor);
}

static NIF(num_possible_cpus_nif)
{
    unsigned int cpus = libbpf_num_possible_cpus();

    if (cpus < 0) {
        return errno_to_result(env);
    }

    return bpf_sys_make_ok(env, enif_make_uint(env, cpus));
}

static ErlNifFunc nif_funcs[] = {
    { "major_version", 0, major_version_nif, 0 },
    { "minor_version", 0, minor_version_nif, 0 },
    { "num_possible_cpus", 0, num_possible_cpus_nif, 0 },
    BPF_SYS_MAP_FUNCS BPF_SYS_OBJECT_FUNCS BPF_SYS_PROGRAM_FUNCS BPF_SYS_BTF_FUNCS BPF_SYS_LINK_FUNCS
};

ERL_NIF_INIT(bpf_sys, nif_funcs, bpf_sys_load, NULL, NULL, NULL);
