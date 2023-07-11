#include "bpf_sys_map.h"

#include "bpf_sys_enum.h"
#include "bpf_sys_error.h"

ErlNifResourceType* BPF_SYS_MAP_TYPE;

static ERL_NIF_TERM ATOM_EXIST;

int bpf_sys_map_load(ErlNifEnv* env, void** priv, ERL_NIF_TERM info_term)
{
    BPF_SYS_MAP_TYPE = enif_open_resource_type(env, NULL, "bpf_sys_map", NULL, ERL_NIF_RT_CREATE, NULL);

    ATOM_EXIST = enif_make_atom(env, "exist");

    return 0;
}

NIF(map_name_nif)
{
    bpf_sys_map_t* map;
    if (!enif_get_resource(env, argv[0], BPF_SYS_MAP_TYPE, (void**)&map)) {
        return enif_make_badarg(env);
    }

    const char* name = bpf_map__name(map->handle);
    return bpf_sys_make_string(env, name);
}

NIF(map_type_nif)
{
    bpf_sys_map_t* map;
    if (!enif_get_resource(env, argv[0], BPF_SYS_MAP_TYPE, (void**)&map)) {
        return enif_make_badarg(env);
    }

    enum bpf_map_type type = bpf_map__type(map->handle);
    return bpf_sys_map_type_to_atom(env, type);
}

NIF(map_lookup_elem_nif)
{
    bpf_sys_map_t* map;
    if (!enif_get_resource(env, argv[0], BPF_SYS_MAP_TYPE, (void**)&map)) {
        return enif_make_badarg(env);
    }

    ErlNifBinary key_bin;
    if (!enif_inspect_binary(env, argv[1], &key_bin)) {
        return enif_make_badarg(env);
    }

    size_t key_size = bpf_map__key_size(map->handle);
    size_t value_size = bpf_map__value_size(map->handle);

    if (key_bin.size != key_size) {
        return bpf_sys_make_error(env, enif_make_atom(env, "einval"));
    }

    ERL_NIF_TERM value_term;
    uint8_t* value_buf = enif_make_new_binary(env, value_size, &value_term);

    if (bpf_map__lookup_elem(map->handle, key_bin.data, key_size, value_buf, value_size, 0) < 0) {
        return errno_to_result(env);
    }

    return bpf_sys_make_ok(env, value_term);
}

NIF(map_update_elem_nif)
{
    bpf_sys_map_t* map;
    if (!enif_get_resource(env, argv[0], BPF_SYS_MAP_TYPE, (void**)&map)) {
        return enif_make_badarg(env);
    }

    ErlNifBinary key_bin;
    if (!enif_inspect_binary(env, argv[1], &key_bin)) {
        return enif_make_badarg(env);
    }

    ErlNifBinary value_bin;
    if (!enif_inspect_binary(env, argv[2], &value_bin)) {
        return enif_make_badarg(env);
    }

    size_t key_size = bpf_map__key_size(map->handle);
    size_t value_size = bpf_map__value_size(map->handle);

    EBPF_DEBUG("key_size: %d, key_bin.size: %d", key_size, key_bin.size);
    EBPF_DEBUG("value_size: %d, value_bin.size: %d", value_size, value_bin.size);

    if (key_bin.size != key_size) {
        return bpf_sys_make_error(env, enif_make_atom(env, "einval"));
    }

    if (value_bin.size != value_size) {
        return bpf_sys_make_error(env, enif_make_atom(env, "einval"));
    }

    uint64_t flags = BPF_ANY; // 0

    ERL_NIF_TERM head;
    ERL_NIF_TERM list = argv[3];
    while (enif_get_list_cell(env, list, &head, &list)) {
        if (!enif_is_tuple(env, head)) {
            return enif_make_badarg(env);
        }

        int arity;
        const ERL_NIF_TERM* array;
        if (!enif_get_tuple(env, head, &arity, &array)) {
            return enif_make_badarg(env);
        }

        if (arity != 2) {
            return enif_make_badarg(env);
        }

        ERL_NIF_TERM key = array[0];
        ERL_NIF_TERM value = array[1];

        if (enif_compare(ATOM_EXIST, key) == 0) {
            if (!bpf_sys_is_boolean(value)) {
                return enif_make_badarg(env);
            }

            if (bpf_sys_is_true(value)) {
                flags |= BPF_EXIST;
            } else {
                flags |= BPF_NOEXIST;
            }
        } else {
            return enif_make_badarg(env);
        }
    }

    if (bpf_map__update_elem(map->handle, key_bin.data, key_size, value_bin.data, value_size, flags) < 0) {
        return errno_to_result(env);
    }

    return ATOM_OK;
}

NIF(map_btf_key_type_id_nif)
{
    bpf_sys_map_t* map;
    if (!enif_get_resource(env, argv[0], BPF_SYS_MAP_TYPE, (void**)&map)) {
        return enif_make_badarg(env);
    }

    uint32_t type_id = bpf_map__btf_key_type_id(map->handle);
    if (type_id == 0) {
        return ATOM_UNDEFINED;
    }
    return enif_make_uint(env, type_id);
}

NIF(map_btf_value_type_id_nif)
{
    bpf_sys_map_t* map;
    if (!enif_get_resource(env, argv[0], BPF_SYS_MAP_TYPE, (void**)&map)) {
        return enif_make_badarg(env);
    }

    uint32_t type_id = bpf_map__btf_value_type_id(map->handle);
    if (type_id == 0) {
        return ATOM_UNDEFINED;
    }
    return enif_make_uint(env, type_id);
}
