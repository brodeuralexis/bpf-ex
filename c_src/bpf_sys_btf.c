#include "bpf_sys_btf.h"

#include <bpf/btf.h>

#include "bpf_sys.h"
#include "bpf_sys_enum.h"
#include "bpf_sys_error.h"

ErlNifResourceType* BPF_SYS_BTF_TYPE;

static void bpf_sys_btf_dtor(ErlNifEnv* env, void* resource)
{
    bpf_sys_btf_t* btf = resource;
    if (btf->owned) {
        btf__free(btf->handle);
    }
}

int bpf_sys_btf_load(ErlNifEnv* env, void** priv, ERL_NIF_TERM info_term)
{
    BPF_SYS_BTF_TYPE = enif_open_resource_type(env, NULL, "bpf_sys_btf", bpf_sys_btf_dtor, ERL_NIF_RT_CREATE, 0);

    return 0;
}

static ERL_NIF_TERM encode_int(ErlNifEnv* env, const struct btf_type* type, ERL_NIF_TERM map)
{
    enif_make_map_put(env, map, enif_make_atom(env, "size"), enif_make_uint(env, type->size), &map);
    int encoding = btf_int_encoding(type);
    bool is_signed = (encoding & BTF_INT_SIGNED) != 0;
    bool is_char = (encoding & BTF_INT_CHAR) != 0;
    bool is_bool = (encoding & BTF_INT_BOOL) != 0;

    ERL_NIF_TERM encoding_term = enif_make_new_map(env);
    enif_make_map_put(env, encoding_term, enif_make_atom(env, "signed"), is_signed ? ATOM_TRUE : ATOM_FALSE, &encoding_term);
    enif_make_map_put(env, encoding_term, enif_make_atom(env, "char"), is_char ? ATOM_TRUE : ATOM_FALSE, &encoding_term);
    enif_make_map_put(env, encoding_term, enif_make_atom(env, "bool"), is_bool ? ATOM_TRUE : ATOM_FALSE, &encoding_term);

    enif_make_map_put(env, map, enif_make_atom(env, "encoding"), encoding_term, &map);

    int bits = btf_int_bits(type);
    enif_make_map_put(env, map, enif_make_atom(env, "bits"), enif_make_uint(env, bits), &map);

    int offset = btf_int_offset(type);
    enif_make_map_put(env, map, enif_make_atom(env, "offset"), enif_make_uint(env, offset), &map);

    return bpf_sys_make_ok(env, map);
}

static ERL_NIF_TERM encode_ptr(ErlNifEnv* env, const struct btf_type* type, ERL_NIF_TERM map)
{
    enif_make_map_put(env, map, enif_make_atom(env, "type"), enif_make_uint(env, type->type), &map);
    return bpf_sys_make_ok(env, map);
}

static ERL_NIF_TERM encode_array(ErlNifEnv* env, const struct btf_type* type, ERL_NIF_TERM map)
{
    struct btf_array* array = btf_array(type);
    enif_make_map_put(env, map, enif_make_atom(env, "type"), enif_make_uint(env, array->type), &map);
    enif_make_map_put(env, map, enif_make_atom(env, "index_type"), enif_make_uint(env, array->index_type), &map);
    enif_make_map_put(env, map, enif_make_atom(env, "nelems"), enif_make_uint(env, array->nelems), &map);
    return bpf_sys_make_ok(env, map);
}

static ERL_NIF_TERM encode_struct_or_union(ErlNifEnv* env, bpf_sys_btf_t* btf, const struct btf_type* type, ERL_NIF_TERM map)
{
    struct btf_member* members = btf_members(type);

    int vlen = btf_vlen(type);

    enif_make_map_put(env, map, enif_make_atom(env, "kflag"), enif_make_uint(env, btf_kflag(type)), &map);
    enif_make_map_put(env, map, enif_make_atom(env, "vlen"), enif_make_uint(env, btf_vlen(type)), &map);
    enif_make_map_put(env, map, enif_make_atom(env, "size"), enif_make_uint(env, type->size), &map);

    ERL_NIF_TERM* members_terms = enif_alloc(vlen * sizeof(*members_terms));

    for (int i = 0; i < vlen; ++i) {
        ERL_NIF_TERM member_map = enif_make_new_map(env);

        const char* name = btf__name_by_offset(btf->handle, members[i].name_off);
        if (name || name[0] != '\0') {
            enif_make_map_put(env, member_map, enif_make_atom(env, "name"), bpf_sys_make_string(env, name), &member_map);
        }

        enif_make_map_put(env, member_map, enif_make_atom(env, "type"), enif_make_uint(env, members[i].type), &member_map);
        enif_make_map_put(env, member_map, enif_make_atom(env, "offset"), enif_make_uint(env, members[i].offset), &member_map);

        members_terms[i] = member_map;
    }

    enif_make_map_put(env, map, enif_make_atom(env, "members"), enif_make_list_from_array(env, members_terms, vlen), &map);
    enif_free(members_terms);

    return bpf_sys_make_ok(env, map);
}

static ERL_NIF_TERM encode_enum(ErlNifEnv* env, bpf_sys_btf_t* btf, const struct btf_type* type, ERL_NIF_TERM map)
{
    int vlen = btf_vlen(type);

    enif_make_map_put(env, map, enif_make_atom(env, "kflag"), enif_make_uint(env, btf_kflag(type)), &map);
    enif_make_map_put(env, map, enif_make_atom(env, "vlen"), enif_make_uint(env, vlen), &map);
    enif_make_map_put(env, map, enif_make_atom(env, "size"), enif_make_uint(env, type->size), &map);

    struct btf_enum* values = btf_enum(type);
    ERL_NIF_TERM* values_terms = enif_alloc(vlen * sizeof(*values_terms));

    for (int i = 0; i < vlen; ++i) {
        ERL_NIF_TERM value_map = enif_make_new_map(env);
        enif_make_map_put(env, value_map, enif_make_atom(env, "val"), enif_make_int(env, values[i].val), &value_map);

        const char* name = btf__name_by_offset(btf->handle, values[i].name_off);
        if (!name || name[0] != '\0') {
            enif_make_map_put(env, value_map, enif_make_atom(env, "name"), bpf_sys_make_string(env, name), &value_map);
        }

        values_terms[i] = value_map;
    }

    enif_make_map_put(env, map, enif_make_atom(env, "enum"), enif_make_list_from_array(env, values_terms, vlen), &map);
    enif_free(values_terms);

    return bpf_sys_make_ok(env, map);
}

static ERL_NIF_TERM encode_fwd(ErlNifEnv* env, const struct btf_type* type, ERL_NIF_TERM map)
{
    enif_make_map_put(env, map, enif_make_atom(env, "kflag"), enif_make_uint(env, btf_kflag(type)), &map);
    return bpf_sys_make_ok(env, map);
}

static ERL_NIF_TERM encode_typedef(ErlNifEnv* env, const struct btf_type* type, ERL_NIF_TERM map)
{
    enif_make_map_put(env, map, enif_make_atom(env, "type"), enif_make_uint(env, type->type), &map);
    return bpf_sys_make_ok(env, map);
}

static ERL_NIF_TERM encode_type_modifier(ErlNifEnv* env, const struct btf_type* type, ERL_NIF_TERM map)
{
    enif_make_map_put(env, map, enif_make_atom(env, "type"), enif_make_uint(env, type->type), &map);
    return bpf_sys_make_ok(env, map);
}

static ERL_NIF_TERM encode_func(ErlNifEnv* env, const struct btf_type* type, ERL_NIF_TERM map)
{
    enif_make_map_put(env, map, enif_make_atom(env, "type"), enif_make_uint(env, type->type), &map);

    ERL_NIF_TERM linkage = ATOM_UNDEFINED;
    switch (btf_vlen(type)) {
    case BTF_FUNC_STATIC:
        linkage = enif_make_atom(env, "static");
        break;
    case BTF_FUNC_GLOBAL:
        linkage = enif_make_atom(env, "global");
        break;
    case BTF_FUNC_EXTERN:
        linkage = enif_make_atom(env, "extern");
        break;
    }

    enif_make_map_put(env, map, enif_make_atom(env, "vlen"), linkage, &map);

    return bpf_sys_make_ok(env, map);
}

static ERL_NIF_TERM encode_func_proto(ErlNifEnv* env, bpf_sys_btf_t* btf, const struct btf_type* type, ERL_NIF_TERM map)
{
    enif_make_map_put(env, map, enif_make_atom(env, "vlen"), enif_make_uint(env, btf_vlen(type)), &map);
    enif_make_map_put(env, map, enif_make_atom(env, "type"), enif_make_uint(env, type->type), &map);

    struct btf_param* params = btf_params(type);
    ERL_NIF_TERM* params_terms = enif_alloc(btf_vlen(type) * sizeof(*params_terms));

    for (int i = 0; i < btf_vlen(type); ++i) {
        ERL_NIF_TERM param_map = enif_make_new_map(env);
        enif_make_map_put(env, param_map, enif_make_atom(env, "type"), enif_make_uint(env, params[i].type), &param_map);
        const char* name = params[i].name_off != 0 ? btf__name_by_offset(btf->handle, params[i].name_off) : NULL;
        if (!name || name[0] != '\0') {
            enif_make_map_put(env, map, enif_make_atom(env, "name"), bpf_sys_make_string(env, name), &map);
        }
        params_terms[i] = param_map;
    }

    enif_make_map_put(env, map, enif_make_atom(env, "params"), enif_make_list_from_array(env, params_terms, btf_vlen(type)), &map);
    enif_free(params_terms);

    return bpf_sys_make_ok(env, map);
}

static ERL_NIF_TERM encode_var(ErlNifEnv* env, const struct btf_type* type, ERL_NIF_TERM map)
{
    struct btf_var* var = btf_var(type);

    enif_make_map_put(env, map, enif_make_atom(env, "type"), enif_make_uint(env, type->type), &map);

    if (var->linkage) {
        enif_make_map_put(env, map, enif_make_atom(env, "linkage"), enif_make_atom(env, "global"), &map);
    } else {
        enif_make_map_put(env, map, enif_make_atom(env, "linkage"), enif_make_atom(env, "static"), &map);
    }

    return bpf_sys_make_ok(env, map);
}

static ERL_NIF_TERM encode_datasec(ErlNifEnv* env, bpf_sys_btf_t* btf, const struct btf_type* type, ERL_NIF_TERM map)
{
    enif_make_map_put(env, map, enif_make_atom(env, "vlen"), enif_make_uint(env, btf_vlen(type)), &map);
    enif_make_map_put(env, map, enif_make_atom(env, "size"), enif_make_uint(env, type->size), &map);

    struct btf_var_secinfo* var_secinfos = btf_var_secinfos(type);
    ERL_NIF_TERM* var_secinfos_terms = enif_alloc(btf_vlen(type) * sizeof(*var_secinfos_terms));

    for (int i = 0; i < btf_vlen(type); ++i) {
        ERL_NIF_TERM var_secinfo_map = enif_make_new_map(env);
        enif_make_map_put(env, var_secinfo_map, enif_make_atom(env, "type"), enif_make_uint(env, var_secinfos[i].type), &var_secinfo_map);
        enif_make_map_put(env, var_secinfo_map, enif_make_atom(env, "offset"), enif_make_uint(env, var_secinfos[i].offset), &var_secinfo_map);
        enif_make_map_put(env, var_secinfo_map, enif_make_atom(env, "size"), enif_make_uint(env, var_secinfos[i].size), &var_secinfo_map);
        var_secinfos_terms[i] = var_secinfo_map;
    }

    enif_make_map_put(env, map, enif_make_atom(env, "var_secinfos"), enif_make_list_from_array(env, var_secinfos_terms, btf_vlen(type)), &map);
    enif_free(var_secinfos_terms);

    return bpf_sys_make_ok(env, map);
}

static ERL_NIF_TERM encode_float(ErlNifEnv* env, const struct btf_type* type, ERL_NIF_TERM map)
{
    enif_make_map_put(env, map, enif_make_atom(env, "size"), enif_make_uint(env, type->size), &map);
    return bpf_sys_make_ok(env, map);
}

static ERL_NIF_TERM encode_decl_tag(ErlNifEnv* env, const struct btf_type* type, ERL_NIF_TERM map)
{
    enif_make_map_put(env, map, enif_make_atom(env, "type"), enif_make_uint(env, type->type), &map);
    // TODO: do something with `struct btf_decl_tag`.
    return bpf_sys_make_ok(env, map);
}

static ERL_NIF_TERM encode_type_tag(ErlNifEnv* env, const struct btf_type* type, ERL_NIF_TERM map)
{
    EBPF_DEBUG0("type tag");

    enif_make_map_put(env, map, enif_make_atom(env, "size"), enif_make_uint(env, type->size), &map);
    return bpf_sys_make_ok(env, map);
}

static ERL_NIF_TERM encode_enum64(ErlNifEnv* env, bpf_sys_btf_t* btf, const struct btf_type* type, ERL_NIF_TERM map)
{
    enif_make_map_put(env, map, enif_make_atom(env, "kflag"), enif_make_uint(env, btf_kflag(type)), &map);
    int vlen = btf_vlen(type);
    enif_make_map_put(env, map, enif_make_atom(env, "vlen"), enif_make_uint(env, vlen), &map);
    enif_make_map_put(env, map, enif_make_atom(env, "size"), enif_make_uint(env, type->size), &map);

    struct btf_enum64* values = btf_enum64(type);
    ERL_NIF_TERM* values_terms = enif_alloc(vlen * sizeof(*values_terms));

    for (int i = 0; i < vlen; ++i) {
        ERL_NIF_TERM value_map = enif_make_new_map(env);

        uint64_t value = (uint64_t)values[i].val_lo32 | ((uint64_t)values[i].val_hi32 << 32);
        enif_make_map_put(env, value_map, enif_make_atom(env, "val"), enif_make_uint64(env, value), &value_map);
        enif_make_map_put(env, value_map, enif_make_atom(env, "val_lo32"), enif_make_uint(env, values[i].val_lo32), &value_map);
        enif_make_map_put(env, value_map, enif_make_atom(env, "val_hi32"), enif_make_uint(env, values[i].val_hi32), &value_map);

        const char* name = btf__name_by_offset(btf->handle, values[i].name_off);
        if (!name || name[0] != '\0') {
            enif_make_map_put(env, value_map, enif_make_atom(env, "name"), bpf_sys_make_string(env, name), &value_map);
        }

        values_terms[i] = value_map;
    }

    enif_make_map_put(env, map, enif_make_atom(env, "enum64"), enif_make_list_from_array(env, values_terms, vlen), &map);
    enif_free(values_terms);

    return bpf_sys_make_ok(env, map);
}

static ERL_NIF_TERM btf_find(ErlNifEnv* env, bpf_sys_btf_t* btf, unsigned int id)
{
    const struct btf_type* type = btf__type_by_id(btf->handle, id);
    if (!type) {
        return ATOM_ERROR;
    }

    ERL_NIF_TERM map = enif_make_new_map(env);

    int kind = btf_kind(type);
    const char* name = type->name_off != 0 ? btf__name_by_offset(btf->handle, type->name_off) : NULL;
    if (name && name[0] != '\0') {
        enif_make_map_put(env, map, enif_make_atom(env, "name"), bpf_sys_make_string(env, name), &map);
    }

    enif_make_map_put(env, map, enif_make_atom(env, "kind"), bpf_sys_btf_kind_to_atom(env, kind), &map);

    switch (kind) {
    case BTF_KIND_INT:
        return encode_int(env, type, map);
    case BTF_KIND_PTR:
        return encode_ptr(env, type, map);
    case BTF_KIND_ARRAY:
        return encode_array(env, type, map);
    case BTF_KIND_STRUCT:
    case BTF_KIND_UNION:
        return encode_struct_or_union(env, btf, type, map);
    case BTF_KIND_ENUM:
        return encode_enum(env, btf, type, map);
    case BTF_KIND_FWD:
        return encode_fwd(env, type, map);
    case BTF_KIND_TYPEDEF:
        return encode_typedef(env, type, map);
    case BTF_KIND_VOLATILE:
    case BTF_KIND_CONST:
    case BTF_KIND_RESTRICT:
        return encode_type_modifier(env, type, map);
    case BTF_KIND_FUNC:
        return encode_func(env, type, map);
    case BTF_KIND_FUNC_PROTO:
        return encode_func_proto(env, btf, type, map);
    case BTF_KIND_VAR:
        return encode_var(env, type, map);
    case BTF_KIND_DATASEC:
        return encode_datasec(env, btf, type, map);
    case BTF_KIND_FLOAT:
        return encode_float(env, type, map);
    case BTF_KIND_DECL_TAG:
        return encode_decl_tag(env, type, map);
    case BTF_KIND_TYPE_TAG:
        return encode_type_tag(env, type, map);
    case BTF_KIND_ENUM64:
        return encode_enum64(env, btf, type, map);
    default:
        return ATOM_NIL;
    }
}

NIF(btf_find_by_name_nif)
{
    ERL_NIF_TERM result;

    bpf_sys_btf_t* btf;
    if (!enif_get_resource(env, argv[0], BPF_SYS_BTF_TYPE, (void**)&btf)) {
        return enif_make_badarg(env);
    }

    const char* name;
    if (!bpf_sys_get_string(env, argv[1], &name)) {
        return enif_make_badarg(env);
    }

    int id = btf__find_by_name(btf->handle, name);
    if (id < 0) {
        result = ATOM_ERROR;
        goto cleanup_name;
    }

    result = btf_find(env, btf, id);

cleanup_name:
    enif_free((void*)name);
    return result;
}

NIF(btf_find_by_id_nif)
{
    bpf_sys_btf_t* btf;
    if (!enif_get_resource(env, argv[0], BPF_SYS_BTF_TYPE, (void**)&btf)) {
        return enif_make_badarg(env);
    }

    unsigned int id;
    if (!enif_get_uint(env, argv[1], &id)) {
        return enif_make_badarg(env);
    }

    return btf_find(env, btf, id);
}

NIF(btf_endianness_nif)
{
    bpf_sys_btf_t* btf;
    if (!enif_get_resource(env, argv[0], BPF_SYS_BTF_TYPE, (void**)&btf)) {
        return enif_make_badarg(env);
    }

    enum btf_endianness endianness = btf__endianness(btf->handle);
    if (endianness == BTF_LITTLE_ENDIAN) {
        return enif_make_atom(env, "little");
    } else {
        return enif_make_atom(env, "big");
    }
}
