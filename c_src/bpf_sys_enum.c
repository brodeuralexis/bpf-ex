#include "bpf_sys_enum.h"

typedef struct {
    const char* str;
    ERL_NIF_TERM atom;
} bpf_sys_enum_value_t;

static bpf_sys_enum_value_t map_types[] = {
#define BPF_SYS_MAP_TYPE(_Value, Atom) \
    { Atom },
#include "enums/bpf_sys_map_type.inc"
#undef BPF_SYS_MAP_TYPE
};

static bpf_sys_enum_value_t attach_types[] = {
#define BPF_SYS_ATTACH_TYPE(_Value, Atom) \
    { Atom },
#include "enums/bpf_sys_attach_type.inc"
#undef BPF_SYS_ATTACH_TYPE
};

static bpf_sys_enum_value_t prog_types[] = {
#define BPF_SYS_PROG_TYPE(_Value, Atom) \
    { Atom },
#include "enums/bpf_sys_prog_type.inc"
#undef BPF_SYS_PROG_TYPE
};

static bpf_sys_enum_value_t link_types[] = {
#define BPF_SYS_LINK_TYPE(_Value, Atom) \
    { Atom },
#include "enums/bpf_sys_link_type.inc"
#undef BPF_SYS_LINK_TYPE
};

static bpf_sys_enum_value_t btf_kinds[] = {
#define BPF_SYS_BTF_KIND(_Value, Atom) \
    { Atom },
#include "enums/bpf_sys_btf_kind.inc"
#undef BPF_SYS_BTF_KIND
};

#define INIT_ENUM(Enum)                                         \
    for (size_t i = 0; i < sizeof(Enum) / sizeof(*Enum); ++i) { \
        Enum[i].atom = enif_make_atom(env, Enum[i].str);        \
    }

#define FOR_EACH_ENUM(enum, i) \
    for (size_t i = 0; i < sizeof(enum) / sizeof(*enum); ++i)

int bpf_sys_enum_load(ErlNifEnv* env, void** priv, ERL_NIF_TERM info_term)
{
    INIT_ENUM(map_types)
    INIT_ENUM(attach_types)
    INIT_ENUM(prog_types)
    INIT_ENUM(link_types)
    INIT_ENUM(btf_kinds);

    return 0;
}

ERL_NIF_TERM bpf_sys_map_type_to_atom(ErlNifEnv* env, enum bpf_map_type type)
{
    return map_types[type].atom;
}

bool bpf_sys_atom_to_map_type(ErlNifEnv* env, ERL_NIF_TERM term, enum bpf_map_type* type)
{
    FOR_EACH_ENUM(map_types, i)
    {
        if (enif_compare(map_types[i].atom, term) == 0) {
            *type = i;
            return true;
        }
    }

    return false;
}

bool bpf_sys_map_is_per_cpu(enum bpf_map_type type)
{
    switch (type) {
    case BPF_MAP_TYPE_PERCPU_ARRAY:
    case BPF_MAP_TYPE_PERCPU_HASH:
    case BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE:
    case BPF_MAP_TYPE_LRU_PERCPU_HASH:
        return true;
    default:
        return false;
    }
}

ERL_NIF_TERM bpf_sys_attach_type_to_atom(ErlNifEnv* env, enum bpf_attach_type type)
{
    return attach_types[type].atom;
}

bool bpf_sys_atom_to_attach_type(ErlNifEnv* env, ERL_NIF_TERM term, enum bpf_attach_type* type)
{
    FOR_EACH_ENUM(attach_types, i)
    {
        if (enif_compare(attach_types[i].atom, term) == 0) {
            *type = i;
            return true;
        }
    }

    return false;
}

ERL_NIF_TERM bpf_sys_link_type_to_atom(ErlNifEnv* env, enum bpf_link_type type)
{
    return link_types[type].atom;
}

bool bpf_sys_atom_to_link_type(ErlNifEnv* env, ERL_NIF_TERM term, enum bpf_link_type* type)
{
    FOR_EACH_ENUM(link_types, i)
    {
        if (enif_compare(link_types[i].atom, term) == 0) {
            *type = i;
            return true;
        }
    }

    return false;
}

ERL_NIF_TERM bpf_sys_prog_type_to_atom(ErlNifEnv* env, enum bpf_prog_type type)
{
    return prog_types[type].atom;
}

bool bpf_sys_atom_to_prog_type(ErlNifEnv* env, ERL_NIF_TERM term, enum bpf_prog_type* type)
{
    FOR_EACH_ENUM(prog_types, i)
    {
        if (enif_compare(prog_types[i].atom, term) == 0) {
            *type = i;
            return true;
        }
    }

    return false;
}

ERL_NIF_TERM bpf_sys_btf_kind_to_atom(ErlNifEnv* env, int type)
{
    return btf_kinds[type].atom;
}

bool bpf_sys_atom_to_btf_kind(ErlNifEnv* env, ERL_NIF_TERM term, int* type)
{
    FOR_EACH_ENUM(btf_kinds, i)
    {
        if (enif_compare(btf_kinds[i].atom, term) == 0) {
            *type = i;
            return true;
        }
    }

    return false;
}
