#ifndef __BPF_SYS_ENUM__
#define __BPF_SYS_ENUM__

#include <stdbool.h>

#include <bpf/libbpf.h>
#include <erl_nif.h>

int bpf_sys_enum_load(ErlNifEnv* env, void** priv, ERL_NIF_TERM info_term);

ERL_NIF_TERM bpf_sys_map_type_to_atom(ErlNifEnv* env, enum bpf_map_type type);

bool bpf_sys_atom_to_map_type(ErlNifEnv* env, ERL_NIF_TERM term, enum bpf_map_type* type);

ERL_NIF_TERM bpf_sys_link_type_to_atom(ErlNifEnv* env, enum bpf_link_type type);

bool bpf_sys_atom_to_link_type(ErlNifEnv* env, ERL_NIF_TERM term, enum bpf_link_type* type);

ERL_NIF_TERM bpf_sys_attach_type_to_atom(ErlNifEnv* env, enum bpf_attach_type type);

bool bpf_sys_atom_to_attach_type(ErlNifEnv* env, ERL_NIF_TERM term, enum bpf_attach_type* type);

ERL_NIF_TERM bpf_sys_prog_type_to_atom(ErlNifEnv* env, enum bpf_prog_type type);

bool bpf_sys_atom_to_prog_type(ErlNifEnv* env, ERL_NIF_TERM term, enum bpf_prog_type* type);

ERL_NIF_TERM bpf_sys_btf_kind_to_atom(ErlNifEnv* env, int type);

bool bpf_sys_atom_to_btf_kind(ErlNifEnv* env, ERL_NIF_TERM term, int* type);

#endif
