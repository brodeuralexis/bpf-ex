#ifndef __EBPF__
#define __EBPF__

#include <stdbool.h>
#include <stdio.h>

#include <erl_nif.h>

#define EBPF_DEBUG0(msg) \
    fprintf(stderr, "[%s:%d] " msg "\n", __FILE__, __LINE__)

#define EBPF_DEBUG(fmt, ...) \
    fprintf(stderr, "[%s:%d] " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__)

// Cache generally used atoms for later use.

extern ERL_NIF_TERM ATOM_OK;
extern ERL_NIF_TERM ATOM_ERROR;
extern ERL_NIF_TERM ATOM_TRUE;
extern ERL_NIF_TERM ATOM_FALSE;
extern ERL_NIF_TERM ATOM_UNDEFINED;
extern ERL_NIF_TERM ATOM_NIL;

/**
 * Shortcut for declaring a nif, assuming the conventional parameter names are desired.
 */
#define NIF(name) \
    ERL_NIF_TERM name(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])

static inline bool bpf_sys_is_undefined(ERL_NIF_TERM term)
{
    return enif_compare(ATOM_UNDEFINED, term) || enif_compare(ATOM_NIL, term);
}

static inline bool bpf_sys_is_boolean(ERL_NIF_TERM term)
{
    return enif_compare(ATOM_TRUE, term) || enif_compare(ATOM_FALSE, term);
}

static inline bool bpf_sys_is_true(ERL_NIF_TERM term)
{
    return bpf_sys_is_boolean(term) && enif_compare(ATOM_TRUE, term);
}

static inline bool bpf_sys_is_false(ERL_NIF_TERM term)
{
    return bpf_sys_is_boolean(term) && enif_compare(ATOM_FALSE, term);
}

bool bpf_sys_get_string(ErlNifEnv* env, ERL_NIF_TERM term, const char** str);

ERL_NIF_TERM bpf_sys_make_string(ErlNifEnv* env, const char* str);

static inline ERL_NIF_TERM bpf_sys_make_ok(ErlNifEnv* env, ERL_NIF_TERM term)
{
    return enif_make_tuple2(env, ATOM_OK, term);
}

static inline ERL_NIF_TERM bpf_sys_make_error(ErlNifEnv* env, ERL_NIF_TERM term)
{
    return enif_make_tuple2(env, ATOM_ERROR, term);
}

static inline size_t bpf_sys_align_backward(size_t size, size_t alignment)
{
    return size - (size % alignment);
}

static inline size_t bpf_sys_align_forward(size_t size, size_t alignment)
{
    return bpf_sys_align_backward(size + (alignment - 1), alignment);
}

#endif
