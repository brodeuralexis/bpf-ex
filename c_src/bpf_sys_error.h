#ifndef __BPF_SYS_ERRNO__
#define __BPF_SYS_ERRNO__

#include <erl_nif.h>

ERL_NIF_TERM errno_to_atom(ErlNifEnv* env);

ERL_NIF_TERM errno_to_result(ErlNifEnv* env);

#endif
