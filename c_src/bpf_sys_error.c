#include "bpf_sys_error.h"

#include <errno.h>

#include "bpf_sys.h"

static struct {
    const char* atom;
} errnos[] = {
    { NULL },
#define BPF_SYS_ERRNO(_Id, _UpperName, LowerName, _Description) \
    { LowerName },
#include "bpf_sys_errno.inc"
#undef BPF_SYS_ERRNO
};

ERL_NIF_TERM errno_to_atom(ErlNifEnv* env)
{
    return enif_make_atom(env, errnos[errno].atom);
}

ERL_NIF_TERM errno_to_result(ErlNifEnv* env)
{
    return bpf_sys_make_error(env, errno_to_atom(env));
}
