#include "bpf_sys_object.h"

#include "bpf_sys_btf.h"
#include "bpf_sys_error.h"
#include "bpf_sys_map.h"
#include "bpf_sys_program.h"

#define DEFAULT_LOG_BUFFER_SIZE (64 * 1024) // Same as Cilium's

ErlNifResourceType* BPF_SYS_OBJECT_TYPE;

static ERL_NIF_TERM ATOM_OBJECT_NAME;
static ERL_NIF_TERM ATOM_RELAXED_MAPS;
static ERL_NIF_TERM ATOM_PIN_ROOT_PATH;
static ERL_NIF_TERM ATOM_KCONFIG;
static ERL_NIF_TERM ATOM_BTF_CUSTOM_PATH;

static void ebpf_object_dtor(ErlNifEnv* env, void* resource)
{
    bpf_sys_object_t* object = resource;

    for (size_t i = 0; i < object->num_maps; ++i) {
        enif_release_resource(object->maps[i]);
    }

    for (size_t i = 0; i < object->num_programs; ++i) {
        enif_release_resource(object->programs[i]);
    }

    enif_free(object->maps);
    enif_free(object->programs);

    if (object->btf) {
        enif_release_resource(object->btf);
    }

    enif_free(object->log_buffer);

    bpf_object__close(object->handle);
}

int bpf_sys_object_load(ErlNifEnv* env, void** priv, ERL_NIF_TERM info_term)
{
    BPF_SYS_OBJECT_TYPE = enif_open_resource_type(env, NULL, "bpf_sys_object", ebpf_object_dtor, ERL_NIF_RT_CREATE, NULL);

    ATOM_OBJECT_NAME = enif_make_atom(env, "object_name");
    ATOM_RELAXED_MAPS = enif_make_atom(env, "relaxed_maps");
    ATOM_PIN_ROOT_PATH = enif_make_atom(env, "pin_root_path");
    ATOM_KCONFIG = enif_make_atom(env, "kconfig");
    ATOM_BTF_CUSTOM_PATH = enif_make_atom(env, "btf_custom_path");

    return 0;
}

static ERL_NIF_TERM do_open(ErlNifEnv* env, struct bpf_object* handle, char* kernel_log_buf)
{
    bpf_sys_object_t* object = enif_alloc_resource(BPF_SYS_OBJECT_TYPE, sizeof(*object));
    object->handle = handle;

    object->num_maps = 0;
    object->num_programs = 0;

    struct bpf_map* map_handle = NULL;
    struct bpf_program* program_handle = NULL;

    bpf_object__for_each_map(map_handle, handle)
    {
        object->num_maps++;
    }

    bpf_object__for_each_program(program_handle, handle)
    {
        object->num_programs++;
    }

    object->maps = enif_alloc(sizeof(*object->maps) * object->num_maps);
    object->programs = enif_alloc(sizeof(*object->programs) * object->num_programs);

    size_t i = 0;
    bpf_object__for_each_map(map_handle, handle)
    {
        bpf_sys_map_t* map = object->maps[i] = enif_alloc_resource(BPF_SYS_MAP_TYPE, sizeof(*map));
        map->handle = map_handle;

        i++;
    }

    i = 0;
    bpf_object__for_each_program(program_handle, handle)
    {
        bpf_sys_program_t* program = object->programs[i] = enif_alloc_resource(BPF_SYS_PROGRAM_TYPE, sizeof(*program));
        program->handle = program_handle;

        i++;
    }

    struct btf* btf_handle = bpf_object__btf(object->handle);
    object->btf = NULL;
    if (btf_handle) {
        bpf_sys_btf_t* btf = object->btf = enif_alloc_resource(BPF_SYS_BTF_TYPE, sizeof(*btf));
        btf->handle = btf_handle;
        btf->owned = false;
    }

    object->log_buffer = kernel_log_buf;
    object->log_size = DEFAULT_LOG_BUFFER_SIZE;

    ERL_NIF_TERM object_term = enif_make_resource(env, object);
    enif_release_resource(object);
    return bpf_sys_make_ok(env, object_term);
}

NIF(object_open_file_nif)
{
    ERL_NIF_TERM result;

    const char* path;

    if (!bpf_sys_get_string(env, argv[0], &path)) {
        return enif_make_badarg(env);
    }

    if (!enif_is_list(env, argv[1])) {
        result = enif_make_badarg(env);
        goto cleanup_path;
    }

    struct bpf_object_open_opts opts;
    memset(&opts, 0, sizeof(opts));
    opts.sz = sizeof(opts);

    ERL_NIF_TERM head;
    ERL_NIF_TERM list = argv[1];
    while (enif_get_list_cell(env, list, &head, &list)) {
        if (!enif_is_tuple(env, head)) {
            result = enif_make_badarg(env);
            goto cleanup_opts;
        }

        int arity;
        const ERL_NIF_TERM* array;
        if (!enif_get_tuple(env, head, &arity, &array)) {
            result = enif_make_badarg(env);
            goto cleanup_opts;
        }

        if (arity != 2) {
            result = enif_make_badarg(env);
            goto cleanup_opts;
        }

        ERL_NIF_TERM key = array[0];
        ERL_NIF_TERM value = array[1];

        if (enif_compare(ATOM_OBJECT_NAME, key) == 0) {
            if (opts.object_name) {
                enif_free((void*)opts.object_name);
                opts.object_name = NULL;
            }

            if (!bpf_sys_get_string(env, value, &opts.object_name)) {
                result = enif_make_badarg(env);
                goto cleanup_opts;
            }
        } else if (enif_compare(ATOM_RELAXED_MAPS, key) == 0) {
            if (!bpf_sys_is_boolean(value)) {
                result = enif_make_badarg(env);
                goto cleanup_opts;
            }

            opts.relaxed_maps = bpf_sys_is_true(value);
        } else if (enif_compare(ATOM_PIN_ROOT_PATH, key) == 0) {
            if (opts.pin_root_path) {
                enif_free((void*)opts.pin_root_path);
                opts.pin_root_path = NULL;
            }

            if (!bpf_sys_get_string(env, value, &opts.pin_root_path)) {
                result = enif_make_badarg(env);
                goto cleanup_opts;
            }
        } else if (enif_compare(ATOM_KCONFIG, key) == 0) {
            if (opts.kconfig) {
                enif_free((void*)opts.kconfig);
                opts.kconfig = NULL;
            }

            if (!bpf_sys_get_string(env, value, &opts.kconfig)) {
                result = enif_make_badarg(env);
                goto cleanup_opts;
            }
        } else if (enif_compare(ATOM_BTF_CUSTOM_PATH, key) == 0) {
            if (opts.btf_custom_path) {
                enif_free((void*)opts.btf_custom_path);
                opts.btf_custom_path = NULL;
            }

            if (!bpf_sys_get_string(env, value, &opts.btf_custom_path)) {
                result = enif_make_badarg(env);
                goto cleanup_opts;
            }
        } else {
            result = enif_make_badarg(env);
            goto cleanup_opts;
        }
    }

    opts.kernel_log_buf = enif_alloc(sizeof(*opts.kernel_log_buf) * DEFAULT_LOG_BUFFER_SIZE);
    opts.kernel_log_size = DEFAULT_LOG_BUFFER_SIZE;
    opts.kernel_log_level = 1;

    struct bpf_object* handle = bpf_object__open_file(path, &opts);
    if (!handle) {
        result = errno_to_result(env);
        goto cleanup_opts;
    }

    result = do_open(env, handle, opts.kernel_log_buf);

cleanup_opts:
    if (opts.object_name) {
        enif_free((void*)opts.object_name);
    }

    if (opts.pin_root_path) {
        enif_free((void*)opts.pin_root_path);
    }

    if (opts.kconfig) {
        enif_free((void*)opts.kconfig);
    }

    if (opts.btf_custom_path) {
        enif_free((void*)opts.btf_custom_path);
    }
cleanup_path:
    enif_free((void*)path);
    return result;
}

NIF(object_load_nif)
{
    bpf_sys_object_t* object;
    if (!enif_get_resource(env, argv[0], BPF_SYS_OBJECT_TYPE, (void**)&object)) {
        return enif_make_badarg(env);
    }

    if (bpf_object__load(object->handle) < 0) {
        return bpf_sys_make_error(env, enif_make_tuple2(env, errno_to_atom(env), bpf_sys_make_string(env, object->log_buffer)));
    }

    return ATOM_OK;
}

NIF(object_pin_maps_nif)
{
    ERL_NIF_TERM result;

    bpf_sys_object_t* object;
    if (!enif_get_resource(env, argv[0], BPF_SYS_OBJECT_TYPE, (void**)&object)) {
        return enif_make_badarg(env);
    }

    const char* path = NULL;
    if (!bpf_sys_is_undefined(argv[1]) && !bpf_sys_get_string(env, argv[1], &path)) {
        return enif_make_badarg(env);
    }

    if (bpf_object__pin_maps(object->handle, path) < 0) {
        result = errno_to_result(env);
        goto cleanup_path;
    }

    result = ATOM_OK;

cleanup_path:
    if (path) {
        enif_free((void*)path);
    }

    return result;
}

NIF(object_unpin_maps_nif)
{
    ERL_NIF_TERM result;

    bpf_sys_object_t* object;
    if (!enif_get_resource(env, argv[0], BPF_SYS_OBJECT_TYPE, (void**)&object)) {
        return enif_make_badarg(env);
    }

    const char* path = NULL;
    if (!bpf_sys_is_undefined(argv[1]) && !bpf_sys_get_string(env, argv[1], &path)) {
        return enif_make_badarg(env);
    }

    if (bpf_object__unpin_maps(object->handle, path) < 0) {
        result = errno_to_result(env);
        goto cleanup_path;
    }

    result = ATOM_OK;

cleanup_path:
    if (path) {
        enif_free((void*)path);
    }

    return result;
}

NIF(object_pin_programs_nif)
{
    ERL_NIF_TERM result;

    bpf_sys_object_t* object;
    if (!enif_get_resource(env, argv[0], BPF_SYS_OBJECT_TYPE, (void**)&object)) {
        return enif_make_badarg(env);
    }

    const char* path = NULL;
    if (!bpf_sys_is_undefined(argv[1]) && !bpf_sys_get_string(env, argv[1], &path)) {
        return enif_make_badarg(env);
    }

    if (bpf_object__pin_programs(object->handle, path) < 0) {
        result = errno_to_result(env);
        goto cleanup_path;
    }

    result = ATOM_OK;

cleanup_path:
    if (path) {
        enif_free((void*)path);
    }

    return result;
}

NIF(object_unpin_programs_nif)
{
    ERL_NIF_TERM result;

    bpf_sys_object_t* object;
    if (!enif_get_resource(env, argv[0], BPF_SYS_OBJECT_TYPE, (void**)&object)) {
        return enif_make_badarg(env);
    }

    const char* path = NULL;
    if (!bpf_sys_is_undefined(argv[1]) && !bpf_sys_get_string(env, argv[1], &path)) {
        return enif_make_badarg(env);
    }

    if (bpf_object__unpin_programs(object->handle, path) < 0) {
        result = errno_to_result(env);
        goto cleanup_path;
    }

    result = ATOM_OK;

cleanup_path:
    if (path) {
        enif_free((void*)path);
    }

    return result;
}

NIF(object_name_nif)
{
    bpf_sys_object_t* object;
    if (!enif_get_resource(env, argv[0], BPF_SYS_OBJECT_TYPE, (void**)&object)) {
        return enif_make_badarg(env);
    }

    const char* name = bpf_object__name(object->handle);
    return bpf_sys_make_string(env, name);
}

NIF(object_kversion_nif)
{
    bpf_sys_object_t* object;
    if (!enif_get_resource(env, argv[0], BPF_SYS_OBJECT_TYPE, (void**)&object)) {
        return enif_make_badarg(env);
    }

    unsigned int kversion = bpf_object__kversion(object->handle);
    return enif_make_uint(env, kversion);
}

NIF(object_set_kversion_nif)
{
    bpf_sys_object_t* object;
    if (!enif_get_resource(env, argv[0], BPF_SYS_OBJECT_TYPE, (void**)&object)) {
        return enif_make_badarg(env);
    }

    unsigned int kversion;
    if (!enif_get_uint(env, argv[1], &kversion)) {
        return enif_make_badarg(env);
    }

    if (bpf_object__set_kversion(object->handle, kversion) < 0) {
        return errno_to_result(env);
    }

    return ATOM_OK;
}

NIF(object_btf_nif)
{
    bpf_sys_object_t* object;
    if (!enif_get_resource(env, argv[0], BPF_SYS_OBJECT_TYPE, ((void**)&object))) {
        return enif_make_badarg(env);
    }

    if (!object->btf) {
        return ATOM_UNDEFINED;
    }

    return enif_make_resource(env, object->btf);
}

NIF(object_maps_nif)
{
    bpf_sys_object_t* object;
    if (!enif_get_resource(env, argv[0], BPF_SYS_OBJECT_TYPE, ((void**)&object))) {
        return enif_make_badarg(env);
    }

    ERL_NIF_TERM* maps_terms = enif_alloc(sizeof(*maps_terms) * object->num_maps);
    for (size_t i = 0; i < object->num_maps; ++i) {
        maps_terms[i] = enif_make_resource(env, object->maps[i]);
    }

    return enif_make_list_from_array(env, maps_terms, object->num_maps);
}

NIF(object_programs_nif)
{
    bpf_sys_object_t* object;
    if (!enif_get_resource(env, argv[0], BPF_SYS_OBJECT_TYPE, ((void**)&object))) {
        return enif_make_badarg(env);
    }

    ERL_NIF_TERM* programs_terms = enif_alloc(sizeof(*programs_terms) * object->num_programs);
    for (size_t i = 0; i < object->num_programs; ++i) {
        programs_terms[i] = enif_make_resource(env, object->programs[i]);
    }

    return enif_make_list_from_array(env, programs_terms, object->num_programs);
}
