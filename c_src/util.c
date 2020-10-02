#include "util.h"

int get_bigint(ErlNifEnv *env, ERL_NIF_TERM bin_term, mpz_t result) {
    ErlNifBinary binary;

    if (!enif_inspect_binary(env, bin_term, &binary)) {
        return 0;
    }
    mpz_import(result, binary.size, 1, 1, 1, 0, binary.data);
    return 1;
}

ERL_NIF_TERM get_tuple_elem(ErlNifEnv *env, ERL_NIF_TERM term, int i) {
    int arity;
    const ERL_NIF_TERM *tuple;

    if (!enif_get_tuple(env, term, &arity, &tuple) || i >= arity) {
        return enif_make_badarg(env);
    }
    return tuple[i];
}

ERL_NIF_TERM make_atom(ErlNifEnv *env, const char *name) {
    ERL_NIF_TERM atom;

    if (enif_make_existing_atom(env, name, &atom, ERL_NIF_LATIN1)) {
        return atom;
    }
    return enif_make_atom(env, name);
}

ERL_NIF_TERM make_binary(ErlNifEnv *env, const mpz_t x) {
    size_t count;
    ErlNifBinary binary;

    // Calculate the required binary size.
    count = (mpz_sizeinbase(x, 2) + 8 - 1) / 8;
    // Allocate binary and write data.
    if (!enif_alloc_binary(count, &binary)) {
        return paillier_internal_error(env);
    }
    mpz_export(binary.data, &count, 1, 1, 1, 0, x);
    binary.size = count;

    return enif_make_binary(env, &binary);
}

ERL_NIF_TERM paillier_internal_error(ErlNifEnv *env) {
    return enif_raise_exception(env, make_atom(env, "paillier_internal_error"));
}

void *paillier_alloc(size_t size) {
    return enif_alloc(size);
}

void *paillier_realloc(void *ptr, size_t old_size, size_t new_size) {
    return enif_realloc(ptr, new_size);
}

void paillier_free(void *ptr, size_t size) {
    return enif_free(ptr);
}
