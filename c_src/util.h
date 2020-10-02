#pragma once

#include <stddef.h>

#include <erl_nif.h>
#include <gmp.h>

int get_bigint(ErlNifEnv *, ERL_NIF_TERM, mpz_t);

ERL_NIF_TERM get_tuple_elem(ErlNifEnv *, ERL_NIF_TERM, int);

ERL_NIF_TERM make_atom(ErlNifEnv *, const char *);
ERL_NIF_TERM make_binary(ErlNifEnv *, const mpz_t);

ERL_NIF_TERM paillier_internal_error(ErlNifEnv *);

void *paillier_alloc(size_t);
void *paillier_realloc(void *, size_t, size_t);
void paillier_free(void *, size_t);
