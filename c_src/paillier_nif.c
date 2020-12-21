#include <erl_nif.h>
#include <gmp.h>

#include "paillier.h"
#include "util.h"

static int get_public_key(ErlNifEnv *env, ERL_NIF_TERM term, paillier_pubkey_t *pub) {
    int arity;
    const ERL_NIF_TERM *tuple;

    if (!enif_get_tuple(env, term, &arity, &tuple) || arity != 4) {
        return 0;
    }

    return enif_get_uint(env, tuple[0], &pub->bits)   &&
           get_bigint(env, tuple[1], pub->n)         &&
           get_bigint(env, tuple[2], pub->n_plusone) &&
           get_bigint(env, tuple[3], pub->n_squared);
}

static int get_keypair(ErlNifEnv *env, ERL_NIF_TERM term, paillier_pubkey_t *pub, paillier_prvkey_t *prv) {
    int arity;
    const ERL_NIF_TERM *tuple;

    if (!enif_get_tuple(env, term, &arity, &tuple) || arity != 6) {
        return 0;
    }

    return enif_get_uint(env, tuple[0], &pub->bits)   &&
           get_bigint(env, tuple[1], pub->n)         &&
           get_bigint(env, tuple[2], pub->n_plusone) &&
           get_bigint(env, tuple[3], pub->n_squared) &&
           get_bigint(env, tuple[4], prv->lambda)    &&
           get_bigint(env, tuple[5], prv->x);
}

static ERL_NIF_TERM make_keypair(ErlNifEnv *env, paillier_pubkey_t *pub, paillier_prvkey_t *prv) {
    ERL_NIF_TERM key_length = enif_make_uint(env, pub->bits);

    ERL_NIF_TERM n = make_binary(env, pub->n);
    ERL_NIF_TERM g = make_binary(env, pub->n_plusone);
    ERL_NIF_TERM n2 = make_binary(env, pub->n_squared);

    ERL_NIF_TERM lambda = make_binary(env, prv->lambda);
    ERL_NIF_TERM mu = make_binary(env, prv->x);

    ERL_NIF_TERM public = enif_make_tuple4(env, key_length, n, g, n2);
    ERL_NIF_TERM private = enif_make_tuple6(env, key_length, n, g, n2, lambda, mu);

    return enif_make_tuple2(env, public, private);
}

static ERL_NIF_TERM keypair(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned int key_length;
    paillier_pubkey_t *pub;
    paillier_prvkey_t *prv;

    if (argc != 1 || !enif_get_uint(env, argv[0], &key_length)) {
        return enif_make_badarg(env);
    }

    paillier_keygen(key_length, &pub, &prv, paillier_get_rand_devurandom);
    ERL_NIF_TERM keypair = make_keypair(env, pub, prv);
    paillier_freepubkey(pub);
    paillier_freeprvkey(prv);

    return keypair;
}

static ERL_NIF_TERM encrypt_nif(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    paillier_pubkey_t pub;
    paillier_plaintext_t plaintext;
    paillier_ciphertext_t ciphertext;

    mpz_init(pub.n);
    mpz_init(pub.n_plusone);
    mpz_init(pub.n_squared);
    mpz_init(plaintext.m);
    mpz_init(ciphertext.c);

    if (argc != 2 || !get_public_key(env, argv[0], &pub) || !get_bigint(env, argv[1], plaintext.m)) {
        enif_make_badarg(env);
    }

    paillier_enc(&ciphertext, &pub, &plaintext, paillier_get_rand_devurandom);
    mpz_clear(pub.n);
    mpz_clear(pub.n_plusone);
    mpz_clear(pub.n_squared);
    mpz_clear(plaintext.m);

    ERL_NIF_TERM result_term = make_binary(env, ciphertext.c);
    mpz_clear(ciphertext.c);
    return result_term;
}

static ERL_NIF_TERM decrypt_nif(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    paillier_pubkey_t pub;
    paillier_prvkey_t prv;
    paillier_plaintext_t plaintext;
    paillier_ciphertext_t ciphertext;

    mpz_init(pub.n);
    mpz_init(pub.n_plusone);
    mpz_init(pub.n_squared);
    mpz_init(prv.lambda);
    mpz_init(prv.x);
    mpz_init(plaintext.m);
    mpz_init(ciphertext.c);

    if (argc != 2 || !get_keypair(env, argv[0], &pub, &prv) || !get_bigint(env, argv[1], ciphertext.c)) {
        enif_make_badarg(env);
    }

    paillier_dec(&plaintext, &pub, &prv, &ciphertext);
    mpz_clear(pub.n);
    mpz_clear(pub.n_plusone);
    mpz_clear(pub.n_squared);
    mpz_clear(prv.lambda);
    mpz_clear(prv.x);
    mpz_clear(ciphertext.c);

    ERL_NIF_TERM result_term = make_binary(env, plaintext.m);
    mpz_clear(plaintext.m);
    return result_term;
}

static ERL_NIF_TERM add(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    mpz_t a, b, n2, result;

    mpz_init(a);
    mpz_init(b);
    mpz_init(n2);
    mpz_init(result);

    if (argc != 3) {
        return enif_make_badarg(env);
    }
    ERL_NIF_TERM n2_term = get_tuple_elem(env, argv[0], 3);
    if (!get_bigint(env, n2_term, n2) || !get_bigint(env, argv[1], a) || !get_bigint(env, argv[2], b)) {
        return enif_make_badarg(env);
    }

    mpz_mul(result, a, b);
    mpz_mod(result, result, n2);
    mpz_clear(a);
    mpz_clear(b);
    mpz_clear(n2);

    ERL_NIF_TERM result_term = make_binary(env, result);
    mpz_clear(result);
    return result_term;
}

static ERL_NIF_TERM mul_nif(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    mpz_t a, b, n2, result;

    mpz_init(a);
    mpz_init(b);
    mpz_init(n2);
    mpz_init(result);

    if (argc != 3) {
        return enif_make_badarg(env);
    }

    ERL_NIF_TERM n2_term = get_tuple_elem(env, argv[0], 3);
    if (!get_bigint(env, n2_term, n2) || !get_bigint(env, argv[1], a) || !get_bigint(env, argv[2], b)) {
        return enif_make_badarg(env);
    }

    mpz_powm(result, a, b, n2);
    mpz_clear(a);
    mpz_clear(b);
    mpz_clear(n2);

    ERL_NIF_TERM result_term = make_binary(env, result);
    mpz_clear(result);
    return result_term;
}

// Initialization.

static ErlNifFunc nif_functions[] = {
    { .name = "keypair"    , .arity = 1, .fptr = keypair    , .flags = 0 },
    { .name = "encrypt_nif", .arity = 2, .fptr = encrypt_nif, .flags = 0 },
    { .name = "decrypt_nif", .arity = 2, .fptr = decrypt_nif, .flags = 0 },
    { .name = "add"        , .arity = 3, .fptr = add        , .flags = 0 },
    { .name = "mul_nif"    , .arity = 3, .fptr = mul_nif    , .flags = 0 },
};

static int load(ErlNifEnv *env, void **priv_data, ERL_NIF_TERM load_info) {
    // Make GMP use erlang's NIF memory functions.
    mp_set_memory_functions(paillier_alloc, paillier_realloc, paillier_free);
    return 0;
}

ERL_NIF_INIT(paillier, nif_functions, load, NULL, NULL, NULL);
