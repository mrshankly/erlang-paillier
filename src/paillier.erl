-module(paillier).

-export([keypair/1, encrypt/2, decrypt/2, add/3, mul/3]).

-on_load(init/0).

-define(APPNAME, paillier).
-define(LIBNAME, paillier).

-type key_length() :: non_neg_integer().
-type public_key() :: {key_length(), binary(), binary(), binary()}.
-type private_key() :: {key_length(), binary(), binary(), binary(), binary(), binary()}.

-type plaintext() :: non_neg_integer().
-type ciphertext() :: binary().

%% API

-spec keypair(key_length()) -> {public_key(), private_key()}.
keypair(_KeyLength) ->
    not_loaded(?LINE).

-spec encrypt(public_key(), plaintext()) -> ciphertext().
encrypt(PublicKey, Plaintext) when Plaintext >= 0 ->
    encrypt_nif(PublicKey, binary:encode_unsigned(Plaintext)).

-spec decrypt(public_key(), ciphertext()) -> plaintext().
decrypt(PrivateKey, Ciphertext) ->
    Result = decrypt_nif(PrivateKey, Ciphertext),
    binary:decode_unsigned(Result).

-spec add(public_key(), ciphertext(), ciphertext()) -> ciphertext().
add(_PublicKey, _A, _B) ->
    not_loaded(?LINE).

-spec mul(public_key(), ciphertext(), plaintext()) -> ciphertext().
mul(PublicKey, A, B) when B >= 0 ->
    mul_nif(PublicKey, A, binary:encode_unsigned(B)).

%% Internal functions.

encrypt_nif(_PublicKey, _Binary) ->
    not_loaded(?LINE).

decrypt_nif(_PrivateKey, _Binary) ->
    not_loaded(?LINE).

mul_nif(_PublicKey, _A, _B) ->
    not_loaded(?LINE).

init() ->
    PrivDir =
        case code:priv_dir(?APPNAME) of
            {error, _} ->
                EbinDir = filename:dirname(code:which(?MODULE)),
                AppPath = filename:dirname(EbinDir),
                filename:join(AppPath, "priv");
            Path ->
                Path
        end,
    erlang:load_nif(filename:join(PrivDir, ?APPNAME), 0).

not_loaded(Line) ->
    erlang:nif_error({not_loaded, [{module, ?MODULE}, {line, Line}]}).
