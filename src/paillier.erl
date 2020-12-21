%%% @doc Module paillier implements NIF bindings to the
%%% <a href="http://hms.isi.jhu.edu/acsc/libpaillier/"><tt>libpaillier</tt></a>
%%% cryptographic library.
%%% @end.
-module(paillier).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

-export([keypair/1, encrypt/2, decrypt/2, add/3, mul/3]).

-export_type([public_key/0, private_key/0, keypair/0]).

-on_load(init/0).

-type key_length() :: non_neg_integer().
-type public_key() :: {key_length(), binary(), binary(), binary()}.
-type private_key() :: {key_length(), binary(), binary(), binary(), binary(), binary()}.
-type keypair() :: {public_key(), private_key()}.

-type plaintext() :: non_neg_integer().
-type ciphertext() :: binary().

%%% ===========================================================================
%%% API
%%% ===========================================================================

%% @doc Generates a new public/private keypair.
%%
%% Generates and returns a new key pair of length `KeyLength' for the Paillier
%% encryption scheme. The return value is a two element tuple, where the first
%% element represents the public key, and the second element represents the
%% private key.
%% @end.
-spec keypair(key_length()) -> keypair().
keypair(_KeyLength) ->
    not_loaded(?LINE).

%% @doc Encrypts a number.
%%
%% Encrypts the number `Plaintext` using the public key `PublicKey'. Returns
%% the ciphertext in binary form.
%% @end.
-spec encrypt(public_key(), plaintext()) -> ciphertext().
encrypt(PublicKey, Plaintext) when Plaintext >= 0 ->
    encrypt_nif(PublicKey, binary:encode_unsigned(Plaintext)).

%% @doc Decrypts a ciphertext into a number.
%%
%% Decrypts `Ciphertext' using the private key `PrivateKey'. Returns the
%% plaintext number.
%% @end.
-spec decrypt(private_key(), ciphertext()) -> plaintext().
decrypt(PrivateKey, Ciphertext) ->
    Result = decrypt_nif(PrivateKey, Ciphertext),
    binary:decode_unsigned(Result).

%% @doc Performs the addition of two ciphertexts.
%% 
%% Performs the homomorphic addition of the ciphertexts `A' and `B'. Returns
%% a ciphertext that will decrypt to the sum of the plaintext value of `A'
%% and `B'.
%% @end.
-spec add(public_key(), ciphertext(), ciphertext()) -> ciphertext().
add(_PublicKey, _A, _B) ->
    not_loaded(?LINE).

%% @doc Multiplies a ciphertext by a plaintext.
%% 
%% Performs the homomorphic multiplication of the ciphertext `A' by the
%% plaintext `B'. Returns a ciphertext that will decrypt to the product of the
%% plaintext value of `A' by `B'.
%% @end.
-spec mul(public_key(), ciphertext(), plaintext()) -> ciphertext().
mul(PublicKey, A, B) when B >= 0 ->
    mul_nif(PublicKey, A, binary:encode_unsigned(B)).

%%% ===========================================================================
%%% Internal functions
%%% ===========================================================================

encrypt_nif(_PublicKey, _Binary) ->
    not_loaded(?LINE).

decrypt_nif(_PrivateKey, _Binary) ->
    not_loaded(?LINE).

mul_nif(_PublicKey, _A, _B) ->
    not_loaded(?LINE).

init() ->
    PrivDir =
        case code:priv_dir(paillier) of
            {error, _} ->
                EbinDir = filename:dirname(code:which(?MODULE)),
                AppPath = filename:dirname(EbinDir),
                filename:join(AppPath, "priv");
            Path ->
                Path
        end,
    erlang:load_nif(filename:join(PrivDir, paillier), 0).

not_loaded(Line) ->
    erlang:nif_error({not_loaded, [{module, ?MODULE}, {line, Line}]}).

-ifdef(TEST).

encryption_decryption_test() ->
    {PublicKey, PrivateKey} = keypair(2048),

    Ciphertext = encrypt(PublicKey, 10),
    Plaintext = decrypt(PrivateKey, Ciphertext),
    ?assertEqual(10, Plaintext).

randomness_test() ->
    {PublicKey, PrivateKey} = keypair(2048),

    CiphertextOne = encrypt(PublicKey, 5),
    CiphertextTwo = encrypt(PublicKey, 5),
    ?assertNotEqual(CiphertextOne, CiphertextTwo),

    PlaintextOne = decrypt(PrivateKey, CiphertextOne),
    PlaintextTwo = decrypt(PrivateKey, CiphertextTwo),
    ?assertEqual(5, PlaintextOne),
    ?assertEqual(5, PlaintextTwo).

addition_test() ->
    {PublicKey, PrivateKey} = keypair(2048),

    Ten = encrypt(PublicKey, 10),
    Two = encrypt(PublicKey, 2),
    ResultCiphertext = add(PublicKey, Ten, Two),
    Result = decrypt(PrivateKey, ResultCiphertext),
    ?assertEqual(12, Result).

multiplication_test() ->
    {PublicKey, PrivateKey} = keypair(2048),

    Two = encrypt(PublicKey, 2),
    ResultCiphertext = mul(PublicKey, Two, 21),
    Result = decrypt(PrivateKey, ResultCiphertext),
    ?assertEqual(42, Result).

-endif.
