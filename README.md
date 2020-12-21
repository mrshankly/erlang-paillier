# erlang-paillier

![CI](https://github.com/mrshankly/erlang-paillier/workflows/CI/badge.svg)

This library provides NIF bindings for the [libpaillier] cryptographic library
for Erlang. The [libpaillier] library was develop by John Bethencourt.

This library was built for a research project and its code has not been
carefully analyzed for potential security flaws, and is not intended for use in
production-level code.

## Building

[GMP] is used for arbitrary precision arithmetic, you will need to have that
installed before building. 

To build the library run `rebar3 compile`.

[libpaillier]: http://hms.isi.jhu.edu/acsc/libpaillier/
[GMP]: https://gmplib.org/

## Documentation

The API is straightforward, you can check the [`paillier.erl`](src/paillier.erl) file or generate the documentation with `rebar3 edoc`.
