# erlang-paillier

![CI](https://github.com/mrshankly/erlang-paillier/workflows/CI/badge.svg)

This library provides bindings for the [libpaillier] cryptographic library for
Erlang. The [libpaillier] library was develop by John Bethencourt.

## Building

[GMP] is used for arbitrary precision arithmetic, you will need to have that
installed before building. 

To build the library run `rebar3 compile`.

[libpaillier]: http://hms.isi.jhu.edu/acsc/libpaillier/
[GMP]: https://gmplib.org/
