[![Status](https://travis-ci.org/ElementsProject/rust-elements.png?branch=master)](https://travis-ci.org/ElementsProject/rust-elements)
[![Safety Dance](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)

# Rust Elements Library

Library with support for de/serialization, parsing and executing on data
structures and network messages related to Elements.

[Documentation](https://docs.rs/bitcoin/)

Supports (or should support)

* De/serialization of Elements protocol network messages
* De/serialization of blocks and transactions
* Script de/serialization
* Private keys and address creation, de/serialization and validation (including full BIP32 support)
* PSBT creation, manipulation, merging and finalization
* Pay-to-contract support as in Appendix A of the [Blockstream sidechains whitepaper](https://www.blockstream.com/sidechains.pdf)

For JSONRPC interaction with Elements Core, it is recommended to use
[rust-liquid-rpc](https://github.com/stevenroose/rust-liquid-rpc).

# Known limitations

## Consensus

This library **must not** be used for consensus code (i.e. fully validating
blockchain data). It technically supports doing this, but doing so is very
ill-advised because there are many deviations, known and unknown, between
this library and the Elements Core reference implementation. In a consensus
based blockchain system such as Elements it is critical that all parties are
using the same rules to validate data, and this library is simply unable
to implement the same rules as Core.

Given the complexity of both C++ and Rust, it is unlikely that this will
ever be fixed, and there are no plans to do so. Of course, patches to
fix specific consensus incompatibilities are welcome.

## Documentation

Currently can be found on [docs.rs/elements](https://docs.rs/elements/).
Patches to add usage examples and to expand on existing docs would be extremely
appreciated.

# Contributing
Contributions are generally welcome. If you intend to make larger changes please
discuss them in an issue before PRing them to avoid duplicate work and
architectural mismatches. If you have any questions or ideas you want to discuss
please join us in
[#sidechains-dev](http://webchat.freenode.net/?channels=%23sidechains-dev) on
freenode.

## Minimum Supported Rust Version (MSRV)
This library should always compile with any combination of features on **Rust 1.22**.

## Installing Rust
Rust can be installed using your package manager of choice or
[rustup.rs](https://rustup.rs). The former way is considered more secure since
it typically doesn't involve trust in the CA system. But you should be aware
that the version of Rust shipped by your distribution might be out of date.
Generally this isn't a problem for `rust-elements` since we support much older
versions (>=1.22) than the current stable one.

## Building
The library can be built and tested using [`cargo`](https://github.com/rust-lang/cargo/):

```
git clone git@github.com:ElementsProject/rust-elements.git
cd rust-elements
cargo build
```

You can run tests with:

```
cargo test
```

Please refer to the [`cargo` documentation](https://doc.rust-lang.org/stable/cargo/) for more detailed instructions. 

## Pull Requests
Every PR needs at least two reviews to get merged. During the review phase
maintainers and contributors are likely to leave comments and request changes.
Please try to address them, otherwise your PR might get closed without merging
after a longer time of inactivity. If your PR isn't ready for review yet please
mark it by prefixing the title with `WIP: `.


# Release Notes

See CHANGELOG.md


# Licensing

The code in this project is licensed under the Creative Commons CC0 1.0
Universal license.
