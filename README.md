# LDAP client library for Rust

[![github actions](https://github.com/ancwrd1/ldap-rs/workflows/CI/badge.svg)](https://github.com/ancwrd1/ldap-rs/actions)
[![crates](https://img.shields.io/crates/v/ldap-rs.svg)](https://crates.io/crates/ldap-rs)
[![license](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![license](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![docs.rs](https://docs.rs/ldap-rs/badge.svg)](https://docs.rs/ldap-rs)

## Overview

LDAP client library for Rust with async/await support, based on [tokio](https://tokio.rs).
TLS connectivity is supported via [native-tls](https://crates.io/crates/native-tls) or [rustls](https://crates.io/crates/rustls).
It is controlled by the feature flags `tls-native-tls` and `tls-rustls`, respectively.

A minimal Kerberos support is provided via `gssapi` feature flag with the following limitations:
 
* SASL protection is not supported for plain connections, use TLS connection.
* Channel binding is not supported.

## Features

- [x] Simple bind with username and password
- [x] SASL EXTERNAL bind
- [x] Kerberos GSSAPI bind (SASL protection is not implemented, use TLS instead)
- [x] Plain, TLS and STARTTLS connections
- [x] Simple search and paged search via asynchronous streams
- [x] Extended `ProtocolOp` client operations (add, modify, delete)

## Usage 

Check the [examples](https://github.com/ancwrd1/ldap-rs/tree/master/examples) directory for usage examples.

## License

Licensed under MIT or Apache license ([LICENSE-MIT](https://opensource.org/licenses/MIT)
or [LICENSE-APACHE](https://opensource.org/licenses/Apache-2.0))
