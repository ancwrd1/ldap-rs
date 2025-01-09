# Yet another LDAP client for Rust

[![github actions](https://github.com/ancwrd1/ldap-rs/workflows/CI/badge.svg)](https://github.com/ancwrd1/ldap-rs/actions)
[![crates](https://img.shields.io/crates/v/ldap-rs.svg)](https://crates.io/crates/ldap-rs)
[![license](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![license](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![docs.rs](https://docs.rs/ldap-rs/badge.svg)](https://docs.rs/ldap-rs)

## Overview

This project aims to provide a minimal working LDAP client written in Rust focused on ergonomics, correctness
and clean code.
It uses tokio asynchronous runtime for network I/O and an excellent [rasn](https://github.com/librasn/rasn)
crate for all ASN.1 goodness.

TLS connectivity is controlled by two feature flags: `tls-native-tls` and `tls-rustls`.
The default is `tls-native-tls` which uses the `native-tls` crate.

A minimal Kerberos support is provided via `gssapi` feature flag with the following limitations:

* SASL protection is not supported for plain connections, TLS should be used for all communication
* Channel binding is not supported


## Features

- [x] Simple bind with username and password
- [x] SASL EXTERNAL bind
- [x] Kerberos GSSAPI bind (SASL protection is not implemented, use TLS instead)
- [x] Plain, TLS and STARTTLS connections
- [x] Simple search and paged search via asynchronous streams
- [x] `rustls` or `'native-tls` selection via feature flag
- [x] Extended `ProtocolOp` client operations (add, modify, delete)

## Usage 

Please see the `examples` directory.

## License

Licensed under MIT or Apache license ([LICENSE-MIT](https://opensource.org/licenses/MIT)
or [LICENSE-APACHE](https://opensource.org/licenses/Apache-2.0))
