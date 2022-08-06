# Yet another LDAP client for Rust

## Overview

This project aims to provide a minimal working LDAP client written in Rust focused on ergonomics, correctness
and clean code.
It uses tokio asynchronous runtime for network I/O and an excellent [rasn](https://github.com/XAMPPRocky/rasn)
crate for all ASN.1 goodness.

TLS connectivity is controlled by two mutually exclusive feature flags: `tls-native-tls` or `tls-rustls`.
The default is to use `tls-native-tls` which uses the `native-tls` crate.

## Roadmap

- [x] Simple bind with username and password
- [x] SASL EXTERNAL bind
- [x] Plain, TLS and STARTTLS connections
- [x] Simple search and paged search via asynchronous streams
- [x] [Documentation](https://ancwrd1.github.io/ldap-rs/doc/ldap_rs/)
- [x] `rustls` support via optional feature flag
- [ ] More of the `ProtocolOp` client operations

## Non-goals

* SASL layer (Kerberos, MD5, etc)
* Server-side implementation

## Usage 

Please see the `examples` directory.

## Alternatives

[ldap3](https://github.com/inejge/ldap3) is actively maintained and has currently more features (e.g. Kerberos support). 

## License

Licensed under MIT or Apache license ([LICENSE-MIT](https://opensource.org/licenses/MIT)
or [LICENSE-APACHE](https://opensource.org/licenses/Apache-2.0))
