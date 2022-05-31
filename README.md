# Yet another LDAP client for Rust

## Overview

This project aims to provide a minimal working LDAP client written in Rust focused on ergonomics, correctness
and clean code.
It uses tokio asynchronous runtime for network I/O and an excellent [rasn](https://github.com/XAMPPRocky/rasn)
crate for all ASN.1 goodness.

For TLS connections currently the `native-tls` crate is used.

## Roadmap

- [x] Simple bind with username and password
- [x] SASL EXTERNAL bind
- [x] Plain, TLS and STARTTLS connections
- [x] Simple search and paged search via asynchronous streams
- [x] [Documentation](https://ancwrd1.github.io/ldap-rs/doc/ldap_rs/)
- [ ] `rustls` support via optional feature flag
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
