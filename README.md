# Yet another LDAP client for Rust

## Overview

This project aims to provide a minimal working LDAP client written in Rust.
It uses tokio asynchronous runtime for network I/O and an excellent [rasn](https://github.com/XAMPPRocky/rasn)
crate for all ASN.1 goodness.

## Roadmap

- [x] Simple bind with username and password
- [x] SASL EXTERNAL bind
- [x] Plain, TLS and STARTTLS connections
- [x] Simple search and paged search via asynchronous streams
- [ ] All of the `ProtocolOp` client operations
- [x] Documentation

## Non-goals

* Kerberos or SASL binds: use TLS instead
* Server-side implementation

## Usage 

Please see the `examples` directory.

## License

Licensed under MIT or Apache license ([LICENSE-MIT](https://opensource.org/licenses/MIT)
or [LICENSE-APACHE](https://opensource.org/licenses/Apache-2.0))
