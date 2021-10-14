# Yet another LDAP client for Rust

## Overview

This project aims to provide a minimal working LDAP client written in Rust.
It is currently in the early stages of development.

## Roadmap

- [x] Simple bind with username and password
- [x] Plain, TLS and STARTTLS connections
- [x] Simple search and paged search
- [x] Streaming search
- [ ] All of the `ProtocolOp` LDAP operations
- [ ] Documentation

## Non-goals

* Kerberos bind (use TLS instead)
* SASL bind (use TLS instead)
* Server-side implementation

## Usage 

Please see the `examples` folder for the usage samples.

## License

Licensed under MIT or Apache license ([LICENSE-MIT](https://opensource.org/licenses/MIT) or [LICENSE-APACHE](https://opensource.org/licenses/Apache-2.0))
