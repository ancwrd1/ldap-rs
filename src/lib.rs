//!
//! LDAP client library for Rust with async/await support, based on [tokio](https://tokio.rs).
//! TLS connectivity is supported via [native-tls](https://crates.io/crates/native-tls) or [rustls](https://crates.io/crates/rustls).
//! It is controlled by the feature flags `tls-native-tls` and `tls-rustls`, respectively.
//!
//! A minimal Kerberos support is provided via `gssapi` feature flag with the following limitations:
//!
//! * SASL protection is not supported for plain connections, use TLS connection.
//! * Channel binding is not supported.
//!
//! Usage example:
//! ```no_run
//! use futures::TryStreamExt;
//! use ldap_rs::{LdapClient, SearchRequest, SearchRequestDerefAliases, SearchRequestScope, TlsOptions};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     pretty_env_logger::init_timed();
//!
//!     let options = TlsOptions::tls();
//!
//!     let mut client = LdapClient::builder("ldap-host.local")
//!         .tls_options(options)
//!         .connect()
//!         .await?;
//!     client
//!         .simple_bind("cn=read-only-admin,dc=example,dc=com", "password")
//!         .await?;
//!
//!     let req = SearchRequest::builder()
//!         .base_dn("dc=example,dc=com")
//!         .scope(SearchRequestScope::WholeSubtree)
//!         .deref_aliases(SearchRequestDerefAliases::NeverDerefAliases)
//!         .filter("(&(objectClass=person)(uid=ne*t*n))")
//!         .build()?;
//!
//!     let result = client.search(req).await?;
//!     let items = result.try_collect::<Vec<_>>().await?;
//!     println!("Items: {items:#?}");
//!
//!     Ok(())
//! }

#![allow(clippy::result_large_err)]

pub use bytes;
pub use rasn_ldap;

pub use client::*;
pub use model::*;
pub use options::*;
pub use request::*;

mod codec;
mod conn;
mod filter;

pub mod channel;
pub mod client;
pub mod controls;
pub mod error;
pub mod model;
pub mod oid;
pub mod options;
pub mod request;
