//! LDAP connection options

#[cfg(feature = "tls-native-tls")]
pub use native_tls;

#[cfg(feature = "tls-rustls")]
pub use {rustls, rustls_pki_types};

#[cfg(tls)]
pub use tls::TlsOptions;

#[cfg(tls)]
pub(crate) use tls::{TlsBackend, TlsKind};

#[cfg(tls)]
mod tls {
    #[cfg(feature = "tls-native-tls")]
    use native_tls::TlsConnector;

    #[cfg(feature = "tls-rustls")]
    pub use rustls::ClientConfig;

    #[derive(Clone, Copy, Debug, Default, PartialEq)]
    pub enum TlsKind {
        #[default]
        Plain,
        Tls,
        StartTls,
    }

    #[derive(Debug)]
    pub enum TlsBackend {
        #[cfg(feature = "tls-native-tls")]
        Native(TlsConnector),
        #[cfg(feature = "tls-rustls")]
        Rustls(ClientConfig),
    }

    impl Default for TlsBackend {
        #[cfg(feature = "tls-native-tls")]
        fn default() -> Self {
            Self::Native(TlsConnector::new().unwrap())
        }

        #[cfg(all(feature = "tls-rustls", not(feature = "tls-native-tls")))]
        fn default() -> Self {
            pub static CA_CERTS: once_cell::sync::Lazy<rustls::RootCertStore> = once_cell::sync::Lazy::new(|| {
                let certs = rustls_native_certs::load_native_certs()
                    .certs
                    .into_iter()
                    .map(|c| c)
                    .collect::<Vec<_>>();
                let mut store = rustls::RootCertStore::empty();
                store.add_parsable_certificates(certs);
                store
            });

            Self::Rustls(
                ClientConfig::builder()
                    .with_root_certificates(CA_CERTS.clone())
                    .with_no_client_auth(),
            )
        }
    }

    /// TLS options
    #[derive(Default, Debug)]
    pub struct TlsOptions {
        pub(crate) backend: Option<TlsBackend>,
        pub(crate) kind: TlsKind,
        pub(crate) domain_name: Option<String>,
    }

    impl TlsOptions {
        fn new(kind: TlsKind) -> Self {
            Self {
                backend: None,
                kind,
                domain_name: None,
            }
        }

        /// Connect using TLS transport
        pub fn tls() -> Self {
            Self::new(TlsKind::Tls)
        }

        /// Connect using STARTTLS negotiation
        pub fn start_tls() -> Self {
            Self::new(TlsKind::StartTls)
        }

        #[cfg(feature = "tls-rustls")]
        /// Set client identity for mutual TLS authentication
        pub fn client_config(mut self, client_config: ClientConfig) -> Self {
            self.backend = Some(TlsBackend::Rustls(client_config));
            self
        }

        #[cfg(feature = "tls-native-tls")]
        /// Set client identity for mutual TLS authentication
        pub fn tls_connector(mut self, tls_connector: TlsConnector) -> Self {
            self.backend = Some(TlsBackend::Native(tls_connector));
            self
        }

        /// Specify custom domain name to use for SNI match. The default is the connection host name
        pub fn domain_name<S: AsRef<str>>(mut self, domain_name: S) -> Self {
            self.domain_name = Some(domain_name.as_ref().to_owned());
            self
        }
    }
}
