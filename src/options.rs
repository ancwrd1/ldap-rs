//! LDAP connection options

#[cfg(feature = "tls-native-tls")]
pub use native_tls::{Certificate, Identity};

#[cfg(feature = "tls-rustls")]
pub use rustls_pki_types::{CertificateDer, PrivateKeyDer};

#[cfg(feature = "tls-rustls")]
type Certificate = CertificateDer<'static>;

#[cfg(feature = "tls-rustls")]
type PrivateKey = PrivateKeyDer<'static>;

#[cfg(feature = "tls-rustls")]
pub(crate) struct Identity {
    pub(crate) private_key: PrivateKey,
    pub(crate) certificates: Vec<Certificate>,
}

#[derive(Clone, PartialEq)]
pub(crate) enum TlsKind {
    Plain,
    #[cfg(tls)]
    Tls,
    #[cfg(tls)]
    StartTls,
}

/// TLS options
pub struct TlsOptions {
    pub(crate) kind: TlsKind,
    #[cfg(tls)]
    pub(crate) ca_certs: Vec<Certificate>,
    #[cfg(feature = "tls-native-tls")]
    pub(crate) verify_hostname: bool,
    #[cfg(tls)]
    pub(crate) verify_certs: bool,
    #[cfg(tls)]
    pub(crate) identity: Option<Identity>,
    #[cfg(tls)]
    pub(crate) domain_name: Option<String>,
}

impl TlsOptions {
    fn new(kind: TlsKind) -> Self {
        Self {
            kind,
            #[cfg(tls)]
            ca_certs: Vec::new(),
            #[cfg(feature = "tls-native-tls")]
            verify_hostname: true,
            #[cfg(tls)]
            verify_certs: true,
            #[cfg(tls)]
            identity: None,
            #[cfg(tls)]
            domain_name: None,
        }
    }

    /// Use plain connection without transport security
    pub fn plain() -> Self {
        Self::new(TlsKind::Plain)
    }

    #[cfg(tls)]
    /// Connect using TLS transport
    pub fn tls() -> Self {
        Self::new(TlsKind::Tls)
    }

    #[cfg(tls)]
    /// Connect using STARTTLS negotiation
    pub fn start_tls() -> Self {
        Self::new(TlsKind::StartTls)
    }

    #[cfg(tls)]
    /// Add CA root certificate to use during TLS handshake
    pub fn ca_cert(mut self, cert: Certificate) -> Self {
        self.ca_certs.push(cert);
        self
    }

    #[cfg(feature = "tls-native-tls")]
    /// Set client identity for mutual TLS authentication
    pub fn identity(mut self, identity: Identity) -> Self {
        self.identity = Some(identity);
        self
    }

    #[cfg(feature = "tls-rustls")]
    /// Set client identity for mutual TLS authentication
    pub fn identity(mut self, private_key: PrivateKey, certificates: Vec<Certificate>) -> Self {
        self.identity = Some(Identity {
            private_key,
            certificates,
        });
        self
    }

    #[cfg(tls)]
    /// Specify custom domain name to use for SNI match. The default is the connection host name
    pub fn domain_name<S: AsRef<str>>(mut self, domain_name: S) -> Self {
        self.domain_name = Some(domain_name.as_ref().to_owned());
        self
    }

    #[cfg(feature = "tls-native-tls")]
    /// Enable or disable host name validation in the server certificate.
    /// By default host name validation is enabled.
    /// This option is only used when certificate verification is enabled.
    pub fn verify_hostname(mut self, flag: bool) -> Self {
        self.verify_hostname = flag;
        self
    }

    #[cfg(tls)]
    /// Enable or disable server certificate validation.
    /// By default server certificate validation is enabled.
    pub fn verify_certs(mut self, flag: bool) -> Self {
        self.verify_certs = flag;
        self
    }
}
