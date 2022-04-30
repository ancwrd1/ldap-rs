//! LDAP connection options

pub use native_tls::{Certificate, Identity};

#[derive(Clone, PartialEq)]
pub(crate) enum TlsKind {
    Plain,
    Tls,
    StartTls,
}

/// TLS options
#[derive(Clone)]
pub struct TlsOptions {
    pub(crate) kind: TlsKind,
    pub(crate) ca_certs: Vec<Certificate>,
    pub(crate) verify_hostname: bool,
    pub(crate) verify_certs: bool,
    pub(crate) identity: Option<Identity>,
    pub(crate) domain_name: Option<String>,
}

impl TlsOptions {
    fn new(kind: TlsKind) -> Self {
        Self {
            kind,
            ca_certs: Vec::new(),
            verify_hostname: true,
            verify_certs: true,
            identity: None,
            domain_name: None,
        }
    }

    /// Use plain connection without transport security
    pub fn plain() -> Self {
        Self::new(TlsKind::Plain)
    }

    /// Connect using TLS transport
    pub fn tls() -> Self {
        Self::new(TlsKind::Tls)
    }

    /// Connect using STARTTLS negotiation
    pub fn start_tls() -> Self {
        Self::new(TlsKind::StartTls)
    }

    /// Add CA root certificate to use during TLS handshake
    pub fn ca_cert(mut self, cert: Certificate) -> Self {
        self.ca_certs.push(cert);
        self
    }

    /// Set client identity for mutual TLS authentication
    pub fn identity(mut self, identity: Identity) -> Self {
        self.identity = Some(identity);
        self
    }

    /// Specify custom domain name to use for SNI match. The default is the connection host name
    pub fn domain_name<S: AsRef<str>>(mut self, domain_name: S) -> Self {
        self.domain_name = Some(domain_name.as_ref().to_owned());
        self
    }

    /// Enable or disable host name validation in the server certificate.
    /// By default host name validation is enabled.
    pub fn verify_hostname(mut self, flag: bool) -> Self {
        self.verify_hostname = flag;
        self
    }

    /// Enable or disable server certificate validation.
    /// By default server certificate validation is enabled.
    pub fn verify_certs(mut self, flag: bool) -> Self {
        self.verify_certs = flag;
        self
    }
}
