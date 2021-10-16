use native_tls::Certificate;

#[derive(PartialEq)]
pub(crate) enum TlsKind {
    Plain,
    Tls,
    StartTls,
}

pub struct TlsOptions {
    pub(crate) kind: TlsKind,
    pub(crate) root_certs: Vec<Certificate>,
    pub(crate) verify_hostname: bool,
    pub(crate) verify_certs: bool,
}

impl TlsOptions {
    fn new(kind: TlsKind) -> Self {
        Self {
            kind,
            root_certs: Vec::new(),
            verify_hostname: true,
            verify_certs: true,
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
    pub fn starttls() -> Self {
        Self::new(TlsKind::StartTls)
    }

    /// Add CA root certificate to use during TLS handshake
    pub fn root_cert(mut self, cert: Certificate) -> Self {
        self.root_certs.push(cert);
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
