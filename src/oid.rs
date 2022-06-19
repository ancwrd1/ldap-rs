//! OID definitions

/// StartTLS extended operation
pub const STARTTLS_OID: &[u8] = b"1.3.6.1.4.1.1466.20037";

/// WHOAMI extended operation
pub const WHOAMI_OID: &str = "1.3.6.1.4.1.4203.1.11.3";

/// Notice of disconnection response sent by the server
pub const NOTICE_OF_DISCONNECTION_OID: &[u8] = b"1.3.6.1.4.1.1466.20036";

/// SimplePagedResultsControl OID
pub const SIMPLE_PAGED_RESULTS_CONTROL_OID: &[u8] = b"1.2.840.113556.1.4.319";
