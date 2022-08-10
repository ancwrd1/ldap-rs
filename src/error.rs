//! LDAP errors

use std::{error, fmt, io};

use futures::channel::mpsc::SendError;
use rasn::ber;
use rasn_ldap::{BindResponse, LdapResult, ResultCode};

use crate::{channel::ChannelError, filter::Rule};

/// LDAP operation error
#[derive(Debug)]
pub struct OperationError {
    /// Result code
    pub result_code: ResultCode,
    /// Matched DN
    pub matched_dn: String,
    /// Diagnostic message
    pub diagnostic_message: String,
}

impl From<BindResponse> for OperationError {
    fn from(r: BindResponse) -> Self {
        OperationError {
            result_code: r.result_code,
            matched_dn: String::from_utf8_lossy(&r.matched_dn).into_owned(),
            diagnostic_message: String::from_utf8_lossy(&r.diagnostic_message).into_owned(),
        }
    }
}

impl From<LdapResult> for OperationError {
    fn from(r: LdapResult) -> Self {
        OperationError {
            result_code: r.result_code,
            matched_dn: String::from_utf8_lossy(&r.matched_dn).into_owned(),
            diagnostic_message: String::from_utf8_lossy(&r.diagnostic_message).into_owned(),
        }
    }
}

/// LDAP errors
#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    AsnDecode(ber::de::Error),
    AsnEncode(ber::enc::Error),
    Channel(ChannelError),
    Send(SendError),
    InvalidMessageId,
    OperationFailed(OperationError),
    InvalidFilter(pest::error::Error<Rule>),
    InvalidResponse,
    ConnectionClosed,
    GssApiError(String),
    NoSaslCredentials,
}

impl error::Error for Error {}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<ber::de::Error> for Error {
    fn from(e: ber::de::Error) -> Self {
        Error::AsnDecode(e)
    }
}

impl From<ber::enc::Error> for Error {
    fn from(e: ber::enc::Error) -> Self {
        Error::AsnEncode(e)
    }
}

impl From<ChannelError> for Error {
    fn from(e: ChannelError) -> Self {
        Error::Channel(e)
    }
}

impl From<SendError> for Error {
    fn from(e: SendError) -> Self {
        Error::Send(e)
    }
}

impl From<pest::error::Error<Rule>> for Error {
    fn from(e: pest::error::Error<Rule>) -> Self {
        Error::InvalidFilter(e)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "{}", e),
            Error::AsnDecode(e) => write!(f, "{:?}", e),
            Error::AsnEncode(e) => write!(f, "{:?}", e),
            Error::Channel(e) => write!(f, "{}", e),
            Error::Send(e) => write!(f, "{}", e),
            Error::InvalidMessageId => write!(f, "Invalid message id"),
            Error::OperationFailed(code) => write!(f, "LDAP operation failed: {:?}", code),
            Error::InvalidResponse => write!(f, "Invalid response"),
            Error::InvalidFilter(e) => write!(f, "{}", e),
            Error::ConnectionClosed => write!(f, "Connection closed"),
            Error::GssApiError(e) => write!(f, "{}", e),
            Error::NoSaslCredentials => write!(f, "No SASL credentials in response"),
        }
    }
}
