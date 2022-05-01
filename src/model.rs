//! Data structures

use bytes::Bytes;
pub use rasn_ldap::{ResultCode, SearchRequestDerefAliases, SearchRequestScope};

/// LDAP attribute definition
#[derive(Clone, Debug, PartialEq)]
pub struct Attribute {
    /// Attribute name
    pub name: String,
    /// Attribute values
    pub values: Vec<Bytes>,
}

pub type Attributes = Vec<Attribute>;

impl From<rasn_ldap::PartialAttribute> for Attribute {
    fn from(raw: rasn_ldap::PartialAttribute) -> Self {
        Attribute {
            name: String::from_utf8_lossy(&raw.r#type).into_owned(),
            values: raw.vals.into_iter().collect(),
        }
    }
}
