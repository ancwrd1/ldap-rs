//! Data structures

use bytes::Bytes;
pub use rasn_ldap::{ResultCode, SearchRequestDerefAliases, SearchRequestScope};

/// LDAP attribute definition
#[derive(Clone, Debug, Eq, PartialEq)]
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

impl From<Attribute> for rasn_ldap::PartialAttribute {
    fn from(attr: Attribute) -> Self {
        rasn_ldap::PartialAttribute::new(attr.name.into_bytes().into(), attr.values.into_iter().collect())
    }
}

impl From<Attribute> for rasn_ldap::Attribute {
    fn from(attr: Attribute) -> Self {
        rasn_ldap::Attribute::new(attr.name.into_bytes().into(), attr.values.into_iter().collect())
    }
}

/// An entry found during the search
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SearchEntry {
    /// The name of the object found (Distinguished Name)
    pub dn: String,
    /// The attributes associated with the object
    pub attributes: Attributes,
}

impl From<rasn_ldap::SearchResultEntry> for SearchEntry {
    fn from(raw: rasn_ldap::SearchResultEntry) -> Self {
        SearchEntry {
            dn: String::from_utf8_lossy(&raw.object_name).into_owned(),
            attributes: raw.attributes.into_iter().map(Into::into).collect(),
        }
    }
}
