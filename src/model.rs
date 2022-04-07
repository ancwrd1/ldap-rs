use std::collections::BTreeSet;

pub use rasn_ldap::{ChangeOperation, ResultCode, SearchRequestDerefAliases, SearchRequestScope};

#[derive(Clone, Debug, PartialEq)]
pub struct SearchRequest(pub(crate) rasn_ldap::SearchRequest);

impl From<SearchRequest> for rasn_ldap::SearchRequest {
    fn from(req: SearchRequest) -> Self {
        req.0
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Attribute {
    pub name: String,
    pub values: BTreeSet<Vec<u8>>,
}

pub type Attributes = Vec<Attribute>;

impl From<rasn_ldap::PartialAttribute> for Attribute {
    fn from(raw: rasn_ldap::PartialAttribute) -> Self {
        Attribute {
            name: String::from_utf8_lossy(&raw.r#type).into_owned(),
            values: raw
                .vals
                .into_iter()
                .map(|v| v.to_vec())
                .collect(),
        }
    }
}
