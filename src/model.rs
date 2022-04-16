use bytes::Bytes;
pub use rasn_ldap::{ChangeOperation, ResultCode, SearchRequestDerefAliases, SearchRequestScope};

use crate::SearchRequestBuilder;

#[derive(Clone, Debug, PartialEq)]
pub struct SearchRequest(pub(crate) rasn_ldap::SearchRequest);

impl SearchRequest {
    pub fn builder() -> SearchRequestBuilder {
        SearchRequestBuilder::new()
    }

    pub fn root_dse() -> Self {
        Self::builder().filter("(objectClass=*)").build().unwrap()
    }
}

impl From<SearchRequest> for rasn_ldap::SearchRequest {
    fn from(req: SearchRequest) -> Self {
        req.0
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Attribute {
    pub name: String,
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
