use std::time::Duration;

use crate::{
    error::Error,
    filter::filter_to_ldap,
    model::{SearchRequest, SearchRequestDerefAliases, SearchRequestScope},
};

pub struct SearchRequestBuilder {
    base_dn: String,
    scope: SearchRequestScope,
    deref_aliases: SearchRequestDerefAliases,
    size_limit: u32,
    time_limit: Duration,
    types_only: bool,
    filter: String,
    attributes: Vec<String>,
}

impl Default for SearchRequestBuilder {
    fn default() -> Self {
        Self {
            base_dn: Default::default(),
            scope: SearchRequestScope::BaseObject,
            deref_aliases: SearchRequestDerefAliases::NeverDerefAliases,
            size_limit: 0,
            time_limit: Duration::default(),
            types_only: false,
            filter: Default::default(),
            attributes: Vec::new(),
        }
    }
}

impl SearchRequestBuilder {
    pub fn new() -> Self {
        SearchRequestBuilder::default()
    }

    pub fn base_dn<S: AsRef<str>>(mut self, base_dn: S) -> Self {
        self.base_dn = base_dn.as_ref().to_owned();
        self
    }

    pub fn scope(mut self, scope: SearchRequestScope) -> Self {
        self.scope = scope;
        self
    }

    pub fn deref_aliases(mut self, deref_aliases: SearchRequestDerefAliases) -> Self {
        self.deref_aliases = deref_aliases;
        self
    }

    pub fn size_limit(mut self, size_limit: u32) -> Self {
        self.size_limit = size_limit;
        self
    }

    pub fn time_limit(mut self, time_limit: Duration) -> Self {
        self.time_limit = time_limit;
        self
    }

    pub fn types_only(mut self, types_only: bool) -> Self {
        self.types_only = types_only;
        self
    }

    pub fn filter<S: AsRef<str>>(mut self, filter: S) -> Self {
        self.filter = filter.as_ref().to_owned();
        self
    }

    pub fn attributes<I, T>(mut self, attributes: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: AsRef<str>,
    {
        self.attributes = attributes.into_iter().map(|a| a.as_ref().to_owned()).collect();
        self
    }

    pub fn build(self) -> Result<SearchRequest, Error> {
        Ok(SearchRequest(rasn_ldap::SearchRequest::new(
            self.base_dn.into(),
            self.scope,
            self.deref_aliases,
            self.size_limit,
            self.time_limit.as_secs() as u32,
            self.types_only,
            filter_to_ldap(self.filter)?,
            self.attributes.into_iter().map(Into::into).collect(),
        )))
    }
}
