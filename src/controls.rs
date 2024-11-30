//! LDAP controls

use std::convert::TryFrom;

use rasn::{ber, types::*, Decode, Decoder, Encode};
use rasn_ldap::Control;

use crate::error::Error;

/// Simple paged result control, OID 1.2.840.113556.1.4.319
#[derive(Debug, Clone, PartialEq, PartialOrd, Eq, Ord, Hash)]
pub struct SimplePagedResultsControl {
    size: Integer,
    cookie: OctetString,
    has_entries: bool,
}

impl SimplePagedResultsControl {
    /// Control OID
    pub const OID: &'static [u8] = crate::oid::SIMPLE_PAGED_RESULTS_CONTROL_OID;

    /// Create paged result control with a given page size
    pub fn new(size: u32) -> Self {
        Self {
            size: size.into(),
            cookie: OctetString::default(),
            has_entries: true,
        }
    }

    /// Replace the page size for a given control
    pub fn with_size(self, size: u32) -> Self {
        Self {
            size: size.into(),
            ..self
        }
    }

    /// Return a cookie
    pub fn cookie(&self) -> &OctetString {
        &self.cookie
    }

    /// Return a current size
    pub fn size(&self) -> &Integer {
        &self.size
    }

    /// Returns true if this control indicates more entries are available
    pub fn has_entries(&self) -> bool {
        self.has_entries
    }
}

#[derive(AsnType, Encode, Decode, Debug, Clone, PartialEq, PartialOrd, Eq, Ord, Hash)]
struct RealSearchControlValue {
    size: Integer,
    cookie: OctetString,
}

impl TryFrom<SimplePagedResultsControl> for Control {
    type Error = Error;

    fn try_from(control: SimplePagedResultsControl) -> Result<Self, Self::Error> {
        let value = RealSearchControlValue {
            size: control.size,
            cookie: control.cookie,
        };
        Ok(Control::new(
            SimplePagedResultsControl::OID.into(),
            false,
            Some(ber::encode(&value)?.into()),
        ))
    }
}

impl TryFrom<Control> for SimplePagedResultsControl {
    type Error = Error;

    fn try_from(value: Control) -> Result<Self, Self::Error> {
        let value = ber::decode::<RealSearchControlValue>(value.control_value.as_deref().unwrap_or(b""))?;
        let has_entries = !value.cookie.is_empty();

        Ok(SimplePagedResultsControl {
            size: value.size,
            cookie: value.cookie,
            has_entries,
        })
    }
}
