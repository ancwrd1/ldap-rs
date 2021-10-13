use std::convert::TryFrom;

use rasn::{ber, types::*, Decode, Encode};
use rasn_ldap::Control;

use crate::error::Error;

pub const PAGED_CONTROL_OID: &[u8] = b"1.2.840.113556.1.4.319";

#[derive(AsnType, Encode, Decode, Debug, Clone, PartialEq, PartialOrd, Eq, Ord, Hash)]
pub struct SimplePagedResultsControl {
    size: Integer,
    cookie: OctetString,
}

impl SimplePagedResultsControl {
    pub fn new(size: u32) -> Self {
        Self {
            size: size.into(),
            cookie: OctetString::default(),
        }
    }

    pub fn with_size(self, size: u32) -> Self {
        Self {
            size: size.into(),
            ..self
        }
    }

    pub fn cookie(&self) -> &OctetString {
        &self.cookie
    }

    pub fn size(&self) -> &Integer {
        &self.size
    }
}

#[derive(AsnType, Encode, Decode, Debug, Clone, PartialEq, PartialOrd, Eq, Ord, Hash)]
pub struct RealSearchControlValue {
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
            PAGED_CONTROL_OID.to_vec().into(),
            false,
            Some(ber::encode(&value)?.into()),
        ))
    }
}

impl TryFrom<Control> for SimplePagedResultsControl {
    type Error = Error;

    fn try_from(value: Control) -> Result<Self, Self::Error> {
        let value = ber::decode::<RealSearchControlValue>(value.control_value.as_deref().unwrap_or(b""))?;

        Ok(SimplePagedResultsControl {
            size: value.size,
            cookie: value.cookie,
        })
    }
}
