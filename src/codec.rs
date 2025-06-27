use bytes::{Buf, BufMut, BytesMut};
use log::{error, trace};
use rasn::error::DecodeErrorKind;
use rasn::{ber, de::Decode};
use rasn_ldap::LdapMessage;
use tokio_util::codec::{Decoder, Encoder};

use crate::error::Error;

pub struct LdapCodec;

impl Decoder for LdapCodec {
    type Item = LdapMessage;
    type Error = Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if !src.has_remaining() {
            return Ok(None);
        }

        let mut decoder = ber::de::Decoder::new(src, ber::de::DecoderOptions::ber());

        match LdapMessage::decode(&mut decoder) {
            Ok(msg) => {
                let len = decoder.decoded_len();
                src.advance(len);
                trace!("Decoded message of {len} bytes: {msg:?}");
                Ok(Some(msg))
            }
            Err(err) => {
                if let DecodeErrorKind::Incomplete { needed } = *err.kind {
                    trace!("Incomplete request, needed: {needed:?}");
                    Ok(None)
                } else {
                    error!("Decoder error: {err}");
                    Err(err.into())
                }
            }
        }
    }
}

impl Encoder<LdapMessage> for LdapCodec {
    type Error = Error;

    fn encode(&mut self, item: LdapMessage, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let encoded = ber::encode(&item)?;
        trace!("Encoded message of {} bytes: {:?}", encoded.len(), item);
        dst.reserve(encoded.len());
        dst.put_slice(&encoded);
        Ok(())
    }
}
