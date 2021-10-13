use bytes::{Buf, BufMut, BytesMut};
use log::{error, trace};
use rasn::{ber, de::Decode};
use rasn_ldap::LdapMessage;
use tokio_util::codec::{Decoder, Encoder};

use crate::error::Error;

pub struct LdapCodec;

impl Decoder for LdapCodec {
    type Item = LdapMessage;
    type Error = Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let mut decoder = ber::de::Decoder::new(&src, ber::de::DecoderOptions::ber());

        match LdapMessage::decode(&mut decoder) {
            Ok(msg) => {
                let len = decoder.decoded_len();
                drop(decoder);
                src.advance(len);
                trace!("Decoded request: {} bytes", len);
                Ok(Some(msg))
            }
            Err(ber::de::Error::Incomplete { needed }) => {
                trace!("Incomplete request, needed: {:?}", needed);
                Ok(None)
            }
            Err(e) => {
                error!("Decoder error: {}", e);
                Err(e.into())
            }
        }
    }
}

impl Encoder<LdapMessage> for LdapCodec {
    type Error = Error;

    fn encode(&mut self, item: LdapMessage, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let encoded = ber::encode(&item)?;
        dst.reserve(encoded.len());
        dst.put_slice(&encoded);
        Ok(())
    }
}
