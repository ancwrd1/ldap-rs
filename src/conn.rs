use std::{
    collections::HashMap,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use futures::channel::mpsc;
use futures::{SinkExt, Stream, StreamExt};
use log::debug;
use parking_lot::RwLock;

use crate::{
    TlsOptions,
    channel::{LdapChannel, LdapMessageReceiver, LdapMessageSender},
    error::Error,
    oid,
    rasn_ldap::{LdapMessage, ProtocolOp},
};

const CHANNEL_SIZE: usize = 1024;

type RequestMap = Arc<RwLock<HashMap<u32, LdapMessageSender>>>;

#[derive(Clone)]
pub struct LdapConnection {
    requests: RequestMap,
    channel_sender: LdapMessageSender,
}

impl LdapConnection {
    pub async fn connect<A>(address: A, port: u16, tls_options: TlsOptions) -> Result<Self, Error>
    where
        A: AsRef<str>,
    {
        let (channel_sender, mut channel_receiver) =
            LdapChannel::for_client(address, port).connect(tls_options).await?;
        let connection = Self {
            requests: RequestMap::default(),
            channel_sender,
        };

        let requests = connection.requests.clone();

        tokio::spawn(async move {
            while let Some(msg) = channel_receiver.next().await {
                match msg.protocol_op {
                    // Check for notice of disconnection.
                    // FIXME: This fails on MS AD because it returns a faulty response.
                    // However the channel will be disconnected anyway.
                    ProtocolOp::ExtendedResp(resp)
                        if resp.response_name.as_deref() == Some(oid::NOTICE_OF_DISCONNECTION_OID) =>
                    {
                        debug!("Notice of disconnection received, exiting");
                        break;
                    }
                    _ => {
                        let sender = requests.read().get(&msg.message_id).cloned();
                        if let Some(mut sender) = sender {
                            let _ = sender.send(msg).await;
                        }
                    }
                }
            }
            debug!("Connection terminated");
            requests.write().clear();
        });

        Ok(connection)
    }

    pub async fn send_recv_stream(&mut self, msg: LdapMessage) -> Result<MessageStream, Error> {
        let id = msg.message_id;
        self.channel_sender.send(msg).await?;

        let (tx, rx) = mpsc::channel(CHANNEL_SIZE);
        self.requests.write().insert(id, tx);

        Ok(MessageStream {
            id,
            requests: self.requests.clone(),
            receiver: rx,
        })
    }

    pub async fn send(&mut self, msg: LdapMessage) -> Result<(), Error> {
        Ok(self.channel_sender.send(msg).await?)
    }

    pub async fn send_recv(&mut self, msg: LdapMessage) -> Result<LdapMessage, Error> {
        Ok(self
            .send_recv_stream(msg)
            .await?
            .next()
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::ConnectionReset, "Connection closed"))?)
    }
}

pub struct MessageStream {
    id: u32,
    requests: RequestMap,
    receiver: LdapMessageReceiver,
}

impl Stream for MessageStream {
    type Item = LdapMessage;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.receiver).poll_next(cx)
    }
}

impl Drop for MessageStream {
    fn drop(&mut self) {
        self.requests.write().remove(&self.id);
    }
}
