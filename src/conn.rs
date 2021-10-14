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
    channel::{LdapChannel, LdapMessageReceiver, LdapMessageSender},
    error::Error,
    rasn_ldap::{LdapMessage, ProtocolOp},
    TlsOptions,
};

const NOTICE_OF_DISCONNECTION_OID: &[u8] = b"1.3.6.1.4.1.1466.20036";

type ClientMap = Arc<RwLock<HashMap<u32, LdapMessageSender>>>;

#[derive(Clone)]
pub(crate) struct LdapConnection {
    clients: ClientMap,
    channel_sender: LdapMessageSender,
}

impl LdapConnection {
    pub(crate) async fn connect<A>(address: A, port: u16, tls_options: TlsOptions) -> Result<Self, Error>
    where
        A: AsRef<str>,
    {
        let (channel_sender, mut channel_receiver) =
            LdapChannel::for_client(address, port).connect(tls_options).await?;
        let connection = Self {
            clients: ClientMap::default(),
            channel_sender,
        };

        let clients = connection.clients.clone();

        tokio::spawn(async move {
            while let Some(msg) = channel_receiver.next().await {
                match msg.protocol_op {
                    ProtocolOp::ExtendedResp(resp)
                        if msg.message_id == 0
                            && resp.response_name.as_deref() == Some(NOTICE_OF_DISCONNECTION_OID) =>
                    {
                        debug!("Notice of disconnection received, exiting");
                        break;
                    }
                    _ => {
                        let sender = clients.read().get(&msg.message_id).map(|c| c.clone());
                        if let Some(mut sender) = sender {
                            let _ = sender.send(msg).await;
                        }
                    }
                }
            }
        });

        Ok(connection)
    }

    pub(crate) async fn send_recv_stream(&mut self, msg: LdapMessage) -> Result<MessageStream, Error> {
        let id = msg.message_id;
        self.channel_sender.send(msg).await?;

        let (tx, rx) = mpsc::channel(1);
        self.clients.write().insert(id, tx);

        Ok(MessageStream {
            id,
            clients: self.clients.clone(),
            receiver: rx,
        })
    }

    pub(crate) async fn send(&mut self, msg: LdapMessage) -> Result<(), Error> {
        Ok(self.channel_sender.send(msg).await?)
    }

    pub(crate) async fn send_recv(&mut self, msg: LdapMessage) -> Result<LdapMessage, Error> {
        Ok(self
            .send_recv_stream(msg)
            .await?
            .next()
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::ConnectionReset, "Connection closed"))?)
    }
}

pub(crate) struct MessageStream {
    id: u32,
    clients: ClientMap,
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
        self.clients.write().remove(&self.id);
    }
}
