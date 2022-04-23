//! Low-level LDAP channel operations

use std::{io, net::ToSocketAddrs, time::Duration};

use futures::{
    channel::mpsc::{self, Receiver, Sender},
    future,
    sink::SinkExt,
    StreamExt, TryStreamExt,
};
use log::{debug, error};
use rasn_ldap::{ExtendedRequest, LdapMessage, ProtocolOp, ResultCode};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};
use tokio_native_tls::TlsStream;

use crate::{
    codec::LdapCodec,
    error::Error,
    options::{TlsKind, TlsOptions},
};

const CHANNEL_SIZE: usize = 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const STARTTLS_OID: &[u8] = b"1.3.6.1.4.1.1466.20037";

pub type LdapMessageSender = Sender<LdapMessage>;
pub type LdapMessageReceiver = Receiver<LdapMessage>;

fn io_error<E>(e: E) -> io::Error
where
    E: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    io::Error::new(io::ErrorKind::InvalidData, e)
}

/// LDAP channel errors
#[derive(Debug, thiserror::Error)]
pub enum ChannelError {
    #[error(transparent)]
    IoError(#[from] io::Error),
    #[error(transparent)]
    ConnectTimeout(#[from] tokio::time::error::Elapsed),
    #[error(transparent)]
    Tls(#[from] native_tls::Error),
    #[error("STARTTLS failed")]
    StartTlsFailed,
}

pub type ChannelResult<T> = Result<T, ChannelError>;

/// LDAP TCP channel connector
pub struct LdapChannel {
    address: String,
    port: u16,
}

impl LdapChannel {
    /// Create a client-side channel with a given server address and port
    pub fn for_client<S>(address: S, port: u16) -> Self
    where
        S: AsRef<str>,
    {
        LdapChannel {
            address: address.as_ref().to_owned(),
            port,
        }
    }

    /// Connect to a server
    /// Returns a pair of (sender, receiver) endpoints
    pub async fn connect(self, tls_options: TlsOptions) -> ChannelResult<(LdapMessageSender, LdapMessageReceiver)> {
        let mut addrs = (self.address.as_ref(), self.port).to_socket_addrs()?;
        let address = addrs.next().ok_or_else(|| io_error("Address resolution error"))?;

        // TCP connect with a timeout
        let stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(&address)).await??;

        debug!("Connection established to {}", address);

        match tls_options.kind {
            TlsKind::Plain => self.make_channel(stream),
            TlsKind::Tls => self.make_channel(self.tls_connect(tls_options, stream).await?),
            TlsKind::StartTls => self.make_channel(self.starttls_connect(tls_options, stream).await?),
        }
    }

    async fn starttls_connect<S>(&self, tls_options: TlsOptions, mut stream: S) -> ChannelResult<TlsStream<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        debug!("Starting STARTTLS negotiation");
        let mut framed = tokio_util::codec::Framed::new(&mut stream, LdapCodec);
        let req = ExtendedRequest {
            request_name: STARTTLS_OID.to_vec().into(),
            request_value: None,
        };
        framed
            .send(LdapMessage::new(1, ProtocolOp::ExtendedReq(req)))
            .await
            .map_err(|_| ChannelError::StartTlsFailed)?;
        if let Some(Ok(item)) = framed.next().await {
            match item.protocol_op {
                ProtocolOp::ExtendedResp(resp) if resp.result_code == ResultCode::Success && item.message_id == 1 => {
                    debug!("STARTTLS succeeded");
                    return self.tls_connect(tls_options, stream).await;
                }
                _ => {}
            }
        }
        debug!("STARTTLS failed");
        Err(ChannelError::StartTlsFailed)
    }

    async fn tls_connect<S>(&self, tls_options: TlsOptions, stream: S) -> ChannelResult<TlsStream<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        debug!("Performing TLS handshake with {}", self.address);
        let mut tls_builder = native_tls::TlsConnector::builder();
        for cert in tls_options.ca_certs {
            tls_builder.add_root_certificate(cert);
        }
        tls_builder.danger_accept_invalid_hostnames(!tls_options.verify_hostname);
        tls_builder.danger_accept_invalid_certs(!tls_options.verify_certs);

        if let Some(identity) = tls_options.identity {
            tls_builder.identity(identity);
        }

        let connector = tls_builder.build()?;

        let tokio_connector = tokio_native_tls::TlsConnector::from(connector);

        let stream = tokio_connector
            .connect(&self.address, stream)
            .await
            .map_err(ChannelError::Tls)?;

        debug!("Handshake completed with {}", self.address);

        Ok(stream)
    }

    fn make_channel<S>(&self, stream: S) -> ChannelResult<(LdapMessageSender, LdapMessageReceiver)>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        // construct framed instance based on LdapCodec
        let framed = tokio_util::codec::Framed::new(stream, LdapCodec);

        // The 'in' channel:
        // Messages received from the socket will be forwarded to tx_in
        // and received by the external client via rx_in endpoint
        let (tx_in, rx_in) = mpsc::channel(CHANNEL_SIZE);

        // The 'out' channel:
        // Messages sent to tx_out by external clients will be picked up on rx_out endpoint
        // and forwarded to socket
        let (tx_out, rx_out) = mpsc::channel(CHANNEL_SIZE);

        let channel = async move {
            // sink is the sending part, stream is the receiving part
            let (mut sink, stream) = framed.split();

            // we receive LdapMessage messages from the clients and convert to stream chunks
            let mut rx = rx_out.map(Ok::<_, Error>);

            // app -> socket
            let to_wire = sink.send_all(&mut rx);

            // convert incoming channel errors into io::Error
            let mut tx = tx_in.sink_map_err(io_error);

            // app <- socket
            let from_wire = stream.map_err(io_error).forward(&mut tx);

            // await for either of futures: terminating one side will drop the other
            let _ = future::select(to_wire, from_wire).await;
        };

        // spawn in the background
        tokio::spawn(channel);

        // we return (tx_out, rx_in) pair so that the consumer can send and receive messages
        Ok((tx_out, rx_in))
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{SocketAddr, ToSocketAddrs},
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
    };

    use rasn_ldap::{ProtocolOp, UnbindRequest};
    use tokio::net::TcpListener;
    use tokio_util::codec::Framed;

    use super::*;

    fn new_msg() -> LdapMessage {
        LdapMessage::new(1, ProtocolOp::UnbindRequest(UnbindRequest))
    }

    async fn start_server(address: &SocketAddr, num_msgs: usize) {
        let tcp = TcpListener::bind(&address).await.unwrap();

        tokio::spawn(async move {
            if let Ok((stream, _)) = tcp.accept().await {
                let framed = Framed::new(stream, LdapCodec);
                let (mut sink, stream) = framed.split();
                sink.send_all(&mut stream.take(num_msgs)).await.unwrap();
            }
        });
    }

    #[tokio::test]
    async fn test_connection_success() {
        let address = ("127.0.0.1", 22561);

        let socket_address = address.to_socket_addrs().unwrap().next().unwrap();

        let counter = Arc::new(AtomicUsize::new(0));
        let flag = counter.clone();

        let res = {
            start_server(&socket_address, 2).await;

            let (mut sender, mut receiver) = LdapChannel::for_client(address.0, address.1)
                .connect(TlsOptions::plain())
                .await
                .unwrap();
            let msg = new_msg();

            sender.send(msg.clone()).await.unwrap();
            sender.send(msg.clone()).await.unwrap();

            while let Some(m) = receiver.next().await {
                assert_eq!(msg, m);
                flag.fetch_add(1, Ordering::SeqCst);
            }
            Ok::<(), ()>(())
        };
        assert!(res.is_ok());
        assert_eq!(counter.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn test_connection_fail() {
        let res = LdapChannel::for_client("127.0.0.1", 32222)
            .connect(TlsOptions::plain())
            .await;

        assert!(res.is_err());
    }
}
