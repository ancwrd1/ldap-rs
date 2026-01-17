//! Low-level LDAP channel operations

use std::{io, net::ToSocketAddrs, time::Duration};

use futures::{
    StreamExt, TryStreamExt,
    channel::mpsc::{self, Receiver, Sender},
    future,
    sink::SinkExt,
};
use log::debug;
use rasn_ldap::LdapMessage;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};

use crate::{
    TlsBackend,
    codec::LdapCodec,
    error::Error,
    options::{TlsKind, TlsOptions},
};

const CHANNEL_SIZE: usize = 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

pub type LdapMessageSender = Sender<LdapMessage>;
pub type LdapMessageReceiver = Receiver<LdapMessage>;

trait TlsStream: AsyncRead + AsyncWrite + Unpin + Send {}

#[cfg(feature = "tls-native-tls")]
impl<T: AsyncRead + AsyncWrite + Unpin + Send> TlsStream for tokio_native_tls::TlsStream<T> {}

#[cfg(feature = "tls-rustls")]
impl<T: AsyncRead + AsyncWrite + Unpin + Send> TlsStream for tokio_rustls::client::TlsStream<T> {}

fn io_error<E>(e: E) -> io::Error
where
    E: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    io::Error::new(io::ErrorKind::InvalidData, e)
}

fn make_channel<S>(stream: S) -> (LdapMessageSender, LdapMessageReceiver)
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
        future::select(to_wire, from_wire).await;
    };

    // spawn in the background
    tokio::spawn(channel);

    // we return (tx_out, rx_in) pair so that the consumer can send and receive messages
    (tx_out, rx_in)
}

/// LDAP channel errors
#[derive(Debug, thiserror::Error)]
pub enum ChannelError {
    #[error(transparent)]
    IoError(#[from] io::Error),

    #[error(transparent)]
    ConnectTimeout(#[from] tokio::time::error::Elapsed),

    #[error("STARTTLS failed")]
    StartTlsFailed,

    #[cfg(feature = "tls-native-tls")]
    #[error(transparent)]
    NativeTls(#[from] native_tls::Error),

    #[cfg(feature = "tls-rustls")]
    #[error(transparent)]
    Rustls(#[from] rustls::Error),

    #[cfg(feature = "tls-rustls")]
    #[error(transparent)]
    DnsName(#[from] rustls_pki_types::InvalidDnsNameError),
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

        debug!("Connection established to {address}");

        let channel = match tls_options.kind {
            TlsKind::Plain => make_channel(stream),
            #[cfg(tls)]
            TlsKind::Tls => make_channel(self.tls_connect(tls_options, stream).await?),
            #[cfg(tls)]
            TlsKind::StartTls => make_channel(self.starttls_connect(tls_options, stream).await?),
        };
        Ok(channel)
    }

    async fn tls_connect<S>(&self, tls_options: TlsOptions, stream: S) -> ChannelResult<Box<dyn TlsStream>>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        match tls_options.backend.unwrap_or_default() {
            #[cfg(feature = "tls-native-tls")]
            TlsBackend::Native(connector) => Ok(Box::new(
                self.tls_connect_native_tls(tls_options.domain_name, connector, stream)
                    .await?,
            )),
            #[cfg(feature = "tls-rustls")]
            TlsBackend::Rustls(client_config) => Ok(Box::new(
                self.tls_connect_rustls(tls_options.domain_name, client_config, stream)
                    .await?,
            )),
        }
    }

    #[cfg(tls)]
    async fn starttls_connect<S>(
        &self,
        tls_options: TlsOptions,
        mut stream: S,
    ) -> ChannelResult<impl AsyncRead + AsyncWrite + Unpin + Send + use<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        use log::warn;
        use rasn_ldap::{ExtendedRequest, ProtocolOp, ResultCode};

        const STARTTLS_TIMEOUT: Duration = Duration::from_secs(30);

        debug!("Begin STARTTLS negotiation");
        let mut framed = tokio_util::codec::Framed::new(&mut stream, LdapCodec);
        let req = ExtendedRequest {
            request_name: crate::oid::STARTTLS_OID.into(),
            request_value: None,
        };
        framed
            .send(LdapMessage::new(1, ProtocolOp::ExtendedReq(req)))
            .await
            .map_err(|_| ChannelError::StartTlsFailed)?;
        match tokio::time::timeout(STARTTLS_TIMEOUT, framed.next()).await {
            Ok(Some(Ok(item))) => match item.protocol_op {
                ProtocolOp::ExtendedResp(resp) if resp.result_code == ResultCode::Success && item.message_id == 1 => {
                    debug!("End STARTTLS negotiation, switching protocols");
                    return self.tls_connect(tls_options, stream).await;
                }
                _ => {
                    warn!("STARTTLS negotiation failed");
                }
            },
            Err(_) => {
                warn!("Timeout occurred while waiting for STARTTLS reply");
            }
            _ => {
                warn!("Unexpected response while waiting for STARTTLS reply");
            }
        }
        Err(ChannelError::StartTlsFailed)
    }

    #[cfg(feature = "tls-native-tls")]
    async fn tls_connect_native_tls<S>(
        &self,
        domain_name: Option<String>,
        tls_connector: native_tls::TlsConnector,
        stream: S,
    ) -> ChannelResult<tokio_native_tls::TlsStream<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let domain = domain_name.as_deref().unwrap_or(&self.address);

        debug!("Performing TLS handshake using native-tls, SNI: {domain}");

        let tokio_connector = tokio_native_tls::TlsConnector::from(tls_connector);

        let stream = tokio_connector
            .connect(domain, stream)
            .await
            .map_err(ChannelError::NativeTls)?;

        debug!("TLS handshake succeeded!");

        Ok(stream)
    }

    #[cfg(feature = "tls-rustls")]
    async fn tls_connect_rustls<S>(
        &self,
        domain_name: Option<String>,
        client_config: rustls::ClientConfig,
        stream: S,
    ) -> ChannelResult<tokio_rustls::client::TlsStream<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        use rustls_pki_types::ServerName;
        use std::sync::Arc;

        let domain = ServerName::try_from(domain_name.as_deref().unwrap_or(&self.address).to_owned())?;

        debug!("Performing TLS handshake using rustls, SNI: {:?}", domain);

        let tokio_connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
        let stream = tokio_connector.connect(domain, stream).await?;

        debug!("TLS handshake succeeded!");

        Ok(stream)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{SocketAddr, ToSocketAddrs},
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
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
                .connect(TlsOptions::default())
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
            .connect(TlsOptions::default())
            .await;

        assert!(res.is_err());
    }
}
