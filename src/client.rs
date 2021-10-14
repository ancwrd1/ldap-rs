use std::{
    convert::{TryFrom, TryInto},
    pin::Pin,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    },
    task::{Context, Poll},
};

use futures::{future::BoxFuture, Future, Stream, StreamExt};
use log::{error, trace};
use rasn_ldap::{
    AuthenticationChoice, BindRequest, LdapMessage, LdapResult, ProtocolOp, ResultCode, SearchRequest,
    SearchResultEntry, UnbindRequest,
};

use crate::conn::MessageStream;
use crate::{
    channel::TlsOptions,
    conn::LdapConnection,
    controls::{SimplePagedResultsControl, PAGED_CONTROL_OID},
    error::Error,
};

pub type Result<T> = std::result::Result<T, Error>;

type SearchResult = Result<(Vec<SearchResultEntry>, SimplePagedResultsControl)>;

pub struct LdapClientBuilder {
    address: String,
    port: u16,
    tls_options: TlsOptions,
}

impl LdapClientBuilder {
    pub fn port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    pub fn tls_options(mut self, options: TlsOptions) -> Self {
        self.tls_options = options;
        self
    }

    pub async fn build_and_connect(self) -> Result<LdapClient> {
        LdapClient::connect(self.address, self.port, self.tls_options).await
    }
}

#[derive(Clone)]
pub struct LdapClient {
    connection: LdapConnection,
    id_counter: Arc<AtomicU32>,
}

impl LdapClient {
    pub fn builder<A: AsRef<str>>(address: A) -> LdapClientBuilder {
        LdapClientBuilder {
            address: address.as_ref().to_owned(),
            port: 389,
            tls_options: TlsOptions::plain(),
        }
    }

    pub async fn connect<A>(address: A, port: u16, tls_options: TlsOptions) -> Result<Self>
    where
        A: AsRef<str>,
    {
        let connection = LdapConnection::connect(address, port, tls_options).await?;
        Ok(Self {
            connection,
            id_counter: Arc::new(AtomicU32::new(2)), // 1 is used by STARTTLS
        })
    }

    fn new_id(&mut self) -> u32 {
        self.id_counter.fetch_add(1, Ordering::SeqCst)
    }

    fn check_result(&self, result: LdapResult) -> Result<()> {
        if result.result_code == ResultCode::Success {
            Ok(())
        } else {
            Err(Error::OperationFailed(result.into()))
        }
    }

    pub async fn simple_bind<U, P>(&mut self, username: U, password: P) -> Result<()>
    where
        U: AsRef<str>,
        P: AsRef<str>,
    {
        let id = self.new_id();

        let auth_choice = AuthenticationChoice::Simple(password.as_ref().to_owned().into());
        let req = BindRequest::new(3, username.as_ref().to_owned().into(), auth_choice);
        let msg = LdapMessage::new(id, ProtocolOp::BindRequest(req));

        trace!("Sending message: {:?}", msg);
        let item = self.connection.send_recv(msg).await?;
        trace!("Received message: {:?}", item);

        match item.protocol_op {
            ProtocolOp::BindResponse(resp) => Ok(self.check_result(LdapResult::new(
                resp.result_code,
                resp.matched_dn,
                resp.diagnostic_message,
            ))?),
            _ => Err(Error::InvalidResponse),
        }
    }

    pub async fn unbind(&mut self) -> Result<()> {
        let id = self.new_id();

        let msg = LdapMessage::new(id, ProtocolOp::UnbindRequest(UnbindRequest));
        self.connection.send(msg).await?;
        Ok(())
    }

    pub async fn search(&mut self, request: SearchRequest) -> Result<SearchEntryStream> {
        let id = self.new_id();

        let msg = LdapMessage::new(id, ProtocolOp::SearchRequest(request));
        let stream = self.connection.send_recv_stream(msg).await?;

        Ok(SearchEntryStream { inner: stream })
    }

    pub fn search_paged(&mut self, request: SearchRequest, page_size: u32) -> PageStream {
        PageStream {
            control: SimplePagedResultsControl::new(page_size),
            client: self.clone(),
            request,
            page_size,
            last_page: false,
            inner: None,
        }
    }

    async fn do_search_paged(&mut self, request: SearchRequest, control: SimplePagedResultsControl) -> SearchResult {
        let id = self.new_id();

        let mut msg = LdapMessage::new(id, ProtocolOp::SearchRequest(request));
        msg.controls = Some(vec![control.try_into()?]);

        let mut stream = self.connection.send_recv_stream(msg).await?;
        let mut entries = Vec::new();

        while let Some(item) = stream.next().await {
            trace!("Received message: {:?}", item);

            match item.protocol_op {
                ProtocolOp::SearchResEntry(entry) => entries.push(entry),
                ProtocolOp::SearchResRef(_) => {}
                ProtocolOp::SearchResDone(done) => {
                    self.check_result(done.0)?;

                    if let Some(controls) = item.controls {
                        if let Some(control) = controls
                            .into_iter()
                            .find(|c| c.control_type == PAGED_CONTROL_OID)
                            .map(|c| SimplePagedResultsControl::try_from(c).ok())
                            .flatten()
                        {
                            return Ok((entries, control));
                        } else {
                            error!("No paged control in the SearchResDone");
                        }
                    } else {
                        error!("No controls returned in the SearchResDone");
                    }
                    break;
                }
                other => {
                    error!("Invalid search response: {:?}", other);
                    break;
                }
            }
        }
        Err(Error::InvalidResponse)
    }
}

pub struct PageStream {
    control: SimplePagedResultsControl,
    client: LdapClient,
    request: SearchRequest,
    page_size: u32,
    last_page: bool,
    inner: Option<BoxFuture<'static, SearchResult>>,
}

impl Stream for PageStream {
    type Item = Result<Vec<SearchResultEntry>>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.last_page {
            return Poll::Ready(None);
        }

        if self.inner.is_none() {
            let mut client = self.client.clone();
            let request = self.request.clone();
            let control = self.control.clone();
            let page_size = self.page_size;

            let fut = async move { client.do_search_paged(request, control.with_size(page_size)).await };
            self.inner = Some(Box::pin(fut));
        }

        match Pin::new(self.inner.as_mut().unwrap()).poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(err)) => {
                self.last_page = true;
                Poll::Ready(Some(Err(err)))
            }
            Poll::Ready(Ok((items, control))) => {
                if control.cookie().is_empty() {
                    self.last_page = true;
                }
                self.control = control;
                self.inner = None;
                Poll::Ready(Some(Ok(items)))
            }
        }
    }
}

pub struct SearchEntryStream {
    inner: MessageStream,
}

impl Stream for SearchEntryStream {
    type Item = Result<SearchResultEntry>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match Pin::new(&mut self.inner).poll_next(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => Poll::Ready(Some(Err(Error::ConnectionClosed))),
            Poll::Ready(Some(msg)) => match msg.protocol_op {
                ProtocolOp::SearchResEntry(item) => Poll::Ready(Some(Ok(item))),
                ProtocolOp::SearchResDone(done) => {
                    if done.0.result_code == ResultCode::Success {
                        Poll::Ready(None)
                    } else {
                        Poll::Ready(Some(Err(Error::OperationFailed(done.0.into()))))
                    }
                }
                _ => Poll::Ready(Some(Err(Error::InvalidResponse))),
            },
        }
    }
}
