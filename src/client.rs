//! LDAP client module

use std::{
    collections::VecDeque,
    convert::{TryFrom, TryInto},
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicU32, Ordering},
        Arc,
    },
    task::{Context, Poll},
};

use futures::{future::BoxFuture, Future, Stream, TryStreamExt};
use parking_lot::RwLock;
use rasn_ldap::{
    AuthenticationChoice, BindRequest, Controls, ExtendedRequest, LdapMessage, LdapResult, ProtocolOp, ResultCode,
    SaslCredentials, SearchResultDone, UnbindRequest,
};

use crate::{
    conn::{LdapConnection, MessageStream},
    controls::SimplePagedResultsControl,
    error::Error,
    oid,
    options::TlsOptions,
    request::SearchRequest,
    ModifyRequest, SearchEntry,
};

pub type Result<T> = std::result::Result<T, Error>;

fn check_result(result: LdapResult) -> Result<()> {
    if result.result_code == ResultCode::Success {
        Ok(())
    } else {
        Err(Error::OperationFailed(result.into()))
    }
}

/// LDAP client builder
pub struct LdapClientBuilder {
    address: String,
    port: u16,
    tls_options: TlsOptions,
}

impl LdapClientBuilder {
    /// Set port number, default is 389
    pub fn port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    /// Set TLS options, default is plain connection
    pub fn tls_options(mut self, options: TlsOptions) -> Self {
        self.tls_options = options;
        self
    }

    /// Build client and connect
    pub async fn connect(self) -> Result<LdapClient> {
        LdapClient::connect(self.address, self.port, self.tls_options).await
    }
}

/// LDAP client
#[derive(Clone)]
pub struct LdapClient {
    connection: LdapConnection,
    id_counter: Arc<AtomicU32>,
}

impl LdapClient {
    /// Create client builder
    pub fn builder<A: AsRef<str>>(address: A) -> LdapClientBuilder {
        LdapClientBuilder {
            address: address.as_ref().to_owned(),
            port: 389,
            tls_options: TlsOptions::plain(),
        }
    }

    pub(crate) async fn connect<A>(address: A, port: u16, tls_options: TlsOptions) -> Result<Self>
    where
        A: AsRef<str>,
    {
        let connection = LdapConnection::connect(address, port, tls_options).await?;
        Ok(Self {
            connection,
            id_counter: Arc::new(AtomicU32::new(2)), // 1 is used by STARTTLS
        })
    }

    fn new_id(&self) -> u32 {
        self.id_counter.fetch_add(1, Ordering::SeqCst)
    }

    async fn do_bind(&mut self, req: BindRequest) -> Result<()> {
        let id = self.new_id();
        let msg = LdapMessage::new(id, ProtocolOp::BindRequest(req));

        let item = self.connection.send_recv(msg).await?;

        match item.protocol_op {
            ProtocolOp::BindResponse(resp) => Ok(check_result(LdapResult::new(
                resp.result_code,
                resp.matched_dn,
                resp.diagnostic_message,
            ))?),
            _ => Err(Error::InvalidResponse),
        }
    }

    /// Perform simple bind operation with username and password
    pub async fn simple_bind<U, P>(&mut self, username: U, password: P) -> Result<()>
    where
        U: AsRef<str>,
        P: AsRef<str>,
    {
        let auth_choice = AuthenticationChoice::Simple(password.as_ref().to_owned().into());
        let req = BindRequest::new(3, username.as_ref().to_owned().into(), auth_choice);
        self.do_bind(req).await
    }

    /// Perform SASL EXTERNAL bind
    pub async fn sasl_external_bind(&mut self) -> Result<()> {
        let auth_choice = AuthenticationChoice::Sasl(SaslCredentials::new("EXTERNAL".into(), None));
        let req = BindRequest::new(3, Default::default(), auth_choice);
        self.do_bind(req).await
    }

    /// Perform unbind operation. This will instruct LDAP server to terminate the connection
    pub async fn unbind(&mut self) -> Result<()> {
        let id = self.new_id();

        let msg = LdapMessage::new(id, ProtocolOp::UnbindRequest(UnbindRequest));
        self.connection.send(msg).await?;

        Ok(())
    }

    /// Send 'whoami' extended request (RFC4532)
    pub async fn whoami(&mut self) -> Result<Option<String>> {
        let id = self.new_id();

        let msg = LdapMessage::new(
            id,
            ProtocolOp::ExtendedReq(ExtendedRequest {
                request_name: oid::WHOAMI_OID.into(),
                request_value: None,
            }),
        );

        let resp = self.connection.send_recv(msg).await?;

        match resp.protocol_op {
            ProtocolOp::ExtendedResp(resp) => {
                check_result(LdapResult::new(
                    resp.result_code,
                    resp.matched_dn,
                    resp.diagnostic_message,
                ))?;
                Ok(resp.response_value.map(|v| String::from_utf8_lossy(&v).into_owned()))
            }
            _ => Err(Error::InvalidResponse),
        }
    }

    /// Perform search operation without paging. Returns a stream of search entries
    pub async fn search(&mut self, request: SearchRequest) -> Result<SearchEntries> {
        let id = self.new_id();

        let msg = LdapMessage::new(id, ProtocolOp::SearchRequest(request.into()));
        let stream = self.connection.send_recv_stream(msg).await?;

        Ok(SearchEntries {
            inner: stream,
            page_control: None,
            page_finished: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Perform search operation without paging and return one result
    pub async fn search_one(&mut self, request: SearchRequest) -> Result<Option<SearchEntry>> {
        let entries = self.search(request).await?;
        let mut attrs = entries.try_collect::<VecDeque<_>>().await?;
        Ok(attrs.pop_front())
    }

    /// Perform search operation with paging. Returns a stream of pages
    pub fn search_paged(&mut self, request: SearchRequest, page_size: u32) -> Pages {
        Pages {
            page_control: Arc::new(RwLock::new(SimplePagedResultsControl::new(page_size))),
            page_finished: Arc::new(AtomicBool::new(true)),
            client: self.clone(),
            request,
            page_size,
            inner: None,
        }
    }

    /// Perform modify operation
    pub async fn modify(&mut self, request: ModifyRequest) -> Result<()> {
        let id = self.new_id();

        let msg = LdapMessage::new(id, ProtocolOp::ModifyRequest(request.into()));
        let resp = self.connection.send_recv(msg).await?;

        match resp.protocol_op {
            ProtocolOp::ModifyResponse(resp) => {
                check_result(LdapResult::new(
                    resp.0.result_code,
                    resp.0.matched_dn,
                    resp.0.diagnostic_message,
                ))?;
                Ok(())
            }
            _ => Err(Error::InvalidResponse),
        }
    }
}

/// Pages represents a stream of paged search results
pub struct Pages {
    page_control: Arc<RwLock<SimplePagedResultsControl>>,
    page_finished: Arc<AtomicBool>,
    client: LdapClient,
    request: SearchRequest,
    page_size: u32,
    inner: Option<BoxFuture<'static, Result<SearchEntries>>>,
}

impl Pages {
    fn is_page_finished(&self) -> bool {
        self.page_finished.load(Ordering::SeqCst)
    }
}

impl Stream for Pages {
    type Item = Result<SearchEntries>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if !self.page_control.read().has_entries() {
            return Poll::Ready(None);
        }

        if self.inner.is_none() {
            if !self.is_page_finished() {
                return Poll::Ready(None);
            }

            let mut client = self.client.clone();
            let request = self.request.clone();
            let control_ref = self.page_control.clone();
            let page_size = self.page_size;
            let page_finished = self.page_finished.clone();

            self.page_finished.store(false, Ordering::SeqCst);

            let fut = async move {
                let id = client.new_id();

                let mut msg = LdapMessage::new(id, ProtocolOp::SearchRequest(request.into()));
                msg.controls = Some(vec![control_ref.read().clone().with_size(page_size).try_into()?]);

                let stream = client.connection.send_recv_stream(msg).await?;
                Ok(SearchEntries {
                    inner: stream,
                    page_control: Some(control_ref),
                    page_finished,
                })
            };
            self.inner = Some(Box::pin(fut));
        }

        match Pin::new(self.inner.as_mut().unwrap()).poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(err)) => Poll::Ready(Some(Err(err))),
            Poll::Ready(Ok(entries)) => {
                self.inner = None;
                Poll::Ready(Some(Ok(entries)))
            }
        }
    }
}

/// Search entries represents a stream of search results
pub struct SearchEntries {
    inner: MessageStream,
    page_control: Option<Arc<RwLock<SimplePagedResultsControl>>>,
    page_finished: Arc<AtomicBool>,
}

impl SearchEntries {
    fn search_done(
        self: Pin<&mut Self>,
        controls: Option<Controls>,
        done: SearchResultDone,
    ) -> Poll<Option<Result<SearchEntry>>> {
        self.page_finished.store(true, Ordering::SeqCst);

        if done.0.result_code == ResultCode::Success {
            if let Some(ref control_ref) = self.page_control {
                let page_control = controls.and_then(|controls| {
                    controls
                        .into_iter()
                        .find(|c| c.control_type == SimplePagedResultsControl::OID)
                        .and_then(|c| SimplePagedResultsControl::try_from(c).ok())
                });

                if let Some(page_control) = page_control {
                    *control_ref.write() = page_control;
                    Poll::Ready(None)
                } else {
                    Poll::Ready(Some(Err(Error::InvalidResponse)))
                }
            } else {
                Poll::Ready(None)
            }
        } else {
            Poll::Ready(Some(Err(Error::OperationFailed(done.0.into()))))
        }
    }
}

impl Stream for SearchEntries {
    type Item = Result<SearchEntry>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            let rc = match Pin::new(&mut self.inner).poll_next(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(None) => Poll::Ready(Some(Err(Error::ConnectionClosed))),
                Poll::Ready(Some(msg)) => match msg.protocol_op {
                    ProtocolOp::SearchResEntry(item) => Poll::Ready(Some(Ok(item.into()))),
                    ProtocolOp::SearchResRef(_) => continue,
                    ProtocolOp::SearchResDone(done) => self.search_done(msg.controls, done),
                    _ => Poll::Ready(Some(Err(Error::InvalidResponse))),
                },
            };
            return rc;
        }
    }
}
