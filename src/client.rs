use std::{
    convert::{TryFrom, TryInto},
    io,
    sync::atomic::{AtomicU32, Ordering},
};

use futures::{SinkExt, StreamExt};
use log::{error, trace};
use rasn_ldap::{
    AuthenticationChoice, BindRequest, LdapMessage, LdapResult, ProtocolOp, ResultCode,
    SearchRequest, SearchResultEntry, UnbindRequest,
};

use crate::{
    channel::{LdapChannel, LdapMessageReceiver, LdapMessageSender, TlsOptions},
    controls::{SimplePagedResultsControl, PAGED_CONTROL_OID},
    error::Error,
};

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

    pub async fn build_and_connect(self) -> Result<LdapClient, Error> {
        LdapClient::connect(self.address, self.port, self.tls_options).await
    }
}

pub struct LdapClient {
    sender: LdapMessageSender,
    receiver: LdapMessageReceiver,
    id_counter: AtomicU32,
}

impl LdapClient {
    pub fn builder<A: AsRef<str>>(address: A) -> LdapClientBuilder {
        LdapClientBuilder {
            address: address.as_ref().to_owned(),
            port: 389,
            tls_options: TlsOptions::plain(),
        }
    }

    pub async fn connect<A>(address: A, port: u16, tls_options: TlsOptions) -> Result<Self, Error>
    where
        A: AsRef<str>,
    {
        let (sender, receiver) = LdapChannel::for_client(address, port)
            .connect(tls_options)
            .await?;
        Ok(Self {
            sender,
            receiver,
            id_counter: AtomicU32::new(2),
        })
    }

    fn new_id(&mut self) -> u32 {
        self.id_counter.fetch_add(1, Ordering::SeqCst)
    }

    async fn recv_message(&mut self, id: u32) -> Result<LdapMessage, Error> {
        let msg =
            self.receiver.next().await.ok_or_else(|| {
                io::Error::new(io::ErrorKind::ConnectionReset, "Connection closed")
            })?;
        if msg.message_id == id {
            Ok(msg)
        } else {
            Err(Error::InvalidMessageId)
        }
    }

    fn check_result(&self, result: LdapResult) -> Result<(), Error> {
        if result.result_code == ResultCode::Success {
            Ok(())
        } else {
            Err(Error::OperationFailed(result.into()))
        }
    }

    pub async fn simple_bind<U, P>(&mut self, username: U, password: P) -> Result<(), Error>
    where
        U: AsRef<str>,
        P: AsRef<str>,
    {
        let id = self.new_id();

        let auth_choice = AuthenticationChoice::Simple(password.as_ref().to_owned().into());
        let req = BindRequest::new(3, username.as_ref().to_owned().into(), auth_choice);
        let msg = LdapMessage::new(id, ProtocolOp::BindRequest(req));

        trace!("Sending message: {:?}", msg);
        self.sender.send(msg).await?;

        let item = self.recv_message(id).await?;
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

    pub async fn unbind(&mut self) -> Result<(), Error> {
        let id = self.new_id();

        let msg = LdapMessage::new(id, ProtocolOp::UnbindRequest(UnbindRequest));
        self.sender.send(msg).await?;
        Ok(())
    }

    pub async fn search(
        &mut self,
        request: SearchRequest,
    ) -> Result<Vec<SearchResultEntry>, Error> {
        let id = self.new_id();

        let msg = LdapMessage::new(id, ProtocolOp::SearchRequest(request));
        self.sender.send(msg).await?;

        let mut entries = Vec::new();

        loop {
            let item = self.recv_message(id).await?;
            trace!("Received message: {:?}", item);

            match item.protocol_op {
                ProtocolOp::SearchResEntry(entry) => entries.push(entry),
                ProtocolOp::SearchResRef(_) => {}
                ProtocolOp::SearchResDone(done) => {
                    self.check_result(done.0)?;
                    break;
                }
                other => {
                    error!("Invalid search response: {:?}", other);
                    return Err(Error::InvalidResponse);
                }
            }
        }
        Ok(entries)
    }

    pub async fn search_paged(
        &mut self,
        request: SearchRequest,
        control: SimplePagedResultsControl,
    ) -> Result<(Vec<SearchResultEntry>, SimplePagedResultsControl), Error> {
        let id = self.new_id();

        let mut msg = LdapMessage::new(id, ProtocolOp::SearchRequest(request));
        msg.controls = Some(vec![control.try_into()?]);

        self.sender.send(msg).await?;

        let mut entries = Vec::new();

        loop {
            let item = self.recv_message(id).await?;
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
