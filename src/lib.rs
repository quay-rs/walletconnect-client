pub mod auth;
pub mod cipher;
pub mod did;
pub mod domain;
pub mod event;
pub mod jwt;
pub mod macros;
pub mod metadata;
pub mod prelude;
pub mod rpc;
pub mod serde_helpers;
pub mod utils;
pub mod watch;

use std::{cell::RefCell, collections::HashMap, sync::Arc};

use self::{
    auth::{AuthToken, SerializedAuthToken, RELAY_WEBSOCKET_ADDRESS},
    cipher::{Cipher, CipherError},
    domain::{ClientIdDecodingError, DecodedClientId, DecodedSymKey, MessageId, ProjectId, Topic},
    metadata::{Metadata, Session},
    rpc::{
        ErrorResponse, RequestPayload, Response, ResponseParams, SuccessfulResponse,
        TAG_SESSION_PROPOSE_REQUEST, TAG_SESSION_REQUEST_REQUEST, TAG_SESSION_SETTLE_RESPONSE,
    },
};

use chrono::{Duration, Utc};
use ed25519_dalek::SigningKey;
use ethers::types::Address;
use ethers::types::H160;
use futures::{
    channel::mpsc::{self, UnboundedSender},
    stream::{SplitSink, SplitStream},
    SinkExt, StreamExt,
};
use gloo_net::websocket::{futures::WebSocket, Message, WebSocketError};
use log::{debug, error};
use metadata::{Chain, Method, Namespace, SessionAccount, SessionRpcRequest};
use serde::Serialize;
use url::Url;
use wasm_bindgen::__rt::WasmRefCell;
use wasm_bindgen_futures::spawn_local;
use x25519_dalek::PublicKey;

#[derive(Debug, Clone)]
pub enum State {
    Connecting,
    InitialSubscription(Topic),
    SessionProposed(Topic),
    SwitchingTopic(Topic),
    AwaitingSettlement(Topic),
    Connected(Topic),
    Disconnected,
}

#[derive(Debug, Clone)]
pub struct MessageIdGenerator {
    next: u64,
}

impl MessageIdGenerator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn next(&self) -> MessageId {
        let next = self.next;
        let timestamp = chrono::Utc::now().timestamp_millis() as u64;
        let id = timestamp << 8 | next;

        MessageId::new(id)
    }
}

impl Default for MessageIdGenerator {
    fn default() -> Self {
        Self { next: 0 }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Query error")]
    Query,

    #[error("Url error")]
    Url,

    #[error("Token error")]
    Token,

    #[error("Disconnected")]
    Disconnected,

    #[error("BadParameter")]
    BadParam,

    #[error("Unknown error")]
    Unknown,

    #[error("Bad response")]
    BadResponse,

    #[error("Wallet error")]
    WalletError((i64, String)),

    #[error(transparent)]
    ClientIdDecodingError(#[from] ClientIdDecodingError),

    #[error(transparent)]
    CipherError(#[from] CipherError),

    #[error(transparent)]
    CorruptedPacket(#[from] serde_json::error::Error),

    #[error(transparent)]
    WebSocketError(#[from] WebSocketError),

    #[error(transparent)]
    JSError(#[from] gloo_utils::errors::JsError),
}

#[derive(Clone)]
pub struct WalletConnect {
    sink: Arc<WasmRefCell<SplitSink<WebSocket, Message>>>,
    stream: Arc<WasmRefCell<SplitStream<WebSocket>>>,
    cipher: Arc<RefCell<Cipher>>,
    id_generator: MessageIdGenerator,
    subscriptions: Arc<RefCell<HashMap<Topic, String>>>,
    pending: Arc<RefCell<HashMap<MessageId, rpc::Params>>>,
    requests_pending: Arc<RefCell<HashMap<MessageId, UnboundedSender<serde_json::Value>>>>,
    state: Arc<RefCell<State>>,
    session: Arc<RefCell<Session>>,
    listener: Option<Arc<Box<dyn Fn(event::Event) + Send + 'static>>>,
}

impl WalletConnect {
    pub fn connect(
        project_id: ProjectId,
        chain_id: u64,
        metadata: Metadata,
        listener: Option<Box<dyn Fn(event::Event) + Send + 'static>>,
    ) -> Result<Self, Error> {
        let key = SigningKey::generate(&mut rand::thread_rng());
        let auth = AuthToken::new(&metadata.url).as_jwt(&key).map_err(|_| Error::Token)?;

        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct QueryParams<'a> {
            project_id: &'a ProjectId,
            auth: &'a SerializedAuthToken,
        }

        let query = serde_qs::to_string(&QueryParams { project_id: &project_id, auth: &auth })
            .map_err(|_| Error::Query)?;

        let mut url = Url::parse(RELAY_WEBSOCKET_ADDRESS).map_err(|_| Error::Url)?;
        url.set_query(Some(&query));

        let ws = WebSocket::open(url.as_str())?;
        let (sink, stream) = ws.split();

        Ok(Self {
            sink: Arc::new(WasmRefCell::new(sink)),
            stream: Arc::new(WasmRefCell::new(stream)),
            cipher: Arc::new(RefCell::new(Cipher::new())),
            id_generator: MessageIdGenerator::default(),
            subscriptions: Arc::new(RefCell::new(HashMap::new())),
            pending: Arc::new(RefCell::new(HashMap::new())),
            requests_pending: Arc::new(RefCell::new(HashMap::new())),
            state: Arc::new(RefCell::new(State::Connecting)),
            session: Arc::new(RefCell::new(Session::from(metadata, chain_id))),
            listener: if let Some(l) = listener { Some(Arc::new(l)) } else { None },
        })
    }

    pub async fn disconnect(&self) -> Result<(), Error> {
        Ok(())
    }

    pub fn can_send(&self) -> bool {
        match self.namespace() {
            Some(namespace) => namespace.methods.contains(&Method::SendTransaction),
            None => false,
        }
    }

    pub fn supports_method(&self, method: &str) -> bool {
        if let Ok(method) = method.parse::<Method>() {
            return match self.namespace() {
                Some(namespace) => namespace.methods.contains(&method),
                None => false,
            };
        }

        false
    }

    pub fn get_account(&self) -> Option<SessionAccount> {
        if let Some(namespace) = &self.namespace() {
            if let Some(accounts) = &namespace.accounts {
                if let Some(account) = accounts.iter().nth(0) {
                    return Some(account.clone());
                }
            }
        }
        None
    }

    pub fn get_accounts(&self) -> Option<Vec<SessionAccount>> {
        if let Some(namespace) = self.namespace() {
            return namespace.accounts.clone();
        }
        None
    }

    pub fn get_accounts_for_chain_id(&self, chain_id: u64) -> Option<Vec<Address>> {
        if let Some(namespace) = self.namespace() {
            if let Some(accounts) = &namespace.accounts {
                return Some(
                    accounts
                        .iter()
                        .filter(|a| {
                            let Chain::Eip155(id) = a.chain;
                            id == chain_id
                        })
                        .map(|a| a.account.into())
                        .collect::<Vec<Address>>(),
                );
            }
        }
        None
    }
    pub fn chain_id(&self) -> u64 {
        if let Some(account) = self.get_account() {
            let Chain::Eip155(chain_id) = account.chain;
            return chain_id;
        }
        0
    }

    pub fn address(&self) -> ethers::types::Address {
        if let Some(account) = self.get_account() {
            account.account.into()
        } else {
            H160::zero()
        }
    }

    pub async fn initiate_session(&mut self) -> Result<String, Error> {
        let (topic, key) = self.cipher.borrow_mut().generate();
        let pub_key = PublicKey::from(&key);
        self.session.borrow_mut().proposer.public_key =
            DecodedClientId::from_key(&pub_key).to_hex();
        self.subscribe(topic.clone()).await?;
        *self.state.borrow_mut() = State::InitialSubscription(topic.clone());

        let mut this = self.clone();
        spawn_local(async move {
            while let Ok(resp) = this.next().await {
                match resp {
                    Response::Success(resp) => {
                        _ = this.process_response(&resp).await;
                    }
                    Response::Error(err) => {
                        _ = this.process_error_response(&err).await;
                    }
                    Response::RPCResponse(req) => {
                        let handled = match this.decrypt_params(req.params).await {
                            Ok(_) => true,
                            Err(err) => {
                                error!("Failed to receive {err:?}");
                                false
                            }
                        };
                        _ = this.respond(req.id, handled).await;
                    }
                }
            }
            _ = this.state_change(State::Disconnected).await;
        });
        Ok(format!(
            "wc:{}@2?relay-protocol=irn&symKey={}",
            topic,
            DecodedSymKey::from_key(&key.to_bytes())
        ))
    }

    pub async fn subscribe(&mut self, topic: Topic) -> Result<(), Error> {
        self.send(&rpc::Subscribe { topic }).await?;
        Ok(())
    }

    pub async fn next(&mut self) -> Result<Response, Error> {
        let mut stream = self.stream.borrow_mut();
        match stream.next().await {
            Some(Ok(Message::Bytes(_))) => Err(Error::BadResponse),
            Some(Ok(Message::Text(text))) => Ok(serde_json::from_str::<Response>(&text)?),
            Some(Err(err)) => {
                error!("{}", err);
                Err(Error::BadResponse)
            }

            None => Err(Error::Disconnected),
        }
    }

    pub async fn publish<T: rpc::SessionPayload>(
        &mut self,
        topic: &Topic,
        request: &T,
        ttl: Duration,
        tag: u32,
        prompt: bool,
    ) -> Result<MessageId, Error> {
        let id = self.id_generator.next();
        let ttl_secs = ttl.num_seconds().try_into().map_err(|_| Error::BadParam)?;
        let payload = rpc::Payload::SessionRequest(rpc::SessionRequest {
            id,
            jsonrpc: rpc::JSON_RPC_VERSION_STR.to_string(),
            params: request.clone().into_params(),
        });
        let req = rpc::Publish {
            topic: topic.clone(),
            message: self.cipher.borrow().encode(topic, &payload)?,
            ttl_secs,
            tag,
            prompt,
        };
        self.send(&req).await?;
        Ok(id)
    }

    pub async fn request(
        &mut self,
        method: &str,
        params: Option<serde_json::Value>,
        chain_id: u64,
    ) -> Result<serde_json::Value, Error> {
        let topic = match *self.state.borrow() {
            State::Connected(ref topic) => Ok(topic.clone()),
            _ => Err(Error::Disconnected),
        }?;
        let message_id = self
            .publish(
                &topic,
                &SessionRpcRequest::new(method, params, chain_id),
                Duration::minutes(5),
                TAG_SESSION_REQUEST_REQUEST,
                true,
            )
            .await?;

        let (tx, mut rx) = mpsc::unbounded::<serde_json::Value>();
        self.requests_pending.borrow_mut().insert(message_id, tx);

        match rx.next().await {
            Some(value) => Ok(value),
            None => Err(Error::BadResponse),
        }
    }

    pub async fn wallet_respond(
        &mut self,
        topic: &Topic,
        id: MessageId,
        result: bool,
        ttl: Duration,
        tag: u32,
        prompt: bool,
    ) -> Result<(), Error> {
        let ttl_secs = ttl.num_seconds().try_into().map_err(|_| Error::BadParam)?;
        let payload = rpc::SessionResponse {
            id,
            jsonrpc: rpc::JSON_RPC_VERSION_STR.to_string(),
            result: rpc::SessionResultParams::Boolean(result),
        };
        let req = rpc::Publish {
            topic: topic.clone(),
            message: self.cipher.borrow().encode(topic, &payload)?,
            ttl_secs,
            tag,
            prompt,
        };
        self.send(&req).await?;
        Ok(())
    }

    pub async fn send<T: RequestPayload>(&mut self, request: &T) -> Result<(), Error> {
        let id = self.id_generator.next();
        let params = request.clone().into_params();
        let payload = rpc::Payload::Request(rpc::Request {
            id: id.clone(),
            jsonrpc: rpc::JSON_RPC_VERSION_STR.to_string(),
            params: params.clone(),
        });
        self.pending.borrow_mut().insert(id, params);
        let serialized_payload = serde_json::to_string(&payload)?;
        self.sink.borrow_mut().send(Message::Text(serialized_payload)).await?;
        Ok(())
    }

    pub async fn respond(&mut self, id: MessageId, success: bool) -> Result<(), Error> {
        let payload = rpc::Response::Success(rpc::SuccessfulResponse {
            id,
            jsonrpc: rpc::JSON_RPC_VERSION_STR.to_string(),
            result: serde_json::Value::Bool(success),
        });
        let serialized_payload = serde_json::to_string(&payload)?;
        self.sink.borrow_mut().send(Message::Text(serialized_payload)).await?;
        Ok(())
    }

    async fn decrypt_params(&mut self, params: ResponseParams) -> Result<(), Error> {
        match params {
            ResponseParams::Publish(payload) => {
                self.consume_message(&payload.topic, &payload.message).await
            }
            ResponseParams::Subscription(payload) => {
                self.consume_message(&payload.data.topic, &payload.data.message).await
            }
        }
    }

    async fn consume_message(&mut self, topic: &Topic, payload: &str) -> Result<(), Error> {
        debug!("RECEIVED MESSAGE:\n {}", self.cipher.borrow().decode_to_string(&topic, &payload)?);
        let request = self.cipher.borrow().decode(topic, payload)?;

        // This protocol was invented by halfwitts not getting how to diffrenciate types properly.
        // A typical wallet response is formatted clo

        match request {
            rpc::SessionMessage::Error(session_error) => {
                error!("Received wallet error {session_error:?}");
                Err(Error::WalletError((session_error.error.code, session_error.error.message)))
            }
            rpc::SessionMessage::Response(response) => match response.result {
                rpc::SessionResultParams::Responder(responder) => {
                    let (new_topic, _) = self.cipher.borrow_mut().create_common_topic(
                        topic,
                        DecodedClientId::from_hex(&responder.responder_public_key)?,
                    )?;
                    self.subscribe(new_topic.clone()).await?;
                    *self.state.borrow_mut() = State::SwitchingTopic(new_topic.clone());
                    Ok(())
                }
                rpc::SessionResultParams::Response(resp) => {
                    match self.requests_pending.borrow_mut().remove(&response.id) {
                        Some(mut tx) => {
                            _ = tx.send(resp).await;
                        }
                        None => {}
                    };
                    Ok(())
                }
                _ => {
                    debug!("Received unhandled result: {:?}", response.result);
                    Ok(())
                }
            },
            rpc::SessionMessage::Message(message) => {
                self.handle_message(&topic, &message).await?;
                Ok(())
            }
        }
    }

    async fn process_response(&mut self, response: &SuccessfulResponse) -> Result<(), Error> {
        // We need to remove the response from the pending
        let potential_params = self.pending.borrow_mut().remove(&response.id);
        if let Some(params) = potential_params {
            match params {
                rpc::Params::Publish(_) => {}
                rpc::Params::Subscribe(sub) => {
                    let topic = sub.topic;
                    let sub_hash = response.result.to_string();
                    self.subscriptions.borrow_mut().insert(topic.clone(), sub_hash);
                    let state = self.state.borrow().clone();
                    match state {
                        State::InitialSubscription(awaiting_topic) => {
                            if topic == awaiting_topic {
                                self.state_change(State::SessionProposed(topic)).await?;
                            }
                        }
                        State::SwitchingTopic(awaiting_topic) => {
                            if topic == awaiting_topic {
                                self.state_change(State::AwaitingSettlement(topic)).await?;
                            }
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    async fn process_error_response(&mut self, response: &ErrorResponse) -> Result<(), Error> {
        debug!("Error {response:?}");
        if let Some(_) = self.pending.borrow_mut().remove(&response.id) {
            error!("Received error response from server {response:?}");

            // We should consider better error handling here
        }
        Ok(())
    }

    async fn handle_message(
        &mut self,
        topic: &Topic,
        request: &rpc::WalletRequest,
    ) -> Result<(), Error> {
        let state = self.state.borrow().clone();
        match request.params {
            rpc::WalletMessage::Settlement(ref settlement) => {
                if let State::AwaitingSettlement(settled_topic) = state {
                    self.session.borrow_mut().settle(&settlement);
                    self.state_change(State::Connected(settled_topic.clone())).await?;
                    // Inform about new wallets and chain - supress errors
                    _ = self.update_events();
                    self.wallet_respond(
                        topic,
                        request.id,
                        true,
                        Duration::minutes(5),
                        TAG_SESSION_SETTLE_RESPONSE,
                        false,
                    )
                    .await?;
                    // TODO: Implement session extension when expiry is close to an end
                    let now = Utc::now();
                    let expires_in = self.session.borrow_mut().expiry.unwrap() - now;
                    debug!(
                        "Session expires at {:?} that is in {:?} seconds",
                        self.session.borrow().expiry,
                        expires_in
                    );
                }
            }
        }
        Ok(())
    }

    async fn state_change(&mut self, new_state: State) -> Result<(), Error> {
        *self.state.borrow_mut() = new_state.clone();
        match new_state {
            State::SessionProposed(ref topic) => {
                let propose = self.session.borrow().into_propose();
                _ = self
                    .publish(
                        &topic,
                        &propose,
                        Duration::minutes(5),
                        TAG_SESSION_PROPOSE_REQUEST,
                        true,
                    )
                    .await?;
            }
            State::Disconnected => {
                debug!("WE NEED TO CLEAN UP!");
                self.notify(event::Event::Disconnected);
            }
            State::Connected(_) => {
                self.notify(event::Event::Connected);
            }
            _ => {}
        }
        Ok(())
    }

    fn namespace(&self) -> Option<Namespace> {
        if let Some(namespaces) = &self.session.borrow().namespaces {
            if let Some(eip155_namespace) = namespaces.get("eip155") {
                return Some(eip155_namespace.clone());
            }
        }
        None
    }

    fn notify(&self, event: event::Event) {
        if let Some(l) = &self.listener {
            l(event);
        }
    }

    fn update_events(&self) -> Result<(), Error> {
        let eip155_namespace = self.namespace().ok_or_else(|| Error::Unknown)?;
        if let Some(accounts) = &eip155_namespace.accounts {
            if let Some(first) = accounts.iter().nth(0) {
                let chain = first.chain.clone();
                let metadata::Chain::Eip155(chain_id) = chain;
                let accounts =
                    accounts
                        .iter()
                        .filter_map(|acc| {
                            if acc.chain == chain {
                                Some(acc.account.into())
                            } else {
                                None
                            }
                        })
                        .collect::<Vec<_>>();
                self.notify(event::Event::ChainChanged(chain_id));
                self.notify(event::Event::AccountsChanged(accounts));
            }
        }
        Ok(())
    }
}
