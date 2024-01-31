//! A simple dApp client library for wallet interaction using WalletConnect v2 protocol.
#![doc = include_str!("../README.md")]

#[doc(hidden)]
pub mod auth;
#[doc(hidden)]
pub mod cipher;
#[doc(hidden)]
pub mod did;
#[doc(hidden)]
pub mod domain;
pub mod event;
#[doc(hidden)]
pub mod jwt;
#[doc(hidden)]
pub mod macros;
pub mod metadata;
#[doc(hidden)]
pub mod prelude;
#[doc(hidden)]
pub mod rpc;
#[doc(hidden)]
pub mod serde_helpers;
#[doc(hidden)]
pub mod utils;
#[doc(hidden)]
pub mod watch;

use std::{collections::HashMap, sync::Arc};

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
use metadata::{Method, Namespace, SessionAccount, SessionRpcRequest};
use serde::{Deserialize, Serialize};
use url::Url;
use wasm_bindgen::__rt::WasmRefCell;
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Clone, Serialize, Deserialize)]
pub struct WalletConnectState {
    pub state: State,
    pub keys: Vec<(Topic, StaticSecret)>,
    pub session: Session,
}

/// Enum defining WalletConnect state at the given moment.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum State {
    /// WalletConnect is yet to connect
    Connecting,
    /// Initial subscription is done on given topic. Awaiting for server submission approval
    InitialSubscription(Topic),
    /// Session has been proposed. Awaiting wallet to settle.
    SessionProposed(Topic),
    /// Wallet has sent own symKey. Switching to topic for settlement
    SwitchingTopic(Topic),
    /// Topic switched. Awaiting for wallets settlement message
    AwaitingSettlement(Topic),
    /// WalletConnect client connected to wallet
    Connected(Topic),
    /// WalletConnect client has been disconnected
    Disconnected,
}

impl State {
    pub fn is_connected(&self) -> bool {
        match self {
            Self::Connected(_) => true,
            _ => false,
        }
    }
}

/// MessageId generator based on sequence and current timestamp
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
/// WalletConnect error.
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
struct ClientState {
    pub cipher: Cipher,
    pub subscriptions: HashMap<Topic, String>,
    pub pending: HashMap<MessageId, rpc::Params>,
    pub requests_pending: HashMap<MessageId, UnboundedSender<serde_json::Value>>,
    pub state: State,
    pub session: Session,
}

/// Main struct for handling WallectConnect links with wallets.
#[derive(Clone)]
pub struct WalletConnect {
    sink: Arc<WasmRefCell<SplitSink<WebSocket, Message>>>,
    stream: Arc<WasmRefCell<SplitStream<WebSocket>>>,
    id_generator: MessageIdGenerator,
    state: Arc<WasmRefCell<ClientState>>,
    chain_id: u64,
}

impl WalletConnect {
    /// Connecting to wallets using WalletConnect relay servers
    pub fn connect(
        project_id: ProjectId,
        chain_id: u64,
        metadata: Metadata,
        stored_state: Option<WalletConnectState>,
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

        let (keys, state, session) = match stored_state {
            None => (None, State::Connecting, Session::from(metadata, chain_id)),
            Some(ref s) => (Some(s.keys.clone()), s.state.clone(), s.session.clone()),
        };

        Ok(Self {
            sink: Arc::new(WasmRefCell::new(sink)),
            stream: Arc::new(WasmRefCell::new(stream)),
            id_generator: MessageIdGenerator::default(),
            state: Arc::new(WasmRefCell::new(ClientState {
                cipher: Cipher::new(keys),
                subscriptions: HashMap::new(),
                pending: HashMap::new(),
                requests_pending: HashMap::new(),
                state,
                session,
            })),
            chain_id,
        })
    }

    /// Stores full connection state and passes it for safekeeping
    pub fn get_state(&self) -> WalletConnectState {
        let state = (*self.state).borrow();
        WalletConnectState {
            state: state.state.clone(),
            keys: state.cipher.keys.clone().into_iter().collect::<Vec<_>>(),
            session: state.session.clone(),
        }
    }

    /// Forces disconnection from wallet and relay servers
    pub async fn disconnect(&self) -> Result<(), Error> {
        // Clear all ciphers and queues;
        let mut state = (*self.state).borrow_mut();
        state.cipher.clear();
        state.pending.clear();
        state.requests_pending.clear();

        // We need to send disconnection event
        // TODO: Send disconnection event

        // Set state
        state.state = State::Disconnected;

        Ok(())
    }

    /// Checks if given WallectConnect wallet connection is able to send transactions (not just
    /// signing them)
    pub fn can_send(&self) -> bool {
        match self.namespace() {
            Some(namespace) => namespace.methods.contains(&Method::SendTransaction),
            None => false,
        }
    }

    /// Checks i given WalletCOnnect wallet connection supporst given JSON-RPC method
    pub fn supports_method(&self, method: &str) -> bool {
        if let Ok(method) = method.parse::<Method>() {
            return match self.namespace() {
                Some(namespace) => namespace.methods.contains(&method),
                None => false,
            };
        }

        false
    }

    /// Gets main account from connected wallet. None if no wallet is connected yet.
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

    /// Get all accounts from connected wallet. None if no wallet is connected yet.
    pub fn get_accounts(&self) -> Option<Vec<SessionAccount>> {
        if let Some(namespace) = self.namespace() {
            return namespace.accounts.clone();
        }
        None
    }

    /// Returns a list of available ChainIds in connected account
    pub fn available_networks(self) -> Vec<u64> {
        let mut chain_ids = Vec::new();
        if let Some(namespace) = self.namespace() {
            if let Some(accounts) = &namespace.accounts {
                for acc in accounts {
                    match acc.chain {
                        metadata::Chain::Eip155(chain_id) => {
                            if !chain_ids.contains(&chain_id) {
                                chain_ids.push(chain_id);
                            }
                        }
                    }
                }
            }
        }
        chain_ids
    }

    /// Get all accounts addresses from connected wallet limited to certain `chain_id`. None if no
    /// wallet is connected yet.
    pub fn get_accounts_for_chain_id(&self, chain_id: u64) -> Option<Vec<Address>> {
        if let Some(namespace) = self.namespace() {
            if let Some(accounts) = &namespace.accounts {
                if accounts.len() > 0 {
                    let chain_id = metadata::Chain::Eip155(chain_id);
                    let accounts = accounts
                        .iter()
                        .filter_map(|acc| {
                            if acc.chain == chain_id {
                                Some(acc.account.into())
                            } else {
                                None
                            }
                        })
                        .collect::<Vec<_>>();
                    return Some(accounts);
                }
            }
        }
        None
    }

    /// Gets wallets `chain_id`
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// Gets main accounts address.
    pub fn address(&self) -> ethers::types::Address {
        if let Some(account) = self.get_account() {
            account.account.into()
        } else {
            H160::zero()
        }
    }

    /// Initiates session with WalletConnect relay server
    pub async fn initiate_session(
        &self,
        initial_topics: Option<Vec<Topic>>,
    ) -> Result<String, Error> {
        let mut result = String::new();
        if let Some(topics) = initial_topics {
            for topic in topics {
                self.subscribe(topic).await?;
            }
        } else {
            let topic;
            let key;
            {
                let mut state = (*self.state).borrow_mut();
                (topic, key) = state.cipher.generate();
                let pub_key = PublicKey::from(&key);
                state.session.proposer.public_key = DecodedClientId::from_key(&pub_key).to_hex();
            }
            self.subscribe(topic.clone()).await?;
            {
                let mut state = (*self.state).borrow_mut();
                state.state = State::InitialSubscription(topic.clone());
            }
            result = format!(
                "wc:{}@2?relay-protocol=irn&symKey={}",
                topic,
                DecodedSymKey::from_key(&key.to_bytes())
            );
        }

        Ok(result)
    }

    /// Subscribe for given topic
    pub async fn subscribe(&self, topic: Topic) -> Result<(), Error> {
        self.send(&rpc::Subscribe { topic }).await?;
        Ok(())
    }

    /// Fetch next message recieved from relay server.
    pub async fn next_from_stream(&self) -> Result<Response, Error> {
        let mut stream = (*self.stream).borrow_mut();
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

    pub async fn next(&self) -> Result<Option<event::Event>, Error> {
        let s = (*self.state).borrow().state.clone();
        if s == State::Disconnected {
            return Err(Error::Disconnected);
        }

        let was_connected = s.is_connected();
        if let Ok(resp) = self.next_from_stream().await {
            match resp {
                Response::Success(resp) => {
                    _ = self.process_response(&resp).await;
                }
                Response::Error(err) => {
                    _ = self.process_error_response(&err).await;
                }
                Response::RPCResponse(req) => {
                    let handled = match self.decrypt_params(req.params).await {
                        Ok(_) => true,
                        Err(err) => {
                            error!("Failed to receive {err:?}");
                            false
                        }
                    };
                    _ = self.respond(req.id, handled).await;
                }
            }
        } else {
            (*self.state).borrow_mut().state = State::Disconnected;
        }

        let is_connected = (*self.state).borrow().state.is_connected();
        if was_connected != is_connected {
            Ok(Some(if is_connected {
                event::Event::Connected
            } else {
                event::Event::Disconnected
            }))
        } else {
            Ok(None)
        }
    }

    /// Publish session payload
    pub async fn publish<T: rpc::SessionPayload>(
        &self,
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
            message: (*self.state).borrow().cipher.encode(topic, &payload)?,
            ttl_secs,
            tag,
            prompt,
        };
        self.send(&req).await?;
        Ok(id)
    }

    /// Sending JSON-RPC request to connected wallet.
    pub async fn request(
        &self,
        method: &str,
        params: Option<serde_json::Value>,
        chain_id: u64,
    ) -> Result<serde_json::Value, Error> {
        let topic = match &(*self.state).borrow().state {
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
        (*self.state).borrow_mut().requests_pending.insert(message_id, tx);

        match rx.next().await {
            Some(value) => Ok(value),
            None => Err(Error::BadResponse),
        }
    }

    /// Responds to payload sent from connected wallet
    pub async fn wallet_respond(
        &self,
        topic: &Topic,
        id: MessageId,
        result: bool,
        ttl: Duration,
        tag: u32,
        prompt: bool,
    ) -> Result<(), Error> {
        let state = (*self.state).borrow().clone();
        let ttl_secs = ttl.num_seconds().try_into().map_err(|_| Error::BadParam)?;
        let payload = rpc::SessionResponse {
            id,
            jsonrpc: rpc::JSON_RPC_VERSION_STR.to_string(),
            result: rpc::SessionResultParams::Boolean(result),
        };
        let req = rpc::Publish {
            topic: topic.clone(),
            message: state.cipher.encode(topic, &payload)?,
            ttl_secs,
            tag,
            prompt,
        };
        self.send(&req).await?;
        Ok(())
    }

    /// Sends payload to relay server
    pub async fn send<T: RequestPayload>(&self, request: &T) -> Result<(), Error> {
        let id = self.id_generator.next();
        let params = request.clone().into_params();
        let payload = rpc::Payload::Request(rpc::Request {
            id: id.clone(),
            jsonrpc: rpc::JSON_RPC_VERSION_STR.to_string(),
            params: params.clone(),
        });
        let mut state = (*self.state).borrow_mut();
        state.pending.insert(id, params);
        let serialized_payload = serde_json::to_string(&payload)?;
        (*self.sink).borrow_mut().send(Message::Text(serialized_payload)).await?;
        Ok(())
    }

    /// Sends response to given message recieved from relay server
    pub async fn respond(&self, id: MessageId, success: bool) -> Result<(), Error> {
        let payload = rpc::Response::Success(rpc::SuccessfulResponse {
            id,
            jsonrpc: rpc::JSON_RPC_VERSION_STR.to_string(),
            result: serde_json::Value::Bool(success),
        });
        let serialized_payload = serde_json::to_string(&payload)?;
        (*self.sink).borrow_mut().send(Message::Text(serialized_payload)).await?;
        Ok(())
    }

    async fn decrypt_params(&self, params: ResponseParams) -> Result<(), Error> {
        match params {
            ResponseParams::Publish(payload) => {
                self.consume_message(&payload.topic, &payload.message).await
            }
            ResponseParams::Subscription(payload) => {
                self.consume_message(&payload.data.topic, &payload.data.message).await
            }
        }
    }

    async fn consume_message(&self, topic: &Topic, payload: &str) -> Result<(), Error> {
        let request = (*self.state).borrow().cipher.decode(topic, payload)?;

        match request {
            rpc::SessionMessage::Error(session_error) => {
                error!("Received wallet error {session_error:?}");
                Err(Error::WalletError((session_error.error.code, session_error.error.message)))
            }
            rpc::SessionMessage::Response(response) => match response.result {
                rpc::SessionResultParams::Responder(responder) => {
                    let sub_topic;
                    {
                        let mut state = (*self.state).borrow_mut();
                        let (new_topic, _) = state.cipher.create_common_topic(
                            topic,
                            DecodedClientId::from_hex(&responder.responder_public_key)?,
                        )?;
                        sub_topic = new_topic.clone();
                        state.state = State::SwitchingTopic(new_topic);
                    }
                    self.subscribe(sub_topic.clone()).await?;
                    Ok(())
                }
                rpc::SessionResultParams::Response(resp) => {
                    let mut state = (*self.state).borrow_mut();
                    match state.requests_pending.remove(&response.id) {
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

    async fn process_response(&self, response: &SuccessfulResponse) -> Result<(), Error> {
        let mut propose_topic = None;
        let mut propose = None;
        {
            let mut state = (*self.state).borrow_mut();
            // We need to remove the response from the pending
            let potential_params = state.pending.remove(&response.id);
            if let Some(params) = potential_params {
                match params {
                    rpc::Params::Publish(_) => {}
                    rpc::Params::Subscribe(sub) => {
                        let topic = sub.topic.clone();
                        let sub_hash = response.result.to_string();
                        state.subscriptions.insert(topic.clone(), sub_hash);
                        match &state.state {
                            State::InitialSubscription(awaiting_topic) => {
                                if topic == *awaiting_topic {
                                    state.state = State::SessionProposed(topic.clone());
                                    propose_topic = Some(topic.clone());
                                    propose = Some(state.session.into_propose());
                                }
                            }
                            State::SwitchingTopic(awaiting_topic) => {
                                if topic == *awaiting_topic {
                                    state.state = State::AwaitingSettlement(topic);
                                }
                            }
                            _ => {}
                        }
                    }
                    _ => {}
                }
            }
        }

        if let (Some(topic), Some(propose)) = (propose_topic, propose) {
            _ = self
                .publish(&topic, &propose, Duration::minutes(5), TAG_SESSION_PROPOSE_REQUEST, true)
                .await?;
        }
        Ok(())
    }

    async fn process_error_response(&self, response: &ErrorResponse) -> Result<(), Error> {
        debug!("Error {response:?}");
        let mut state = (*self.state).borrow_mut();
        if let Some(_) = state.pending.remove(&response.id) {
            error!("Received error response from server {response:?}");

            // We should consider better error handling here
        }
        Ok(())
    }

    async fn handle_message(
        &self,
        topic: &Topic,
        request: &rpc::WalletRequest,
    ) -> Result<(), Error> {
        let s = (*self.state).borrow().state.clone();
        match request.params {
            rpc::WalletMessage::Ping(_) => {}
            rpc::WalletMessage::Settlement(ref settlement) => {
                if let State::AwaitingSettlement(settled_topic) = &s {
                    {
                        let mut state = (*self.state).borrow_mut();

                        state.session.settle(&settlement);
                        state.state = State::Connected(settled_topic.clone());
                        let now = Utc::now();
                        let expires_in = state.session.expiry.unwrap() - now;
                        // TODO: Implement session extension when expiry is close to an end
                        debug!(
                            "Session expires at {:?} that is in {:?} seconds",
                            state.session.expiry, expires_in
                        );
                    }
                    // Inform about new wallets and chain - supress errors
                    self.wallet_respond(
                        topic,
                        request.id,
                        true,
                        Duration::minutes(5),
                        TAG_SESSION_SETTLE_RESPONSE,
                        false,
                    )
                    .await?;
                }
            }
        }
        Ok(())
    }

    fn namespace(&self) -> Option<Namespace> {
        let state = (*self.state).borrow();
        if let Some(namespaces) = &state.session.namespaces {
            if let Some(eip155_namespace) = namespaces.get("eip155") {
                return Some(eip155_namespace.clone());
            }
        }
        None
    }
}
