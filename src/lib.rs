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
pub mod watch;

use std::{collections::HashMap, sync::Arc};

use self::rpc::TAG_SESSION_PROPOSE_REQUEST;

use self::{
    auth::{AuthToken, SerializedAuthToken, RELAY_WEBSOCKET_ADDRESS},
    cipher::{Cipher, CipherError},
    domain::{ClientIdDecodingError, DecodedClientId, DecodedSymKey, MessageId, ProjectId, Topic},
    metadata::{Metadata, Session},
    rpc::{
        ErrorResponse, RequestPayload, Response, ResponseParams, SuccessfulResponse,
        TAG_SESSION_SETTLE_RESPONSE,
    },
};

use chrono::{Duration, Utc};
use ed25519_dalek::SigningKey;
use futures::{
    stream::{SplitSink, SplitStream},
    SinkExt, StreamExt,
};
use gloo_net::websocket::{futures::WebSocket, Message, WebSocketError};
use log::{debug, error};
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
    cipher: Cipher,
    id_generator: MessageIdGenerator,
    subscriptions: HashMap<Topic, String>,
    pending: HashMap<MessageId, rpc::Params>,
    state: State,
    session: Session,
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
            cipher: Cipher::new(),
            id_generator: MessageIdGenerator::default(),
            subscriptions: HashMap::new(),
            pending: HashMap::new(),
            state: State::Connecting,
            session: Session::from(metadata, chain_id),
            listener: if let Some(l) = listener { Some(Arc::new(l)) } else { None },
        })
    }

    pub async fn initiate_session(&mut self) -> Result<String, Error> {
        let (topic, key) = self.cipher.generate();
        let pub_key = PublicKey::from(&key);
        self.session.proposer.public_key = DecodedClientId::from_key(&pub_key).to_hex();
        self.state = State::InitialSubscription(topic.clone());
        self.subscribe(topic.clone()).await?;

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
    ) -> Result<(), Error> {
        let ttl_secs = ttl.num_seconds().try_into().map_err(|_| Error::BadParam)?;
        let payload = rpc::Payload::SessionRequest(rpc::SessionRequest {
            id: self.id_generator.next(),
            jsonrpc: rpc::JSON_RPC_VERSION_STR.to_string(),
            params: request.clone().into_params(),
        });
        let req = rpc::Publish {
            topic: topic.clone(),
            message: self.cipher.encode(topic, &payload)?,
            ttl_secs,
            tag,
            prompt,
        };
        self.send(&req).await?;
        Ok(())
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
            message: self.cipher.encode(topic, &payload)?,
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
        self.pending.insert(id, params);
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
        debug!("Responding: {}", &serialized_payload);
        self.sink.borrow_mut().send(Message::Text(serialized_payload)).await?;
        Ok(())
    }

    async fn decrypt_params(&mut self, params: ResponseParams) -> Result<(), Error> {
        match params {
            ResponseParams::Publish(payload) => {
                self.consume_message(
                    &payload.topic,
                    self.cipher.decode(&payload.topic, &payload.message)?,
                )
                .await
            }
            ResponseParams::Subscription(payload) => {
                debug!(
                    "RECEIVED MESSAGE:\n {}",
                    self.cipher.decode_to_string(&payload.data.topic, &payload.data.message)?
                );
                self.consume_message(
                    &payload.data.topic,
                    self.cipher.decode(&payload.data.topic, &payload.data.message)?,
                )
                .await
            }
        }
    }

    async fn consume_message(
        &mut self,
        topic: &Topic,
        response: rpc::SessionMessage,
    ) -> Result<(), Error> {
        match response {
            rpc::SessionMessage::Error(session_error) => {
                error!("Received wallet error {session_error:?}");
                Err(Error::WalletError((session_error.error.code, session_error.error.message)))
            }
            rpc::SessionMessage::Response(response) => match response.result {
                rpc::SessionResultParams::Responder(responder) => {
                    let (new_topic, _) = self.cipher.create_common_topic(
                        topic,
                        DecodedClientId::from_hex(&responder.responder_public_key)?,
                    )?;
                    self.state = State::SwitchingTopic(new_topic.clone());
                    self.subscribe(new_topic.clone()).await?;
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
        if let Some(params) = self.pending.remove(&response.id) {
            match params {
                rpc::Params::Publish(_) => {}
                rpc::Params::Subscribe(sub) => {
                    let topic = sub.topic;
                    let sub_hash = response.result.to_string();
                    self.subscriptions.insert(topic.clone(), sub_hash);
                    match &self.state {
                        State::InitialSubscription(awaiting_topic) => {
                            if topic == *awaiting_topic {
                                self.state_change(State::SessionProposed(topic)).await?;
                            }
                        }
                        State::SwitchingTopic(awaiting_topic) => {
                            if topic == *awaiting_topic {
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
        if let Some(_) = self.pending.remove(&response.id) {
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
        match request.params {
            rpc::WalletMessage::Settlement(ref settlement) => {
                if let State::AwaitingSettlement(settled_topic) = &self.state {
                    self.session.settle(&settlement);
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
                    let expires_in = self.session.expiry.unwrap() - now;
                    debug!(
                        "Session expires at {:?} that is in {:?} seconds",
                        self.session.expiry, expires_in
                    );
                }
            }
        }
        Ok(())
    }

    async fn state_change(&mut self, state: State) -> Result<(), Error> {
        debug!("State changed to {state:?}");
        match state {
            State::SessionProposed(ref topic) => {
                _ = self
                    .publish(
                        &topic,
                        &self.session.into_propose(),
                        Duration::minutes(5),
                        TAG_SESSION_PROPOSE_REQUEST,
                        true,
                    )
                    .await?;
                self.state = state.clone();
            }
            State::Disconnected => {
                self.state = state;
                debug!("WE NEED TO CLEAN UP!");
                self.notify(event::Event::Disconnected);
            }
            State::Connected(_) => {
                self.notify(event::Event::Connected);
            }
            _ => {
                self.state = state;
            }
        }
        Ok(())
    }

    fn notify(&self, event: event::Event) {
        if let Some(l) = &self.listener {
            l(event);
        }
    }

    fn update_events(&self) -> Result<(), Error> {
        let namespace = &self.session.namespaces.as_ref().ok_or_else(|| Error::Unknown)?;
        let eip155_namespace = &namespace.get("eip155").ok_or_else(|| Error::Unknown)?;
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
