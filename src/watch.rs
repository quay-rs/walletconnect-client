use {
    super::{
        domain::Topic,
        jwt::{JwtBasicClaims, VerifyableClaims},
    },
    serde::{Deserialize, Serialize},
};

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WatchType {
    Subscriber,
    Publisher,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WatchStatus {
    Accepted,
    Queued,
    Delivered,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WatchAction {
    #[serde(rename = "irn_watchRegister")]
    Register,
    #[serde(rename = "irn_watchUnregister")]
    Unregister,
    #[serde(rename = "irn_watchEvent")]
    WatchEvent,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct WatchRegisterClaims {
    /// Basic JWT claims.
    #[serde(flatten)]
    pub basic: JwtBasicClaims,
    /// Action. Must be `irn_watchRegister`.
    pub act: WatchAction,
    /// Watcher type. Either subscriber or publisher.
    pub typ: WatchType,
    /// Webhook URL.
    pub whu: String,
    /// Array of message tags to watch.
    pub tag: Vec<u32>,
    /// Array of statuses to watch.
    pub sts: Vec<WatchStatus>,
}

impl VerifyableClaims for WatchRegisterClaims {
    fn basic(&self) -> &JwtBasicClaims {
        &self.basic
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct WatchUnregisterClaims {
    /// Basic JWT claims.
    #[serde(flatten)]
    pub basic: JwtBasicClaims,
    /// Action. Must be `irn_watchUnregister`.
    pub act: WatchAction,
    /// Watcher type. Either subscriber or publisher.
    pub typ: WatchType,
    /// Webhook URL.
    pub whu: String,
}

impl VerifyableClaims for WatchUnregisterClaims {
    fn basic(&self) -> &JwtBasicClaims {
        &self.basic
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WatchEventPayload {
    /// Webhook status. Either `accepted`, `queued` or `delivered`.
    pub status: WatchStatus,
    /// Topic of the message that triggered the watch event.
    pub topic: Topic,
    /// The published message.
    pub message: String,
    /// Message publishing timestamp.
    pub published_at: i64,
    /// Message tag.
    pub tag: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct WatchEventClaims {
    /// Basic JWT claims.
    #[serde(flatten)]
    pub basic: JwtBasicClaims,
    /// Action. Must be `irn_watchEvent`.
    pub act: WatchAction,
    /// Watcher type. Either subscriber or publisher.
    pub typ: WatchType,
    /// Webhook URL.
    pub whu: String,
    /// Event payload.
    pub evt: WatchEventPayload,
}

impl VerifyableClaims for WatchEventClaims {
    fn basic(&self) -> &JwtBasicClaims {
        &self.basic
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WatchWebhookPayload {
    /// JWT with [`WatchEventClaims`] payload.
    pub event_auth: String,
}
