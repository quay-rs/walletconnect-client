use super::{
    BatchFetchMessages, BatchReceiveMessages, BatchSubscribe, BatchUnsubscribe, FetchMessages,
    Publish, Subscribe, Subscription, Unsubscribe, WatchRegister, WatchUnregister,
};
use serde::{Deserialize, Serialize};
/// Enum representing parameters of all possible RPC requests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "method", content = "params")]
pub enum Params {
    /// Parameters to subscribe.
    #[serde(rename = "irn_subscribe", alias = "iridium_subscribe")]
    Subscribe(Subscribe),

    /// Parameters to unsubscribe.
    #[serde(rename = "irn_unsubscribe", alias = "iridium_unsubscribe")]
    Unsubscribe(Unsubscribe),

    /// Parameters to fetch.
    #[serde(rename = "irn_fetchMessages", alias = "iridium_fetchMessages")]
    FetchMessages(FetchMessages),

    /// Parameters to batch subscribe.
    #[serde(rename = "irn_batchSubscribe", alias = "iridium_batchSubscribe")]
    BatchSubscribe(BatchSubscribe),

    /// Parameters to batch unsubscribe.
    #[serde(rename = "irn_batchUnsubscribe", alias = "iridium_batchUnsubscribe")]
    BatchUnsubscribe(BatchUnsubscribe),

    /// Parameters to batch fetch.
    #[serde(rename = "irn_batchFetchMessages", alias = "iridium_batchFetchMessages")]
    BatchFetchMessages(BatchFetchMessages),

    /// Parameters to publish.
    #[serde(rename = "irn_publish", alias = "iridium_publish")]
    Publish(Publish),

    /// Parameters to batch receive.
    #[serde(rename = "irn_batchReceive", alias = "iridium_batchReceive")]
    BatchReceiveMessages(BatchReceiveMessages),

    /// Parameters to watch register.
    #[serde(rename = "irn_watchRegister", alias = "iridium_watchRegister")]
    WatchRegister(WatchRegister),

    /// Parameters to watch unregister.
    #[serde(rename = "irn_watchUnregister", alias = "iridium_watchUnregister")]
    WatchUnregister(WatchUnregister),

    /// Parameters for a subscription. The messages for any given topic sent to
    /// clients are wrapped into this format. A `publish` message to a topic
    /// results in a `subscription` message to each client subscribed to the
    /// topic the data is published for.
    #[serde(rename = "irn_subscription", alias = "iridium_subscription")]
    Subscription(Subscription),
}

/// Enum representing parameters of all possible RPC requests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "method", content = "params")]
pub enum ResponseParams {
    /// Parameters to subscribe.
    #[serde(rename = "irn_subscription", alias = "iridium_subscription")]
    Subscription(Subscription),
    #[serde(rename = "irn_subscribe", alias = "iridium_subscribe")]
    Publish(Publish),
}
