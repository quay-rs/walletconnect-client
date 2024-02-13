use std::{collections::HashMap, fmt::Display, num::ParseIntError, str::FromStr};

use chrono::{DateTime, NaiveDateTime, Utc};
use ethers::{types::H160, utils::hex};
use serde::{de::Error, Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

use super::{
    domain::Topic,
    rpc::{SessionParams, SessionPayload},
};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProtocolOption {
    protocol: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<String>,
}

impl Default for ProtocolOption {
    fn default() -> Self {
        Self { protocol: "irn".to_string(), data: None }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Redirects {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub native: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub universal: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Metadata {
    pub name: String,
    pub description: String,
    pub url: String,
    pub icons: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verify_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect: Option<Redirects>,
}

impl Metadata {
    pub fn from(name: &str, description: &str, url: &str, icons: Vec<String>) -> Self {
        Self {
            name: name.to_string(),
            description: description.to_string(),
            url: url.to_string(),
            icons,
            verify_url: None,
            redirect: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Peer {
    pub public_key: String,
    pub metadata: Metadata,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Event {
    #[serde(rename = "chainChanged")]
    ChainChanged,
    #[serde(rename = "accountsChanged")]
    AccountsChanged,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Method {
    #[serde(rename = "personal_sign")]
    Sign,
    #[serde(rename = "eth_signTypedData")]
    SignTypedData,
    #[serde(rename = "eth_signTypedData_v4")]
    SignTypedDataV4,
    #[serde(rename = "eth_signTransaction")]
    SignTransaction,
    #[serde(rename = "eth_sendTransaction")]
    SendTransaction,
}

impl FromStr for Method {
    type Err = bool;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "personal_sign" => Ok(Method::Sign),
            "eth_signTypedData" => Ok(Method::SignTypedData),
            "eth_signTypedData_v4" => Ok(Method::SignTypedDataV4),
            "eth_signTransaction" => Ok(Method::SignTransaction),
            "eth_sendTransaction" => Ok(Method::SendTransaction),
            _ => Err(false),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Chain {
    Eip155(u64),
}

#[derive(Debug, Clone, Error)]
pub enum ChainError {
    #[error("Chain information provided in bad format")]
    BadFormat,

    #[error("Invalid chain type")]
    InvalidType,

    #[error(transparent)]
    ParseIntError(#[from] ParseIntError),
}

impl FromStr for Chain {
    type Err = ChainError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let components = s.split(":").collect::<Vec<_>>();
        if components.len() != 2 {
            return Err(ChainError::BadFormat);
        }

        if components[0].to_lowercase() != "eip155" {
            return Err(ChainError::InvalidType);
        }

        Ok(Self::Eip155(components[1].parse::<u64>()?))
    }
}

impl Display for Chain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Eip155(chain_id) => f.write_str(&format!("eip155:{chain_id}")),
        }
    }
}

impl Serialize for Chain {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("{self}"))
    }
}
impl<'de> Deserialize<'de> for Chain {
    fn deserialize<D>(deserializer: D) -> Result<Chain, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: &str = Deserialize::deserialize(deserializer)?;

        s.parse::<Chain>().map_err(D::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Namespace {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accounts: Option<Vec<SessionAccount>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chains: Option<Vec<Chain>>,
    pub methods: Vec<Method>,
    pub events: Vec<Event>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Session {
    pub relay: ProtocolOption,
    pub namespaces: Option<HashMap<String, Namespace>>,
    pub required_namespaces: HashMap<String, Namespace>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub optional_namespaces: Option<HashMap<String, Namespace>>,
    pub pairing_topic: Option<Topic>,
    pub proposer: Peer,
    pub controller: Option<Peer>,
    pub expiry: Option<DateTime<Utc>>,
}

impl Session {
    pub fn from(metadata: Metadata, chain_id: u64) -> Self {
        let mut required_namespaces = HashMap::new();
        let mut optional_namespaces = HashMap::new();

        required_namespaces.insert(
            "eip155".to_string(),
            Namespace {
                accounts: None,
                chains: Some(vec![Chain::Eip155(chain_id)]),
                methods: vec![Method::SignTransaction, Method::SignTypedDataV4],
                events: vec![Event::ChainChanged, Event::AccountsChanged],
            },
        );

        optional_namespaces.insert(
            "eip155".to_string(),
            Namespace {
                accounts: None,
                chains: Some(vec![Chain::Eip155(chain_id)]),
                methods: vec![Method::SendTransaction, Method::Sign, Method::SignTypedData],
                events: Vec::new(),
            },
        );

        Self {
            relay: ProtocolOption { protocol: "irn".to_string(), data: None },
            namespaces: None,
            required_namespaces,
            optional_namespaces: Some(optional_namespaces),
            pairing_topic: None,
            proposer: Peer { public_key: "".to_string(), metadata },
            controller: None,
            expiry: None,
        }
    }

    pub fn settle(&mut self, settlement: &SessionSettlement) {
        self.namespaces = Some(settlement.namespaces.clone());
        self.controller = Some(settlement.controller.clone());
        self.expiry = Some(DateTime::from_naive_utc_and_offset(
            NaiveDateTime::from_timestamp_opt(settlement.expiry, 0).unwrap(),
            Utc::now().offset().clone(),
        ));
        self.pairing_topic = Some(settlement.pairing_topic.clone());
    }

    pub fn into_propose(&self) -> SessionPropose {
        SessionPropose {
            relays: vec![self.relay.clone()],
            required_namespaces: self.required_namespaces.clone(),
            optional_namespaces: self.optional_namespaces.clone(),
            proposer: self.proposer.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionRpcRequestData {
    pub method: String,
    pub params: Option<serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionRpcRequest {
    pub request: SessionRpcRequestData,
    pub chain_id: Chain,
}

impl SessionRpcRequest {
    pub fn new(method: &str, params: Option<serde_json::Value>, chain_id: u64) -> Self {
        Self {
            request: SessionRpcRequestData { method: method.to_string(), params },
            chain_id: Chain::Eip155(chain_id),
        }
    }
}

impl SessionPayload for SessionRpcRequest {
    fn into_params(self) -> SessionParams {
        SessionParams::Request(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionPropose {
    pub relays: Vec<ProtocolOption>,
    pub required_namespaces: HashMap<String, Namespace>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub optional_namespaces: Option<HashMap<String, Namespace>>,
    pub proposer: Peer,
}

impl SessionPayload for SessionPropose {
    fn into_params(self) -> SessionParams {
        SessionParams::Propose(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Responder {
    pub relay: ProtocolOption,
    pub responder_public_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Empty {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionSettlement {
    pub relay: ProtocolOption,
    pub namespaces: HashMap<String, Namespace>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required_namespaces: Option<HashMap<String, Namespace>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub optional_namespaces: Option<HashMap<String, Namespace>>,
    pub pairing_topic: Topic,
    pub controller: Peer,
    pub expiry: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SessionAccount {
    pub chain: Chain,
    pub account: H160,
}

#[derive(Debug, Clone, Error)]
pub enum SessionAccountError {
    #[error("Account information provided in bad format")]
    BadFormat,

    #[error("Invalid chain type")]
    InvalidType,

    #[error(transparent)]
    ParseIntError(#[from] ParseIntError),

    #[error("Account address in bad format")]
    ParseAccountError,
}

impl FromStr for SessionAccount {
    type Err = SessionAccountError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let components = s.split(":").collect::<Vec<_>>();
        if components.len() != 3 {
            return Err(SessionAccountError::BadFormat);
        }

        if components[0].to_lowercase() != "eip155" {
            return Err(SessionAccountError::InvalidType);
        }

        Ok(SessionAccount {
            chain: Chain::Eip155(components[1].parse::<u64>()?),
            account: H160::from_str(components[2])
                .map_err(|_| SessionAccountError::ParseAccountError)?,
        })
    }
}

impl Display for SessionAccount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!("{}:{}", self.chain, hex::encode(self.account)))
    }
}

impl Serialize for SessionAccount {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("{self}"))
    }
}

impl<'de> Deserialize<'de> for SessionAccount {
    fn deserialize<D>(deserializer: D) -> Result<SessionAccount, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: &str = Deserialize::deserialize(deserializer)?;

        s.parse::<SessionAccount>().map_err(D::Error::custom)
    }
}
