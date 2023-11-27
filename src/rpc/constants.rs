/// Version of the WalletConnect protocol that we're implementing.
pub const JSON_RPC_VERSION_STR: &str = "2.0";

/// The maximum number of topics allowed for a batch subscribe request.
///
/// See <https://github.com/WalletConnect/walletconnect-docs/blob/main/docs/specs/servers/relay/relay-server-rpc.md>
pub const MAX_SUBSCRIPTION_BATCH_SIZE: usize = 500;

/// The maximum number of topics allowed for a batch fetch request.
///
/// See <https://github.com/WalletConnect/walletconnect-docs/blob/main/docs/specs/servers/relay/relay-server-rpc.md>
pub const MAX_FETCH_BATCH_SIZE: usize = 500;

/// The maximum number of receipts allowed for a batch receive request.
///
/// See <https://github.com/WalletConnect/walletconnect-docs/blob/main/docs/specs/servers/relay/relay-server-rpc.md>
pub const MAX_RECEIVE_BATCH_SIZE: usize = 500;

pub const TAG_SESSION_PROPOSE_REQUEST: u32 = 1100;
pub const TAG_SESSION_PROPOSE_RESPONSE: u32 = 1101;

pub const TAG_SESSION_SETTLE_REQUEST: u32 = 1102;
pub const TAG_SESSION_SETTLE_RESPONSE: u32 = 1103;

pub const TAG_SESSION_UPDATE_REQUEST: u32 = 1104;
pub const TAG_SESSION_UPDATE_RESPONSE: u32 = 1105;

pub const TAG_SESSION_EXTEND_REQUEST: u32 = 1106;
pub const TAG_SESSION_EXTEND_RESPONSE: u32 = 1107;

pub const TAG_SESSION_REQUEST_REQUEST: u32 = 1108;
pub const TAG_SESSION_REQUEST_RESPONSE: u32 = 1109;

pub const TAG_SESSION_EVENT_REQUEST: u32 = 1110;
pub const TAG_SESSION_EVENT_RESPONSE: u32 = 1111;

pub const TAG_SESSION_DELETE_REQUEST: u32 = 1112;
pub const TAG_SESSION_DELETE_RESPONSE: u32 = 1113;

pub const TAG_SESSION_PING_REQUEST: u32 = 1114;
pub const TAG_SESSION_PING_RESPONSE: u32 = 1115;
