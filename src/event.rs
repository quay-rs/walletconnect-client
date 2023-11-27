use ethers::types::Address;

#[derive(Debug, Clone)]
pub enum Event {
    Connected,
    Disconnected,
    ChainChanged(u64),
    AccountsChanged(Vec<Address>),
}
