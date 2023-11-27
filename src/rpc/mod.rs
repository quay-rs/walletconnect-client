pub mod batch;
pub mod constants;
pub mod error;
pub mod fetch;
pub mod msgid;
pub mod params;
pub mod payload;
pub mod publish;
pub mod request;
pub mod response;
pub mod rpc_response;
pub mod session;
pub mod subscribe;
pub mod subscription;
pub mod watch;

pub use batch::*;
pub use constants::*;
pub use error::*;
pub use fetch::*;
pub use msgid::*;
pub use params::*;
pub use payload::*;
pub use publish::*;
pub use request::*;
pub use response::*;
pub use rpc_response::*;
pub use session::*;
pub use subscribe::*;
pub use subscription::*;
pub use watch::*;
pub use watch::*;

use serde::{de::DeserializeOwned, Serialize};
use std::fmt::Debug;

pub trait Serializable:
    Debug + Clone + PartialEq + Eq + Serialize + DeserializeOwned + Send + Sync + 'static
{
}
impl<T> Serializable for T where
    T: Debug + Clone + PartialEq + Eq + Serialize + DeserializeOwned + Send + Sync + 'static
{
}
