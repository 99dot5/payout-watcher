//! HTTP client for the RPC of the two Octez nodes: the L1 node
//! (`octez-node`, [`l1`]) and the smart-rollup node
//! (`octez-smart-rollup-node`, [`rollup`]).
//!
//! The nodes' measured behaviour is written down once, next to the code it
//! shapes:
//!
//! - block identifiers, per node: [`l1::BlockId`], [`rollup::BlockId`];
//! - a block hash, the same on both: [`BlockHash`];
//! - an absent durable key: [`rollup::Client::durable_value`];
//! - the undivided pending outbox and each level's execution status, the
//!   one list that also carries the lost levels: [`rollup::PendingStatus`];
//! - an unknown rollup, other failures and a starting node: [`Error`];
//! - why connections are never reused for one-shot requests: [`Request`].
//!
//! A node's base URL is a [`NodeUrl`], validated when it is built, and every
//! request URL is built by appending path segments to it.

mod block_hash;
mod endpoint;
mod error;
pub mod l1;
mod node_url;
mod profile;
pub mod rollup;

pub use block_hash::{BlockHash, InvalidBlockHash};
pub use error::{Error, RawResponse};
pub use node_url::{InvalidNodeUrl, NodeUrl};
pub use profile::{BuildError, Profile, Request, RequestSettings, Stream, StreamSettings};
pub use reqwest::StatusCode;
pub use url::Url;
