//! The [`DurableStore`] backend trait + its [`StoreError`].
//!
//! Backends (the live Octez node RPC in [`crate::live`]; a future snapshot
//! reader) implement three reads over durable storage: [`DurableStore::subkeys`]
//! (child segments), [`DurableStore::value`] (raw bytes), and
//! [`DurableStore::length`] (byte length, for the large-value guard). Errors are
//! typed so degraded modes are actionable rather than a raw HTTP status.

use core::future::Future;

/// A read-only view over the rollup's durable storage.
///
/// Uses `-> impl Future` rather than `async fn` in the trait to match the
/// workspace convention (avoids the `async_fn_in_trait` lint under the
/// `failOnWarnings` clippy gate). Static dispatch — backends are chosen at the
/// call site, not behind `dyn`.
pub trait DurableStore {
    /// Child key segments under `key`. A `""` entry means `key` also holds a
    /// value (a value-AND-branch node).
    fn subkeys(&self, key: &str) -> impl Future<Output = Result<Vec<String>, StoreError>>;

    /// Raw bytes stored at `key`, or `None` when the key is absent.
    fn value(&self, key: &str) -> impl Future<Output = Result<Option<Vec<u8>>, StoreError>>;

    /// Byte length of the value at `key`, or `None` when the key is absent.
    fn length(&self, key: &str) -> impl Future<Output = Result<Option<u64>, StoreError>>;
}

/// Failure modes of a [`DurableStore`] read, kept typed so the caller can render
/// actionable remediation instead of a raw HTTP status.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// The node's secure ACL blocks this endpoint on a non-loopback bind
    /// (`subkeys`/`values` are blocked by default; `value`/`length` are not).
    #[error(
        "the rollup node's RPC ACL blocks /{endpoint}; run this on the rollup host or start the node with an allow-all ACL"
    )]
    AclBlocked { endpoint: String },
    /// The requested block is past the node's history retention.
    #[error(
        "durable value/subkeys unavailable — the requested block is beyond the node's history retention; try block=head (key: {key})"
    )]
    BlockPruned { key: String },
    /// Transport / HTTP-layer failure talking to the node.
    #[error("rollup RPC HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    /// The node responded, but the body could not be decoded into the expected
    /// shape (non-JSON, bad hex, unexpected value type, wrong status, …).
    #[error("rollup RPC decode error: {0}")]
    Decode(String),
}
