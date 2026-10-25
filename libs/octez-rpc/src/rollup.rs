//! The smart-rollup node's RPC (`octez-smart-rollup-node`): `/global` reads
//! and `/local` node state; the write side is [`batcher`].

pub mod batcher;
mod block_id;
mod outbox;

pub use block_id::BlockId;
pub use outbox::{OutboxTransaction, PendingOutboxEntry, PendingOutboxMessage, PendingStatus};

use crate::NodeUrl;
use crate::error::{Error, RawResponse};
use crate::profile::{BuildError, Profile, Request, Transport};
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::fmt;

/// The PVM whose durable storage the `durable` endpoints read.
const PVM: &str = "wasm_2_0_0";

/// A client of one rollup node, in connection profile `P`, which defaults to
/// [`Request`].
#[derive(Debug, Clone)]
pub struct Client<P = Request> {
    transport: Transport<P>,
}

/// Which pending outbox list to read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingOutbox {
    /// Cemented, waiting for an L1 execution.
    Executable,
    /// Not cemented yet.
    Unexecutable,
}

impl fmt::Display for PendingOutbox {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Executable => "executable",
            Self::Unexecutable => "unexecutable",
        })
    }
}

impl<P: Profile> Client<P> {
    /// A client of the rollup node at `base`.
    pub fn new(base: NodeUrl, settings: P::Settings) -> Result<Self, BuildError> {
        Ok(Self {
            transport: Transport::new(base, &settings)?,
        })
    }
}

/// Every one-shot `GET` path this crate reads from the rollup node, so each
/// one is spelled exactly once: a typed read and its `*_raw` twin build their
/// URL from the same entry. The batcher's `POST` is not here.
#[derive(Debug, Clone, Copy)]
pub(crate) enum RollupPath<'a> {
    DurableValue(&'a BlockId, &'a str),
    DurableLength(&'a BlockId, &'a str),
    DurableSubkeys(&'a BlockId, &'a str),
    Level(&'a BlockId),
    TezosLevel,
    SmartRollupAddress,
    OutboxPending(PendingOutbox),
    /// The undivided pending list, optionally one `outbox_level` of it (the
    /// query value, already rendered).
    OutboxPendingAll(Option<&'a str>),
    BatcherQueue(&'a str),
}

impl<'a> RollupPath<'a> {
    /// The path below the node's base, one entry per segment.
    pub(crate) fn segments(&self) -> Vec<String> {
        match *self {
            Self::DurableValue(block, _) => durable_path(block, "value"),
            Self::DurableLength(block, _) => durable_path(block, "length"),
            Self::DurableSubkeys(block, _) => durable_path(block, "subkeys"),
            Self::Level(block) => global_block_path(block, &["level"]),
            Self::TezosLevel => owned(&["global", "tezos_level"]),
            Self::SmartRollupAddress => owned(&["global", "smart_rollup_address"]),
            Self::OutboxPending(list) => owned(&["local", "outbox", "pending", &list.to_string()]),
            Self::OutboxPendingAll(_) => owned(&["local", "outbox", "pending"]),
            Self::BatcherQueue(id) => owned(&["local", "batcher", "queue", id]),
        }
    }

    /// The query string: the durable reads' `key`, the undivided pending
    /// list's `outbox_level`, nothing for the others.
    pub(crate) fn query(&self) -> Vec<(&'static str, &'a str)> {
        match *self {
            Self::DurableValue(_, key)
            | Self::DurableLength(_, key)
            | Self::DurableSubkeys(_, key) => {
                vec![("key", key)]
            }
            Self::OutboxPendingAll(Some(level)) => vec![("outbox_level", level)],
            Self::OutboxPendingAll(None) => Vec::new(),
            Self::Level(_)
            | Self::TezosLevel
            | Self::SmartRollupAddress
            | Self::OutboxPending(_)
            | Self::BatcherQueue(_) => Vec::new(),
        }
    }
}

impl<P> Client<P> {
    pub fn base(&self) -> &NodeUrl {
        self.transport.base()
    }

    /// `/global/block/{block}/durable/wasm_2_0_0/value?key={key}`: the bytes
    /// stored at `key`.
    ///
    /// Measured: a present key is HTTP 200 with a JSON string of hex, an
    /// ABSENT key is HTTP 200 with the body `null` (returned as `None`), never
    /// a 404. A 404 is therefore some other failure (a wrong base path, a
    /// proxy) and stays an error.
    pub async fn durable_value(
        &self,
        block: &BlockId,
        key: &str,
    ) -> Result<Option<Vec<u8>>, Error> {
        let path = RollupPath::DurableValue(block, key);
        let hex_value: Option<String> = self.get_json(path).await?;

        hex_value
            .map(|hex_value| {
                hex::decode(hex_value.trim()).map_err(|e| Error::Decode {
                    url: self.url(path).to_string(),
                    reason: format!("durable value is not hex: {e}"),
                })
            })
            .transpose()
    }

    /// The durable-value RPC for `key`, unclassified: the `200 null` of an
    /// absent key, a 5xx and every other status come back as the
    /// [`RawResponse`], for callers that classify the answer themselves.
    pub async fn durable_value_raw(
        &self,
        block: &BlockId,
        key: &str,
    ) -> Result<RawResponse, Error> {
        self.get_raw(RollupPath::DurableValue(block, key)).await
    }

    /// `/global/block/{block}/durable/wasm_2_0_0/length?key={key}`: the length
    /// of the value at `key`, `None` when absent (`null`, as for the value).
    pub async fn durable_length(&self, block: &BlockId, key: &str) -> Result<Option<u64>, Error> {
        let path = RollupPath::DurableLength(block, key);
        let length: Value = self.get_json(path).await?;
        let bad = |reason: String| Error::Decode {
            url: self.url(path).to_string(),
            reason,
        };

        // A JSON string of digits, occasionally a number.
        match length {
            Value::Null => Ok(None),
            Value::String(digits) => digits
                .trim()
                .parse()
                .map(Some)
                .map_err(|e| bad(format!("length {digits:?}: {e}"))),
            Value::Number(n) => n
                .as_u64()
                .map(Some)
                .ok_or_else(|| bad(format!("length {n} is not a u64"))),
            other => Err(bad(format!("unexpected length body {other}"))),
        }
    }

    /// `/global/block/{block}/durable/wasm_2_0_0/subkeys?key={key}`: the
    /// direct children of `key`.
    pub async fn durable_subkeys(&self, block: &BlockId, key: &str) -> Result<Vec<String>, Error> {
        self.get_json(RollupPath::DurableSubkeys(block, key)).await
    }

    /// `/global/block/{block}/level`: the L1 level of that rollup block.
    pub async fn level(&self, block: &BlockId) -> Result<u32, Error> {
        self.get_json(RollupPath::Level(block)).await
    }

    /// `/global/tezos_level`: the latest L1 level the node has processed.
    pub async fn tezos_level(&self) -> Result<u32, Error> {
        self.get_json(RollupPath::TezosLevel).await
    }

    /// `/global/smart_rollup_address`: the `sr1…` this node runs.
    pub async fn smart_rollup_address(&self) -> Result<String, Error> {
        self.get_json(RollupPath::SmartRollupAddress).await
    }

    /// [`Self::smart_rollup_address`] unclassified, for an operator probe
    /// that reports the node's own status and body. Only a transport failure
    /// is an `Err` ([`Error::Unavailable`]).
    pub async fn smart_rollup_address_raw(&self) -> Result<RawResponse, Error> {
        self.get_raw(RollupPath::SmartRollupAddress).await
    }

    /// `/local/outbox/pending/{list}`: the outbox messages emitted and not
    /// yet executed on L1, in that list.
    pub async fn outbox_pending<T: DeserializeOwned>(
        &self,
        list: PendingOutbox,
    ) -> Result<T, Error> {
        self.get_json(RollupPath::OutboxPending(list)).await
    }

    /// [`Self::outbox_pending`] unclassified, for an operator probe that
    /// reports the node's own status and body.
    /// Only a transport failure is an `Err` ([`Error::Unavailable`]).
    pub async fn outbox_pending_raw(&self, list: PendingOutbox) -> Result<RawResponse, Error> {
        self.get_raw(RollupPath::OutboxPending(list)).await
    }

    /// `/local/outbox/pending[?outbox_level={level}]`: every outbox message
    /// the node has not seen executed, each level with its `status`
    /// ([`PendingStatus`]: `pending`, `executable` or `lost`), and only that
    /// level's when `outbox_level` is given. This is the one list that shows
    /// a `lost` message; the two sub-lists ([`Self::outbox_pending`]) leave
    /// them out. A level with no unexecuted message, or above the node's
    /// head, is an empty list.
    pub async fn outbox_pending_status(
        &self,
        outbox_level: Option<u32>,
    ) -> Result<Vec<PendingOutboxEntry>, Error> {
        let level = outbox_level.map(|level| level.to_string());

        self.get_json(RollupPath::OutboxPendingAll(level.as_deref()))
            .await
    }

    /// `/local/batcher/queue/{id}`: the batcher's record of one message it
    /// was given ([`batcher`]). A 404 is the node having no record of the id,
    /// returned as `None`.
    pub async fn batcher_queue<T: DeserializeOwned>(&self, id: &str) -> Result<Option<T>, Error> {
        self.transport
            .get_json_or_not_found(&RollupPath::BatcherQueue(id).segments())
            .await
    }

    fn url(&self, path: RollupPath<'_>) -> url::Url {
        self.transport.url(&path.segments(), &path.query())
    }

    /// `GET` of `path`, unclassified.
    async fn get_raw(&self, path: RollupPath<'_>) -> Result<RawResponse, Error> {
        self.transport
            .get_raw(&path.segments(), &path.query())
            .await
    }

    /// `GET` of `path`, classified and decoded.
    async fn get_json<T: DeserializeOwned>(&self, path: RollupPath<'_>) -> Result<T, Error> {
        self.transport
            .get_json(&path.segments(), &path.query())
            .await
    }
}

fn owned(segments: &[&str]) -> Vec<String> {
    segments.iter().map(|segment| segment.to_string()).collect()
}

/// `global/block/{block}/{rest…}`.
fn global_block_path(block: &BlockId, rest: &[&str]) -> Vec<String> {
    let block = block.to_string();
    let mut segments = owned(&["global", "block", &block]);

    segments.extend(owned(rest));

    segments
}

/// `global/block/{block}/durable/wasm_2_0_0/{endpoint}`.
fn durable_path(block: &BlockId, endpoint: &str) -> Vec<String> {
    global_block_path(block, &["durable", PVM, endpoint])
}
