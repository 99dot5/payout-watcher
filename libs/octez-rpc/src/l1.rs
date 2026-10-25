//! The L1 node's RPC (`octez-node`), under `/chains/main`, `/injection` and
//! `/monitor`.

mod block_id;
mod validation_pass;

pub use block_id::{BlockId, L1Anchor, Step};
pub use validation_pass::ValidationPass;

use crate::NodeUrl;
use crate::error::{Error, RawResponse, decode, failure};
use crate::profile::{BuildError, Profile, Request, Stream, Transport};
use futures_util::stream::{BoxStream, StreamExt};
use serde::de::DeserializeOwned;
use serde_json::Value;
use tokio_util::codec::{FramedRead, LinesCodec, LinesCodecError};
use tokio_util::io::StreamReader;

/// A client of one L1 node, in connection profile `P`. `P` defaults to
/// [`Request`], so a one-shot client is written `Client`; a streaming client
/// spells out `Client<Stream>`.
///
/// Every endpoint is on every profile except [`Client::monitor_heads`], which
/// only a [`Stream`] client has: a [`Request`] client's whole-request timeout
/// would cut the stream. The converse holds too: a [`Stream`] client has no
/// request timeout, so one-shot reads made through it can hang on a silent
/// node; make them through a [`Request`] client.
///
/// ```compile_fail
/// # async fn heads(client: octez_rpc::l1::Client) {
/// let _ = client.monitor_heads::<serde_json::Value>().await;
/// # }
/// ```
///
/// ```no_run
/// # async fn heads(client: octez_rpc::l1::Client<octez_rpc::Stream>) {
/// let _ = client.monitor_heads::<serde_json::Value>().await;
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct Client<P = Request> {
    transport: Transport<P>,
}

impl<P: Profile> Client<P> {
    /// A client of the L1 node at `base`.
    pub fn new(base: NodeUrl, settings: P::Settings) -> Result<Self, BuildError> {
        Ok(Self {
            transport: Transport::new(base, &settings)?,
        })
    }
}

/// Every one-shot `GET` path this crate reads from the L1 node, so each one is
/// spelled exactly once: a typed read and its `*_raw` twin build their URL
/// from the same entry. The `POST` endpoints and the heads stream are not
/// here.
#[derive(Debug, Clone, Copy)]
pub(crate) enum L1Path<'a> {
    ChainId,
    Header(&'a BlockId),
    Hash(&'a BlockId),
    Constants(&'a BlockId),
    Counter(&'a BlockId, &'a str),
    ManagerKey(&'a BlockId, &'a str),
    Balance(&'a BlockId, &'a str),
    Storage(&'a BlockId, &'a str),
    Script(&'a BlockId, &'a str),
    Entrypoints(&'a BlockId, &'a str),
    BigMapValue {
        block: &'a BlockId,
        id: u64,
        key_hash: &'a str,
    },
    OperationHashes(&'a BlockId, ValidationPass),
    Operation {
        block: &'a BlockId,
        pass: ValidationPass,
        index: u32,
    },
    Operations(&'a BlockId),
    PassOperations(&'a BlockId, ValidationPass),
    GenesisInfo(&'a BlockId, &'a str),
}

impl L1Path<'_> {
    /// The path below the node's base, one entry per segment.
    pub(crate) fn segments(&self) -> Vec<String> {
        match *self {
            Self::ChainId => chain_path(&["chain_id"]),
            Self::Header(block) => block_path(block, &["header"]),
            Self::Hash(block) => block_path(block, &["hash"]),
            Self::Constants(block) => block_path(block, &["context", "constants"]),
            Self::Counter(block, address) => contract_path(block, address, "counter"),
            Self::ManagerKey(block, address) => contract_path(block, address, "manager_key"),
            Self::Balance(block, address) => contract_path(block, address, "balance"),
            Self::Storage(block, contract) => contract_path(block, contract, "storage"),
            Self::Script(block, contract) => contract_path(block, contract, "script"),
            Self::Entrypoints(block, contract) => contract_path(block, contract, "entrypoints"),
            Self::BigMapValue {
                block,
                id,
                key_hash,
            } => block_path(block, &["context", "big_maps", &id.to_string(), key_hash]),
            Self::OperationHashes(block, pass) => {
                block_path(block, &["operation_hashes", &pass.to_string()])
            }
            Self::Operation { block, pass, index } => block_path(
                block,
                &["operations", &pass.to_string(), &index.to_string()],
            ),
            Self::Operations(block) => block_path(block, &["operations"]),
            Self::PassOperations(block, pass) => {
                block_path(block, &["operations", &pass.to_string()])
            }
            Self::GenesisInfo(block, rollup) => block_path(
                block,
                &[
                    "context",
                    "smart_rollups",
                    "smart_rollup",
                    rollup,
                    "genesis_info",
                ],
            ),
        }
    }
}

impl<P> Client<P> {
    pub fn base(&self) -> &NodeUrl {
        self.transport.base()
    }

    /// `/chains/main/chain_id`: the chain's `Net…` id.
    pub async fn chain_id(&self) -> Result<String, Error> {
        self.get_json(L1Path::ChainId).await
    }

    /// [`Self::chain_id`] unclassified: the node's own status and body, for an
    /// operator probe that reports them. Only a transport failure is an
    /// `Err` ([`Error::Unavailable`]).
    pub async fn chain_id_raw(&self) -> Result<RawResponse, Error> {
        self.get_raw(L1Path::ChainId).await
    }

    /// `/chains/main/blocks/{block}/header`.
    pub async fn header<T: DeserializeOwned>(&self, block: &BlockId) -> Result<T, Error> {
        self.get_json(L1Path::Header(block)).await
    }

    /// [`Self::header`] unclassified, for an operator probe that reports the
    /// node's own status and body.
    /// Only a transport failure is an `Err` ([`Error::Unavailable`]).
    pub async fn header_raw(&self, block: &BlockId) -> Result<RawResponse, Error> {
        self.get_raw(L1Path::Header(block)).await
    }

    /// `/chains/main/blocks/{block}/hash`.
    pub async fn hash(&self, block: &BlockId) -> Result<String, Error> {
        self.get_json(L1Path::Hash(block)).await
    }

    /// `/chains/main/blocks/{block}/context/constants`.
    pub async fn constants<T: DeserializeOwned>(&self, block: &BlockId) -> Result<T, Error> {
        self.get_json(L1Path::Constants(block)).await
    }

    /// `/chains/main/blocks/{block}/context/contracts/{address}/counter`.
    pub async fn counter(&self, block: &BlockId, address: &str) -> Result<u64, Error> {
        self.get_u64(L1Path::Counter(block, address)).await
    }

    /// `/chains/main/blocks/{block}/context/contracts/{address}/manager_key`:
    /// the revealed public key, `None` while unrevealed (`null`).
    pub async fn manager_key(
        &self,
        block: &BlockId,
        address: &str,
    ) -> Result<Option<String>, Error> {
        self.get_json(L1Path::ManagerKey(block, address)).await
    }

    /// `/chains/main/blocks/{block}/context/contracts/{address}/balance`: the
    /// spendable balance in mutez.
    pub async fn balance(&self, block: &BlockId, address: &str) -> Result<u64, Error> {
        self.get_u64(L1Path::Balance(block, address)).await
    }

    /// [`Self::balance`] unclassified, for an operator probe that reports the
    /// node's own status and body.
    /// Only a transport failure is an `Err` ([`Error::Unavailable`]).
    pub async fn balance_raw(&self, block: &BlockId, address: &str) -> Result<RawResponse, Error> {
        self.get_raw(L1Path::Balance(block, address)).await
    }

    /// `/chains/main/blocks/{block}/context/contracts/{contract}/storage`.
    pub async fn storage<T: DeserializeOwned>(
        &self,
        block: &BlockId,
        contract: &str,
    ) -> Result<T, Error> {
        self.get_json(L1Path::Storage(block, contract)).await
    }

    /// [`Self::storage`] unclassified, for an operator probe that reports the
    /// node's own status and body.
    /// Only a transport failure is an `Err` ([`Error::Unavailable`]).
    pub async fn storage_raw(&self, block: &BlockId, contract: &str) -> Result<RawResponse, Error> {
        self.get_raw(L1Path::Storage(block, contract)).await
    }

    /// `/chains/main/blocks/{block}/context/contracts/{contract}/script`.
    pub async fn script<T: DeserializeOwned>(
        &self,
        block: &BlockId,
        contract: &str,
    ) -> Result<T, Error> {
        self.get_json(L1Path::Script(block, contract)).await
    }

    /// [`Self::script`] unclassified (the 404 of an address with no contract
    /// at it is an answer), for an operator probe that reports the node's
    /// own status and body.
    /// Only a transport failure is an `Err` ([`Error::Unavailable`]).
    pub async fn script_raw(&self, block: &BlockId, contract: &str) -> Result<RawResponse, Error> {
        self.get_raw(L1Path::Script(block, contract)).await
    }

    /// `/chains/main/blocks/{block}/context/contracts/{contract}/entrypoints`.
    /// An address with no contract at it is a 404, an [`Error::Status`].
    pub async fn entrypoints<T: DeserializeOwned>(
        &self,
        block: &BlockId,
        contract: &str,
    ) -> Result<T, Error> {
        self.get_json(L1Path::Entrypoints(block, contract)).await
    }

    /// [`Self::entrypoints`] unclassified (the 404 of an address with no
    /// contract is an answer), for an operator probe that reports the node's
    /// own status and body.
    /// Only a transport failure is an `Err` ([`Error::Unavailable`]).
    pub async fn entrypoints_raw(
        &self,
        block: &BlockId,
        contract: &str,
    ) -> Result<RawResponse, Error> {
        self.get_raw(L1Path::Entrypoints(block, contract)).await
    }

    /// `/chains/main/blocks/{block}/context/big_maps/{id}/{key_hash}`: one
    /// value, keyed by the `expr…` hash of its packed key. A key the map does
    /// not hold is a 404, returned as `None`.
    pub async fn big_map_value<T: DeserializeOwned>(
        &self,
        block: &BlockId,
        id: u64,
        key_hash: &str,
    ) -> Result<Option<T>, Error> {
        let path = L1Path::BigMapValue {
            block,
            id,
            key_hash,
        };

        self.transport.get_json_or_not_found(&path.segments()).await
    }

    /// [`Self::big_map_value`] unclassified: every 404 comes back as an
    /// answer with its body, for an operator probe that judges which 404
    /// means absent.
    /// Only a transport failure is an `Err` ([`Error::Unavailable`]).
    pub async fn big_map_value_raw(
        &self,
        block: &BlockId,
        id: u64,
        key_hash: &str,
    ) -> Result<RawResponse, Error> {
        self.get_raw(L1Path::BigMapValue {
            block,
            id,
            key_hash,
        })
        .await
    }

    /// `/chains/main/blocks/{block}/operation_hashes/{pass}`.
    pub async fn operation_hashes(
        &self,
        block: &BlockId,
        pass: ValidationPass,
    ) -> Result<Vec<String>, Error> {
        self.get_json(L1Path::OperationHashes(block, pass)).await
    }

    /// `/chains/main/blocks/{block}/operations/{pass}/{index}`.
    pub async fn operation<T: DeserializeOwned>(
        &self,
        block: &BlockId,
        pass: ValidationPass,
        index: u32,
    ) -> Result<T, Error> {
        self.get_json(L1Path::Operation { block, pass, index })
            .await
    }

    /// `/chains/main/blocks/{block}/operations`: every validation pass at
    /// once. The answer is an array of four arrays, one per validation pass
    /// (consensus, voting, anonymous, manager), each that pass's operations
    /// in block order, as [`Client::operation`] indexes them.
    pub async fn operations<T: DeserializeOwned>(&self, block: &BlockId) -> Result<T, Error> {
        self.get_json(L1Path::Operations(block)).await
    }

    /// `/chains/main/blocks/{block}/operations/3`: the manager pass alone
    /// ([`ValidationPass::Manager`]), a flat array of its operations in block
    /// order.
    pub async fn manager_operations<T: DeserializeOwned>(
        &self,
        block: &BlockId,
    ) -> Result<T, Error> {
        self.get_json(L1Path::PassOperations(block, ValidationPass::Manager))
            .await
    }

    /// `/chains/main/blocks/{block}/operations/{pass}` as the node's text,
    /// undecoded, for a substring check before any parse (octez renders an
    /// address as its verbatim base58 string).
    pub async fn operations_text(
        &self,
        block: &BlockId,
        pass: ValidationPass,
    ) -> Result<String, Error> {
        self.transport
            .get_text(&L1Path::PassOperations(block, pass).segments(), &[])
            .await
    }

    /// `/chains/main/blocks/{block}/context/smart_rollups/smart_rollup/{rollup}/genesis_info`.
    /// An `sr1…` the node has no rollup at is [`Error::RollupNotFound`].
    pub async fn genesis_info<T: DeserializeOwned>(
        &self,
        block: &BlockId,
        rollup: &str,
    ) -> Result<T, Error> {
        self.get_json(L1Path::GenesisInfo(block, rollup)).await
    }

    /// [`Self::genesis_info`] unclassified (an unknown `sr1…` is the node's
    /// 500 and its body), for an operator probe that reports the node's own
    /// status and body.
    /// Only a transport failure is an `Err` ([`Error::Unavailable`]).
    pub async fn genesis_info_raw(
        &self,
        block: &BlockId,
        rollup: &str,
    ) -> Result<RawResponse, Error> {
        self.get_raw(L1Path::GenesisInfo(block, rollup)).await
    }

    /// `POST /chains/main/blocks/{block}/helpers/scripts/run_operation`:
    /// simulate `{"operation": …, "chain_id": …}`.
    pub async fn run_operation<T: DeserializeOwned>(
        &self,
        block: &BlockId,
        request: &Value,
    ) -> Result<T, Error> {
        self.transport
            .post_json(
                &block_path(block, &["helpers", "scripts", "run_operation"]),
                &[],
                request,
            )
            .await
    }

    /// `POST /chains/main/blocks/{block}/helpers/forge/operations`: the node's
    /// forge of `operation` (`{"branch": …, "contents": […]}`), as bytes.
    pub async fn forge_operations(
        &self,
        block: &BlockId,
        operation: &Value,
    ) -> Result<Vec<u8>, Error> {
        let segments = block_path(block, &["helpers", "forge", "operations"]);
        let forged: String = self.transport.post_json(&segments, &[], operation).await?;

        hex::decode(&forged).map_err(|e| Error::Decode {
            url: self.transport.url(&segments, &[]).to_string(),
            reason: format!("forged bytes {forged:?}: {e}"),
        })
    }

    /// `POST /injection/operation?chain=main` of a signed operation; the
    /// answer is its `o…` hash.
    pub async fn inject_operation(&self, signed: &[u8]) -> Result<String, Error> {
        self.transport
            .post_json(
                &["injection", "operation"],
                &[("chain", "main")],
                &hex::encode(signed),
            )
            .await
    }

    /// `GET` of `path`, unclassified.
    async fn get_raw(&self, path: L1Path<'_>) -> Result<RawResponse, Error> {
        self.transport.get_raw(&path.segments(), &[]).await
    }

    /// `GET` of `path`, classified and decoded.
    async fn get_json<T: DeserializeOwned>(&self, path: L1Path<'_>) -> Result<T, Error> {
        self.transport.get_json(&path.segments(), &[]).await
    }

    /// A count the node renders as a JSON string of digits.
    async fn get_u64(&self, path: L1Path<'_>) -> Result<u64, Error> {
        let segments = path.segments();
        let digits: String = self.transport.get_json(&segments, &[]).await?;

        digits.parse().map_err(|e| Error::Decode {
            url: self.transport.url(&segments, &[]).to_string(),
            reason: format!("{digits:?} is not a count: {e}"),
        })
    }
}

/// `chains/main/{rest…}`.
fn chain_path(rest: &[&str]) -> Vec<String> {
    ["chains", "main"]
        .iter()
        .chain(rest)
        .map(|segment| segment.to_string())
        .collect()
}

/// `chains/main/blocks/{block}/{rest…}`.
fn block_path(block: &BlockId, rest: &[&str]) -> Vec<String> {
    let block = block.to_string();
    let mut segments = chain_path(&["blocks", &block]);

    segments.extend(rest.iter().map(|segment| segment.to_string()));

    segments
}

/// `chains/main/blocks/{block}/context/contracts/{address}/{leaf}`.
fn contract_path(block: &BlockId, address: &str, leaf: &str) -> Vec<String> {
    block_path(block, &["context", "contracts", address, leaf])
}

/// A failure reading the heads stream: the transport's own error when the
/// connection broke, a decode error otherwise.
fn broken_stream(url: String, error: LinesCodecError) -> Error {
    let reason = error.to_string();

    if let LinesCodecError::Io(io) = error
        && let Some(inner) = io.into_inner()
        && let Ok(source) = inner.downcast::<reqwest::Error>()
    {
        return Error::Unavailable {
            url,
            source: *source,
        };
    }

    Error::Decode {
        url,
        reason: format!("the heads stream broke: {reason}"),
    }
}

impl Client<Stream> {
    /// `/monitor/heads/main`: one item per new head, decoded from each line
    /// of the never-ending answer (blank lines skipped). The stream ends when
    /// the node closes it; the caller bounds the wait for each item.
    pub async fn monitor_heads<T: DeserializeOwned + Send + 'static>(
        &self,
    ) -> Result<BoxStream<'static, Result<T, Error>>, Error> {
        let url = self.transport.url(&["monitor", "heads", "main"], &[]);
        let unavailable = |source| Error::Unavailable {
            url: url.to_string(),
            source,
        };
        let response = self
            .transport
            .http()
            .get(url.clone())
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(unavailable)?;
        let status = response.status();

        if !status.is_success() {
            let body = response.text().await.map_err(unavailable)?;

            return Err(failure(url.as_str(), status, body));
        }

        let bytes = response
            .bytes_stream()
            .map(|chunk| chunk.map_err(std::io::Error::other));
        let lines = FramedRead::new(StreamReader::new(bytes), LinesCodec::new());
        let url = url.to_string();

        Ok(lines
            .filter_map(move |line| {
                let url = url.clone();

                async move {
                    match line {
                        Ok(line) if line.trim().is_empty() => None,
                        Ok(line) => Some(decode(&url, &line)),
                        Err(e) => Some(Err(broken_stream(url, e))),
                    }
                }
            })
            .boxed())
    }
}
