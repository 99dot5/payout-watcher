//! Where the watcher reads from: an L1 node and a rollup node, each either
//! live over its RPC or replayed from a recorded snapshot file.
//!
//! Both are the RUNNER's nodes. Nothing here has a default address: the L1
//! RPC and the rollup node come from the config file or the flags, so the
//! watcher checks the operator only against nodes its runner trusts.

use octez_rpc::l1::{self, L1Anchor, ValidationPass};
use octez_rpc::{BuildError, NodeUrl, RequestSettings, rollup};
use serde::Deserialize;
use serde_json::Value;
use smart_rollup_storage_reader::LiveDurableStore;
use smart_rollup_storage_reader::store::{DurableStore, StoreError};
use std::collections::BTreeMap;
use std::future::Future;
use std::time::Duration;
use thiserror::Error;

/// A node that did not answer, or answered something unreadable. Retryable:
/// the pass stops, and the next resumes from the state file.
#[derive(Debug, Error)]
pub enum NodeError {
    #[error("L1 node: {0}")]
    L1(String),
    #[error("rollup node: {0}")]
    Rollup(String),
}

impl From<StoreError> for NodeError {
    fn from(e: StoreError) -> Self {
        Self::Rollup(e.to_string())
    }
}

/// The reads the watcher makes from L1.
pub trait L1Node {
    /// The highest final level: `head~2` (Tenderbake blocks are final two
    /// levels down).
    fn finalized_level(&self) -> impl Future<Output = Result<i64, NodeError>>;

    /// `/chains/main/blocks/{level}/operations/3`: the block's manager
    /// operation groups, a flat list.
    fn manager_operations(&self, level: i64) -> impl Future<Output = Result<Value, NodeError>>;

    /// `/chains/main/blocks/{level}/context/contracts/{contract}/script`: the
    /// code and the storage as of the END of `level`.
    fn contract_script(
        &self,
        contract: &str,
        level: i64,
    ) -> impl Future<Output = Result<Value, NodeError>>;
}

/// The reads the watcher makes from its rollup node: durable values at the
/// node's finalised block, which L1 level that block is, and one durable
/// value at an earlier level.
pub trait RollupNode: DurableStore {
    fn finalized_level(&self) -> impl Future<Output = Result<i64, NodeError>>;

    /// The durable value at `key` as it was at the end of L1 `level`: how a
    /// sweep's request-time equity is read back. Needs a node that keeps its
    /// history for that level (the default `archive` mode does; `full` keeps
    /// only what is not yet cemented); a level the node has pruned is an
    /// error, which stops the pass like any other failed read.
    fn value_at_level(
        &self,
        level: i64,
        key: &str,
    ) -> impl Future<Output = Result<Option<Vec<u8>>, NodeError>>;
}

const READ_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// The highest final L1 block: Tenderbake blocks are final two levels down.
const L1_FINALIZED: l1::BlockId = l1::BlockId::back(L1Anchor::Head, 2);

/// The rollup node's block every durable read and the level are taken at.
const ROLLUP_FINALIZED: rollup::BlockId = rollup::BlockId::Finalized;

const REQUEST_SETTINGS: RequestSettings = RequestSettings {
    connect_timeout: CONNECT_TIMEOUT,
    request_timeout: READ_TIMEOUT,
};

/// An L1 level as the node's block identifier takes it.
fn l1_level(level: i64) -> Result<l1::BlockId, NodeError> {
    u32::try_from(level)
        .map(l1::BlockId::level)
        .map_err(|_| NodeError::L1(format!("{level} is not an L1 level")))
}

fn l1_error(e: octez_rpc::Error) -> NodeError {
    NodeError::L1(e.to_string())
}

/// A live L1 node over octez-rpc.
#[derive(Debug, Clone)]
pub struct LiveL1Node {
    client: l1::Client,
}

impl LiveL1Node {
    /// A client of the L1 node at `url` (validated when the config loaded).
    pub fn new(url: NodeUrl) -> Result<Self, BuildError> {
        Ok(Self {
            client: l1::Client::new(url, REQUEST_SETTINGS)?,
        })
    }
}

impl L1Node for LiveL1Node {
    async fn finalized_level(&self) -> Result<i64, NodeError> {
        let header: Value = self.client.header(&L1_FINALIZED).await.map_err(l1_error)?;

        header
            .get("level")
            .and_then(Value::as_i64)
            .ok_or_else(|| NodeError::L1(format!("a block header without a level: {header}")))
    }

    async fn manager_operations(&self, level: i64) -> Result<Value, NodeError> {
        self.client
            .manager_operations(&l1_level(level)?)
            .await
            .map_err(l1_error)
    }

    async fn contract_script(&self, contract: &str, level: i64) -> Result<Value, NodeError> {
        self.client
            .script(&l1_level(level)?, contract)
            .await
            .map_err(l1_error)
    }
}

/// A live rollup node over octez-rpc, read at its `finalized` block.
#[derive(Debug, Clone)]
pub struct LiveRollupNode {
    client: rollup::Client,
    store: LiveDurableStore,
}

impl LiveRollupNode {
    /// A client of the rollup node at `url` (validated when the config
    /// loaded), shared by the durable reads and the level.
    pub fn new(url: NodeUrl) -> Result<Self, BuildError> {
        let client = rollup::Client::new(url, REQUEST_SETTINGS)?;
        let store = LiveDurableStore::with_rpc(client.clone(), ROLLUP_FINALIZED);

        Ok(Self { client, store })
    }
}

impl DurableStore for LiveRollupNode {
    async fn subkeys(&self, key: &str) -> Result<Vec<String>, StoreError> {
        self.store.subkeys(key).await
    }

    async fn value(&self, key: &str) -> Result<Option<Vec<u8>>, StoreError> {
        self.store.value(key).await
    }

    async fn length(&self, key: &str) -> Result<Option<u64>, StoreError> {
        self.store.length(key).await
    }
}

impl RollupNode for LiveRollupNode {
    async fn finalized_level(&self) -> Result<i64, NodeError> {
        self.client
            .level(&ROLLUP_FINALIZED)
            .await
            .map(i64::from)
            .map_err(|e| NodeError::Rollup(e.to_string()))
    }

    async fn value_at_level(&self, level: i64, key: &str) -> Result<Option<Vec<u8>>, NodeError> {
        let level = u32::try_from(level)
            .map_err(|_| NodeError::Rollup(format!("{level} is not an L1 level")))?;
        let store = LiveDurableStore::with_rpc(self.client.clone(), rollup::BlockId::Level(level));

        Ok(store.value(key).await?)
    }
}

/// A recorded snapshot of both nodes, replayed offline: what the README calls
/// a fixture. Anyone can record one from their own nodes and replay a
/// verdict; the test suite replays synthetic ones for every alarm.
#[derive(Debug, Clone, Deserialize)]
pub struct Snapshot {
    pub l1: L1NodeSnapshot,
    pub rollup: RollupNodeSnapshot,
}

/// An L1 node replayed from recorded answers.
#[derive(Debug, Clone, Deserialize)]
pub struct L1NodeSnapshot {
    pub finalized_level: i64,
    /// Level → the `/operations` answer, all four validation passes as
    /// recorded; an absent level is an empty block.
    #[serde(default)]
    pub blocks: BTreeMap<i64, Value>,
    /// Each contract's script as of `from_level` and later, until the next
    /// entry for the same contract.
    #[serde(default)]
    pub scripts: Vec<ScriptSnapshot>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ScriptSnapshot {
    pub contract: String,
    pub from_level: i64,
    pub script: Value,
}

/// A rollup node replayed from recorded answers.
#[derive(Debug, Clone, Deserialize)]
pub struct RollupNodeSnapshot {
    pub finalized_level: i64,
    /// Durable key → value, hex, at the finalised block.
    #[serde(default)]
    pub durable: BTreeMap<String, String>,
    /// L1 level → (durable key → value, hex) as of the end of that level:
    /// what [`RollupNode::value_at_level`] answers. A level not recorded
    /// holds nothing.
    #[serde(default)]
    pub durable_at_level: BTreeMap<i64, BTreeMap<String, String>>,
}

impl Snapshot {
    pub fn load(path: &std::path::Path) -> std::io::Result<Self> {
        let bytes = std::fs::read(path)?;

        serde_json::from_slice(&bytes).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("{}: {e}", path.display()),
            )
        })
    }
}

impl L1Node for L1NodeSnapshot {
    async fn finalized_level(&self) -> Result<i64, NodeError> {
        Ok(self.finalized_level)
    }

    /// The recorded answer's manager pass, its fourth element; an absent
    /// level or a malformed entry is an empty list.
    async fn manager_operations(&self, level: i64) -> Result<Value, NodeError> {
        Ok(self
            .blocks
            .get(&level)
            .and_then(|passes| passes.get(ValidationPass::Manager.index() as usize))
            .filter(|groups| groups.is_array())
            .cloned()
            .unwrap_or_else(|| Value::Array(Vec::new())))
    }

    async fn contract_script(&self, contract: &str, level: i64) -> Result<Value, NodeError> {
        self.scripts
            .iter()
            .filter(|s| s.contract == contract && s.from_level <= level)
            .max_by_key(|s| s.from_level)
            .map(|s| s.script.clone())
            .ok_or_else(|| NodeError::L1(format!("no script for {contract} at level {level}")))
    }
}

impl DurableStore for RollupNodeSnapshot {
    async fn subkeys(&self, key: &str) -> Result<Vec<String>, StoreError> {
        let prefix = format!("{}/", key.trim_end_matches('/'));

        Ok(self
            .durable
            .keys()
            .filter_map(|k| k.strip_prefix(&prefix))
            .filter_map(|rest| rest.split('/').next())
            .map(str::to_string)
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect())
    }

    async fn value(&self, key: &str) -> Result<Option<Vec<u8>>, StoreError> {
        self.durable
            .get(key)
            .map(|text| {
                hex::decode(text)
                    .map_err(|e| StoreError::Decode(format!("snapshot value at {key}: {e}")))
            })
            .transpose()
    }

    async fn length(&self, key: &str) -> Result<Option<u64>, StoreError> {
        Ok(self.durable.get(key).map(|text| (text.len() / 2) as u64))
    }
}

impl RollupNode for RollupNodeSnapshot {
    async fn finalized_level(&self) -> Result<i64, NodeError> {
        Ok(self.finalized_level)
    }

    async fn value_at_level(&self, level: i64, key: &str) -> Result<Option<Vec<u8>>, NodeError> {
        self.durable_at_level
            .get(&level)
            .and_then(|durable| durable.get(key))
            .map(|text| {
                hex::decode(text).map_err(|e| {
                    NodeError::Rollup(format!("snapshot value at {key} at level {level}: {e}"))
                })
            })
            .transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    const VAULT: &str = "KT1BuEZtb68c1Q4yjtckcNjGELqWt56Xyesc";

    /// A node stand-in: answers `GET {target}` from `routes` (any other
    /// target is a 404 naming it), one request per connection, and records
    /// every target it was sent.
    async fn serve(routes: &[(&str, &str)]) -> (NodeUrl, Arc<Mutex<Vec<String>>>) {
        let routes: Arc<HashMap<String, String>> = Arc::new(
            routes
                .iter()
                .map(|(target, body)| (target.to_string(), body.to_string()))
                .collect(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let url = NodeUrl::parse(&format!("http://{}", listener.local_addr().expect("addr")))
            .expect("url");
        let seen = Arc::new(Mutex::new(Vec::new()));
        let recorded = seen.clone();

        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let mut head = Vec::new();
                let mut chunk = [0u8; 1024];

                while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                    match socket.read(&mut chunk).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => head.extend_from_slice(&chunk[..n]),
                    }
                }

                let head = String::from_utf8_lossy(&head).to_string();
                let target = head.split(' ').nth(1).unwrap_or_default().to_string();
                let (status, body) = match routes.get(&target) {
                    Some(body) => ("200 OK", body.clone()),
                    None => ("404 Not Found", format!("no route {target}")),
                };

                recorded.lock().expect("seen").push(target);

                let answer = format!(
                    "HTTP/1.1 {status}\r\ncontent-type: application/json\r\n\
                     content-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );

                let _ = socket.write_all(answer.as_bytes()).await;
            }
        });

        (url, seen)
    }

    #[test]
    fn the_rollup_reads_are_at_the_protocol_s_finalized_block() {
        assert_eq!(
            ROLLUP_FINALIZED.to_string(),
            payout_protocol::kernel_records::FINALIZED_BLOCK
        );
    }

    #[tokio::test]
    async fn the_live_l1_reads_the_octez_paths() {
        let script = format!("/chains/main/blocks/41/context/contracts/{VAULT}/script");
        let (url, seen) = serve(&[
            ("/chains/main/blocks/head~2/header", r#"{"level": 42}"#),
            (
                "/chains/main/blocks/42/operations/3",
                r#"[{"hash": "oo1", "contents": []}]"#,
            ),
            (&script, r#"{"code": [], "storage": {"int": "0"}}"#),
        ])
        .await;
        let l1 = LiveL1Node::new(url).expect("client");

        assert_eq!(l1.finalized_level().await.expect("level"), 42);
        assert_eq!(
            l1.manager_operations(42).await.expect("operations"),
            serde_json::json!([{"hash": "oo1", "contents": []}])
        );
        assert_eq!(
            l1.contract_script(VAULT, 41).await.expect("script")["storage"]["int"],
            "0"
        );
        assert_eq!(
            *seen.lock().expect("seen"),
            [
                "/chains/main/blocks/head~2/header".to_string(),
                "/chains/main/blocks/42/operations/3".to_string(),
                script,
            ]
        );
    }

    #[tokio::test]
    async fn the_live_l1_refuses_a_header_without_a_level_and_a_negative_level() {
        let (url, seen) = serve(&[("/chains/main/blocks/head~2/header", "{}")]).await;
        let l1 = LiveL1Node::new(url).expect("client");

        assert!(matches!(l1.finalized_level().await, Err(NodeError::L1(_))));
        assert!(matches!(
            l1.manager_operations(-1).await,
            Err(NodeError::L1(_))
        ));
        assert_eq!(
            seen.lock().expect("seen").len(),
            1,
            "a negative level is never sent"
        );
    }

    #[tokio::test]
    async fn the_live_rollup_reads_at_its_finalized_block() {
        let (url, seen) = serve(&[
            ("/global/block/finalized/level", "77"),
            (
                "/global/block/finalized/durable/wasm_2_0_0/value?key=%2Fkernel%2Finfo",
                r#""00ff""#,
            ),
            (
                "/global/block/finalized/durable/wasm_2_0_0/value?key=%2Fabsent",
                "null",
            ),
            (
                "/global/block/70/durable/wasm_2_0_0/value?key=%2Fkernel%2Finfo",
                r#""00ee""#,
            ),
        ])
        .await;
        let rollup = LiveRollupNode::new(url).expect("client");

        assert_eq!(rollup.finalized_level().await.expect("level"), 77);
        assert_eq!(
            rollup.value("/kernel/info").await.expect("value"),
            Some(vec![0x00, 0xff])
        );
        assert_eq!(rollup.value("/absent").await.expect("absent"), None);
        // A read at a level goes to that level's block, not `finalized`.
        assert_eq!(
            rollup
                .value_at_level(70, "/kernel/info")
                .await
                .expect("value at level"),
            Some(vec![0x00, 0xee])
        );
        assert!(matches!(
            rollup.value_at_level(-1, "/kernel/info").await,
            Err(NodeError::Rollup(_))
        ));
        assert_eq!(seen.lock().expect("seen").len(), 4);
    }

    #[tokio::test]
    async fn a_snapshot_answers_a_level_read_from_its_own_map() {
        let snapshot: RollupNodeSnapshot = serde_json::from_value(serde_json::json!({
            "finalized_level": 10,
            "durable": { "/k": "ff" },
            "durable_at_level": { "7": { "/k": "aa" } }
        }))
        .unwrap();

        assert_eq!(snapshot.value("/k").await.unwrap(), Some(vec![0xff]));
        assert_eq!(
            snapshot.value_at_level(7, "/k").await.unwrap(),
            Some(vec![0xaa])
        );
        assert_eq!(snapshot.value_at_level(8, "/k").await.unwrap(), None);
        assert_eq!(snapshot.value_at_level(7, "/other").await.unwrap(), None);
    }

    #[tokio::test]
    async fn a_rollup_node_error_is_a_rollup_error() {
        let (url, _seen) = serve(&[]).await;
        let rollup = LiveRollupNode::new(url).expect("client");

        assert!(matches!(
            rollup.finalized_level().await,
            Err(NodeError::Rollup(_))
        ));
    }

    #[tokio::test]
    async fn a_snapshot_script_is_the_latest_at_or_below_the_level() {
        let snapshot: L1NodeSnapshot = serde_json::from_value(serde_json::json!({
            "finalized_level": 10,
            "blocks": {
                "4": [[], [], [], [{"hash": "oo4"}]],
                "5": [[], [], []],
                "6": [[], [], [], {"hash": "oo6"}]
            },
            "scripts": [
                {"contract": "KT1a", "from_level": 0, "script": {"v": 0}},
                {"contract": "KT1a", "from_level": 5, "script": {"v": 5}},
                {"contract": "KT1b", "from_level": 0, "script": {"v": 9}}
            ]
        }))
        .unwrap();

        assert_eq!(snapshot.contract_script("KT1a", 4).await.unwrap()["v"], 0);
        assert_eq!(snapshot.contract_script("KT1a", 5).await.unwrap()["v"], 5);
        assert_eq!(snapshot.contract_script("KT1b", 7).await.unwrap()["v"], 9);
        assert!(snapshot.contract_script("KT1c", 7).await.is_err());
        assert_eq!(
            snapshot.manager_operations(4).await.unwrap(),
            serde_json::json!([{"hash": "oo4"}])
        );

        // An absent level, a recording without a fourth pass and a fourth
        // pass that is not a list all read as an empty manager pass.
        for level in [3, 5, 6] {
            assert_eq!(
                snapshot.manager_operations(level).await.unwrap(),
                serde_json::json!([])
            );
        }
    }
}
