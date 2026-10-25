//! Live [`DurableStore`] backed by the Octez rollup-node durable-storage RPC,
//! read through [`octez_rpc::rollup::Client`] (`GET
//! {node_url}/global/block/{block}/durable/wasm_2_0_0/{value|subkeys|length}?key=…`).
//!
//! ## Octez secure-ACL behavior
//!
//! On a non-loopback RPC bind the node's default "secure" ACL **blocks**
//! `subkeys`/`values` while still allowing `value`/`length`. So `value`/`length`
//! reads keep working against a remote node, but `subkeys` may come back `403`
//! (or a forbidden/ACL body) — surfaced as [`StoreError::AclBlocked`] with
//! actionable guidance rather than a raw HTTP error. Run on the rollup host
//! (loopback) or start the node with an allow-all ACL to browse subkeys
//! remotely.

use crate::store::{DurableStore, StoreError};
use octez_rpc::BlockHash;
use octez_rpc::rollup::{BlockId, Client};
use reqwest::StatusCode;
use serde_json::Value;
use thiserror::Error;

/// Live rollup-node durable-storage reader: one [`octez_rpc::rollup::Client`]
/// read at one block. The caller parses the node URL and the block at its own
/// boundary (see [`parse_block`]) and builds the client once.
#[derive(Debug, Clone)]
pub struct LiveDurableStore {
    client: Client,
    block: BlockId,
}

/// A block identifier [`parse_block`] does not accept.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error(
    "{raw:?} is not a rollup block: expected head, finalized, cemented, a level or a block hash"
)]
pub struct InvalidBlock {
    pub raw: String,
}

/// Parse the rollup node's block identifier: `head`, `finalized`, `cemented`,
/// a decimal level (digits only, no sign) or a block hash ([`BlockHash::parse`]).
pub fn parse_block(raw: &str) -> Result<BlockId, InvalidBlock> {
    let invalid = || InvalidBlock {
        raw: raw.to_string(),
    };

    match raw {
        "head" => return Ok(BlockId::Head),
        "finalized" => return Ok(BlockId::Finalized),
        "cemented" => return Ok(BlockId::Cemented),
        _ => {}
    }

    if !raw.is_empty() && raw.bytes().all(|b| b.is_ascii_digit()) {
        return raw.parse().map(BlockId::Level).map_err(|_| invalid());
    }

    BlockHash::parse(raw)
        .map(BlockId::Hash)
        .map_err(|_| invalid())
}

impl LiveDurableStore {
    /// Reader at `block` over an already-built rollup client (cheap to clone,
    /// shares its connection policy).
    pub fn with_rpc(client: Client, block: BlockId) -> Self {
        Self { client, block }
    }

    /// The rollup client this store reads through, for the node's other
    /// endpoints.
    pub fn rpc(&self) -> &Client {
        &self.client
    }
}

/// An [`octez_rpc::Error`] as the typed degraded mode the store reports.
fn store_error(err: octez_rpc::Error, block: &BlockId, endpoint: &str, key: &str) -> StoreError {
    match err {
        octez_rpc::Error::Unavailable { source, .. } => StoreError::Http(source),
        octez_rpc::Error::Status { code, body, .. } => {
            classify_error(code, &body, block, endpoint, key)
        }
        octez_rpc::Error::RollupNotFound { url, body } => StoreError::Decode(format!(
            "{endpoint} RPC for key {key}: no such smart rollup ({url}): {body}"
        )),
        octez_rpc::Error::Decode { url, reason } => {
            StoreError::Decode(format!("{endpoint} RPC for key {key} ({url}): {reason}"))
        }
    }
}

/// Decode a durable-value RPC body into optional raw bytes.
///
/// `null` ⇒ `None` (absent key); a JSON hex string ⇒ `Some(bytes)`; anything
/// else is a protocol error. The bytes are not interpreted: every record is a
/// borsh envelope the caller decodes.
pub fn parse_durable_value(body: &Value) -> Result<Option<Vec<u8>>, StoreError> {
    match body {
        Value::Null => Ok(None),
        Value::String(hex_str) => hex::decode(hex_str.trim())
            .map(Some)
            .map_err(|e| StoreError::Decode(format!("durable value is not valid hex: {e}"))),
        other => Err(StoreError::Decode(format!(
            "unexpected durable-value RPC body shape: {other}"
        ))),
    }
}

impl DurableStore for LiveDurableStore {
    async fn subkeys(&self, key: &str) -> Result<Vec<String>, StoreError> {
        // `subkeys` is the endpoint the secure ACL blocks; `classify_error`
        // tells the ACL from a pruned block before a generic error.
        self.client
            .durable_subkeys(&self.block, key)
            .await
            .map_err(|e| store_error(e, &self.block, "subkeys", key))
    }

    async fn value(&self, key: &str) -> Result<Option<Vec<u8>>, StoreError> {
        // Absence is always a `200 null`; no non-success status means "no
        // value here". Measured on an octez rollup node, 2026-10-05: a level
        // the node does not have yet or has pruned is `500`, and an
        // unparseable block id is `400` — so a `404` is some other failure (a
        // wrong URL, a proxy) and is an error like the rest.
        self.client
            .durable_value(&self.block, key)
            .await
            .map_err(|e| store_error(e, &self.block, "value", key))
    }

    async fn length(&self, key: &str) -> Result<Option<u64>, StoreError> {
        self.client
            .durable_length(&self.block, key)
            .await
            .map_err(|e| store_error(e, &self.block, "length", key))
    }
}

/// Classify a non-success RPC response into the typed degraded modes.
///
/// - `403`/`401`, or any body mentioning ACL/forbidden → [`StoreError::AclBlocked`]
///   (the secure ACL blocks `subkeys`/`values` on non-loopback binds).
/// - `404`/`500` whose body references the block/history, on a read of any
///   block but `head` → [`StoreError::BlockPruned`]. `head` is never past the
///   node's retention, so the same answer to a `head` read is a node fault,
///   and the variant's "try block=head" hint would point back at the read that
///   just failed.
/// - anything else → a generic [`StoreError::Decode`] carrying the status + body.
fn classify_error(
    status: StatusCode,
    body: &str,
    block: &BlockId,
    endpoint: &str,
    key: &str,
) -> StoreError {
    let body_lower = body.to_lowercase();

    if status == StatusCode::FORBIDDEN
        || status == StatusCode::UNAUTHORIZED
        || body_lower.contains("acl")
        || body_lower.contains("forbidden")
    {
        return StoreError::AclBlocked {
            endpoint: endpoint.to_string(),
        };
    }

    if *block != BlockId::Head
        && (status == StatusCode::NOT_FOUND || status == StatusCode::INTERNAL_SERVER_ERROR)
        && (body_lower.contains("block")
            || body_lower.contains("history")
            || body_lower.contains("pruned"))
    {
        return StoreError::BlockPruned {
            key: key.to_string(),
        };
    }

    StoreError::Decode(format!(
        "{endpoint} RPC for key {key} returned HTTP {status}: {body}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use octez_rpc::{NodeUrl, RequestSettings};
    use serde_json::json;

    /// A reader at `head` of the node at `url`.
    fn store_at(url: &str) -> LiveDurableStore {
        let client = Client::new(NodeUrl::parse(url).unwrap(), RequestSettings::default()).unwrap();

        LiveDurableStore::with_rpc(client, BlockId::Head)
    }

    /// Bodies measured on an octez rollup node, 2026-10-05.
    #[test]
    fn a_missing_or_pruned_block_is_an_error() {
        let future = r#"[{"kind":"temporary","id":"failure","msg":"Cannot retrieve hash of level 999999999"}]"#;
        let pruned = "Failure(\"Could not load block directory for block 1: Error:\n Attempting to access data for level 1, which is before the first available level 5131472\n\")";

        assert!(matches!(
            classify_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                future,
                &BlockId::Level(999_999_999),
                "value",
                "/k"
            ),
            StoreError::Decode(_)
        ));
        assert!(matches!(
            classify_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                pruned,
                &BlockId::Level(1),
                "value",
                "/k"
            ),
            StoreError::BlockPruned { .. }
        ));
    }

    /// `head` is never pruned: a 500 naming a block on a `head` read is a node
    /// fault, not a retention miss whose hint is "try block=head".
    #[test]
    fn a_head_read_is_never_pruned() {
        let names_a_block = "Failure(\"Could not load block directory for block 1\")";
        let classify = |block: &BlockId| {
            classify_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                names_a_block,
                block,
                "value",
                "/k",
            )
        };
        let on_head = classify(&BlockId::Head);

        assert!(matches!(on_head, StoreError::Decode(_)), "{on_head:?}");
        assert!(!on_head.to_string().contains("try block=head"), "{on_head}");
        assert!(matches!(
            classify(&BlockId::Level(1)),
            StoreError::BlockPruned { .. }
        ));
    }

    #[test]
    fn a_not_found_is_an_error_not_an_absent_key() {
        assert!(matches!(
            classify_error(StatusCode::NOT_FOUND, "", &BlockId::Head, "value", "/k"),
            StoreError::Decode(_)
        ));
        assert!(matches!(
            classify_error(StatusCode::FORBIDDEN, "", &BlockId::Head, "value", "/k"),
            StoreError::AclBlocked { .. }
        ));
    }

    #[test]
    fn with_rpc_reads_at_the_given_block() {
        let client = Client::new(
            NodeUrl::parse("http://node:8932/rpc").unwrap(),
            RequestSettings::default(),
        )
        .unwrap();
        let store = LiveDurableStore::with_rpc(client, BlockId::Cemented);

        assert_eq!(store.block, BlockId::Cemented);
        assert_eq!(store.rpc().base().as_str(), "http://node:8932/rpc");
    }

    #[test]
    fn parse_block_accepts_every_rollup_identifier() {
        let hash = "BLockGenesisGenesisGenesisGenesisGenesisb83baZgbyZe";

        for (raw, want) in [
            ("head", BlockId::Head),
            ("finalized", BlockId::Finalized),
            ("cemented", BlockId::Cemented),
            ("0", BlockId::Level(0)),
            ("4294967295", BlockId::Level(u32::MAX)),
            (hash, BlockId::Hash(BlockHash::parse(hash).unwrap())),
        ] {
            assert_eq!(parse_block(raw), Ok(want), "{raw}");
        }
    }

    #[test]
    fn parse_block_refuses_anything_else() {
        for raw in [
            "",
            "Head",
            "head~1",
            "+42",
            "-1",
            "4294967296",
            "genesis",
            "BLockGenesisGenesisGenesisGenesisGenesisb83baZgbyZf",
            "a/b",
        ] {
            assert_eq!(
                parse_block(raw),
                Err(InvalidBlock {
                    raw: raw.to_string()
                }),
                "{raw:?}"
            );
        }
    }

    /// A one-request HTTP server on a loopback port, answering with `response`.
    fn serve_once(response: &'static str) -> String {
        use std::io::{Read, Write};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());

        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0u8; 2048];
            let _ = stream.read(&mut request);

            stream.write_all(response.as_bytes()).unwrap();
        });

        url
    }

    #[tokio::test]
    async fn an_absent_key_is_a_200_null() {
        let url = serve_once(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 4\r\nconnection: close\r\n\r\nnull",
        );

        assert_eq!(store_at(&url).value("/k").await.unwrap(), None);
    }

    #[tokio::test]
    async fn a_present_key_is_its_hex_bytes() {
        let url = serve_once(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 8\r\nconnection: close\r\n\r\n\"616263\"",
        );

        assert_eq!(
            store_at(&url).value("/k").await.unwrap(),
            Some(b"abc".to_vec())
        );
    }

    #[tokio::test]
    async fn a_404_answer_is_an_error_not_an_absent_key() {
        let url =
            serve_once("HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n");
        let error = store_at(&url).value("/k").await.unwrap_err();

        assert!(matches!(error, StoreError::Decode(_)), "{error:?}");
        assert!(error.to_string().contains("404"), "{error}");
    }

    #[tokio::test]
    async fn an_unreachable_node_is_an_http_error() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        drop(listener);

        assert!(matches!(
            store_at(&url).value("/k").await,
            Err(StoreError::Http(_))
        ));
    }

    // Moved from `reconciler-core` (`parse_durable_value`).

    #[test]
    fn parse_durable_value_decodes_hex() {
        let body = Value::String("616263".to_string());

        assert_eq!(
            parse_durable_value(&body).unwrap(),
            Some(vec![0x61, 0x62, 0x63])
        );
    }

    #[test]
    fn parse_durable_value_null_is_absent() {
        assert_eq!(parse_durable_value(&Value::Null).unwrap(), None);
    }

    #[test]
    fn parse_durable_value_rejects_bad_hex() {
        assert!(parse_durable_value(&Value::String("zz".to_string())).is_err());
    }

    // Moved from `config-sync` (`parse_durable_bytes`, the same decode).

    /// The bytes form must NOT interpret its payload: every scope's record is
    /// borsh, so a UTF-8 decode here would reject perfectly good bytes.
    #[test]
    fn parse_durable_bytes_decodes_hex_verbatim() {
        // hex("active") = 616374697665 — returned as bytes, untrimmed.
        let body = Value::String("616374697665".to_string());

        assert_eq!(
            parse_durable_value(&body).unwrap(),
            Some(b"active".to_vec())
        );
    }

    #[test]
    fn parse_durable_bytes_null_is_absent() {
        assert_eq!(parse_durable_value(&Value::Null).unwrap(), None);
    }

    #[test]
    fn parse_durable_bytes_rejects_bad_hex() {
        let body = Value::String("zz".to_string());

        assert!(parse_durable_value(&body).is_err());
    }

    #[test]
    fn parse_durable_bytes_rejects_unexpected_shape() {
        assert!(
            parse_durable_value(&json!({
                "unexpected": true,
            }))
            .is_err()
        );
    }

    // Moved from `operator-cli` (`rollup_probe::parse_durable_bytes`).

    #[test]
    fn parse_durable_bytes_decodes_hex_and_null() {
        assert_eq!(
            parse_durable_value(&Value::String("0a0b0c".to_string())).unwrap(),
            Some(vec![0x0a, 0x0b, 0x0c])
        );
        assert_eq!(parse_durable_value(&Value::Null).unwrap(), None);
        assert!(parse_durable_value(&Value::String("zz".to_string())).is_err());
        assert!(parse_durable_value(&json!({"x": 1})).is_err());
    }
}
