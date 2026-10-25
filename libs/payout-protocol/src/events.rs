//! The vault's payout and sweep events, read out of one L1 block's
//! operations, each payout paired with the `fast_payout` call that carried
//! its signatures.
//!
//! Both payout paths emit a contract event naming the session, the amount
//! asked for, the amount paid now and the running total (the vault's paid
//! ledger, ADR 0027 §4.3); a sweep emits one naming the kernel record it
//! executes, the amount and the treasury it paid:
//!
//! | tag               | amount field | emitted by                                       |
//! | ----------------- | ------------ | ------------------------------------------------ |
//! | `fast_payout`     | `fast`       | `fast_payout(session_id, amount, signatures)`    |
//! | `cemented_payout` | `cemented`   | `execute_cemented_payout((session_id, amount))`  |
//! | `sweep`           | `amount`     | `execute_sweep((sweep_id, amount))`              |
//!
//! An event is an internal operation result of the manager operation that
//! triggered it: the submitter's `transaction` for a fast payout, the
//! `smart_rollup_execute_outbox_message` for a cemented payout or a sweep.
//! The event is what the vault DID; the `fast_payout` call's parameters, in
//! the same operation, are what it was SHOWN — the signatures the watcher
//! re-verifies. Only `applied` results count: a reverted call changed
//! nothing.

use crate::keys::{address_text, key_text, signature_text};
use crate::micheline::{MichelineError, as_bytes, as_map, as_u128, field, fields};
use serde_json::{Value, json};
use std::collections::BTreeSet;

/// Event tag of the fast payout.
pub const FAST_PAYOUT_TAG: &str = "fast_payout";
/// Event tag of the cemented payout.
pub const CEMENTED_PAYOUT_TAG: &str = "cemented_payout";
/// Event tag of the house sweep.
pub const SWEEP_TAG: &str = "sweep";
/// The vault entrypoint whose parameters carry the signatures.
pub const FAST_PAYOUT_ENTRYPOINT: &str = "fast_payout";

/// The `fast_payout` entrypoint's parameter type, as the compiled vault
/// declares it: `pair (mutez %amount) (pair (bytes %session_id) (map
/// %signatures key signature))`. A node returns an operation's parameter
/// value without its type, so the type is pinned here; read by annotation
/// like everything else.
pub fn fast_payout_parameter_type() -> Value {
    json!({"prim":"pair","args":[
        {"prim":"mutez","annots":["%amount"]},
        {"prim":"pair","args":[
            {"prim":"bytes","annots":["%session_id"]},
            {"prim":"map","args":[{"prim":"key"},{"prim":"signature"}],"annots":["%signatures"]}]}]})
}

/// Which payout path an event reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayoutPath {
    Fast,
    Cemented,
}

impl PayoutPath {
    pub fn tag(self) -> &'static str {
        match self {
            Self::Fast => FAST_PAYOUT_TAG,
            Self::Cemented => CEMENTED_PAYOUT_TAG,
        }
    }

    fn amount_field(self) -> &'static str {
        match self {
            Self::Fast => "fast",
            Self::Cemented => "cemented",
        }
    }
}

/// One key's entry in a `fast_payout` call's `signatures` map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureEntry {
    pub public_key: String,
    pub signature: String,
}

/// The parameters of an applied `fast_payout` call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FastPayoutCall {
    pub session_id: [u8; 16],
    pub amount: u128,
    pub signatures: Vec<SignatureEntry>,
}

/// One decoded payout event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayoutEvent {
    pub path: PayoutPath,
    pub vault: String,
    pub session_id: [u8; 16],
    /// `fast` or `cemented`: the amount the path asked to pay, in mutez.
    pub amount: u128,
    pub paid_now: u128,
    pub paid_total: u128,
    /// The operation group's hash: the `reference` of every alarm about it.
    pub operation_hash: String,
    /// The chain the operation group was included on (`Net…`).
    pub chain_id: Option<String>,
    /// For a fast payout, the call in the same operation naming the same
    /// session; `None` when it could not be found or decoded.
    pub call: Option<Result<FastPayoutCall, String>>,
}

/// One decoded `sweep` event: an executed `execute_sweep((sweep_id,
/// amount))`, which paid `amount` mutez to `treasury`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SweepEvent {
    pub vault: String,
    /// The 16-byte sweep id, `u64 BE level ‖ u64 BE id`: the kernel's
    /// `sweep-{level}-{id}` record this execution names.
    pub sweep_id: [u8; 16],
    /// The amount paid, in mutez.
    pub amount: u128,
    /// The address paid, as the vault's storage names it.
    pub treasury: String,
    /// The operation group's hash: the `reference` of every alarm about it.
    pub operation_hash: String,
}

/// What a block holds for the watched vaults.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockItem {
    Event(PayoutEvent),
    Sweep(SweepEvent),
    /// An applied payout or sweep event of a watched vault that did not
    /// decode: the vault moved money in a shape this watcher cannot read.
    Undecodable {
        vault: String,
        tag: String,
        operation_hash: String,
        reason: String,
    },
}

impl BlockItem {
    /// The watched vault the item is about.
    pub fn vault(&self) -> &str {
        match self {
            Self::Event(event) => &event.vault,
            Self::Sweep(sweep) => &sweep.vault,
            Self::Undecodable { vault, .. } => vault,
        }
    }
}

/// `(vault, parameter value)` when `node` is a transaction to a watched
/// vault's `fast_payout` entrypoint.
fn fast_payout_call_of<'a>(
    node: &'a Value,
    vaults: &BTreeSet<String>,
) -> Option<(&'a str, &'a Value)> {
    if node.get("kind").and_then(Value::as_str) != Some("transaction") {
        return None;
    }
    let vault = node
        .get("destination")
        .and_then(Value::as_str)
        .filter(|d| vaults.contains(*d))?;
    let parameters = node.get("parameters")?;
    if parameters.get("entrypoint").and_then(Value::as_str) != Some(FAST_PAYOUT_ENTRYPOINT) {
        return None;
    }

    Some((vault, parameters.get("value")?))
}

fn status_applied(node: &Value, result_key: &str) -> bool {
    node.get(result_key)
        .and_then(|r| r.get("status"))
        .and_then(Value::as_str)
        == Some("applied")
}

fn session_id_of(node: &Value) -> Result<[u8; 16], MichelineError> {
    let bytes = as_bytes(node)?;
    <[u8; 16]>::try_from(bytes.as_slice())
        .map_err(|_| MichelineError(format!("a session id is 16 bytes, found {}", bytes.len())))
}

fn sweep_id_of(node: &Value) -> Result<[u8; 16], MichelineError> {
    let bytes = as_bytes(node)?;
    <[u8; 16]>::try_from(bytes.as_slice())
        .map_err(|_| MichelineError(format!("a sweep id is 16 bytes, found {}", bytes.len())))
}

/// Decode a `sweep` event's payload through its type: `amount`, `sweep_id`
/// and `treasury`, by annotation.
fn decode_sweep(ty: &Value, payload: &Value) -> Result<([u8; 16], u128, String), MichelineError> {
    let f = fields(ty, payload)?;

    Ok((
        sweep_id_of(field(&f, "sweep_id")?)?,
        as_u128(field(&f, "amount")?)?,
        address_text(field(&f, "treasury")?)?,
    ))
}

/// Decode a `fast_payout` call's parameter value.
pub fn decode_fast_payout_call(value: &Value) -> Result<FastPayoutCall, MichelineError> {
    let f = fields(&fast_payout_parameter_type(), value)?;
    let signatures = as_map(field(&f, "signatures")?)?
        .into_iter()
        .map(|(k, v)| {
            Ok(SignatureEntry {
                public_key: key_text(k)?,
                signature: signature_text(v)?,
            })
        })
        .collect::<Result<Vec<_>, MichelineError>>()?;

    Ok(FastPayoutCall {
        session_id: session_id_of(field(&f, "session_id")?)?,
        amount: as_u128(field(&f, "amount")?)?,
        signatures,
    })
}

struct RawEvent<'a> {
    path: PayoutPath,
    vault: &'a str,
    ty: &'a Value,
    payload: &'a Value,
}

fn decode_event(raw: &RawEvent<'_>) -> Result<([u8; 16], u128, u128, u128), MichelineError> {
    let f = fields(raw.ty, raw.payload)?;

    Ok((
        session_id_of(field(&f, "session_id")?)?,
        as_u128(field(&f, raw.path.amount_field())?)?,
        as_u128(field(&f, "paid_now")?)?,
        as_u128(field(&f, "paid_total")?)?,
    ))
}

/// Every payout event of a vault in `vaults` in this block, in block order.
///
/// `operations` is the node's `/chains/main/blocks/{level}/operations/3`
/// answer: the block's manager operation groups, a flat list.
pub fn scan_block(operations: &Value, vaults: &BTreeSet<String>) -> Vec<BlockItem> {
    let mut items = Vec::new();
    let groups = operations.as_array().map(Vec::as_slice).unwrap_or(&[]);

    for group in groups {
        let hash = group
            .get("hash")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let chain_id = group.get("chain_id").and_then(Value::as_str);
        let contents = group
            .get("contents")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or(&[]);

        for content in contents {
            scan_content(content, hash, chain_id, vaults, &mut items);
        }
    }

    items
}

fn scan_content(
    content: &Value,
    hash: &str,
    chain_id: Option<&str>,
    vaults: &BTreeSet<String>,
    items: &mut Vec<BlockItem>,
) {
    let Some(metadata) = content.get("metadata") else {
        return;
    };
    let internal = metadata
        .get("internal_operation_results")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[]);

    // The fast_payout calls of this operation: the manager operation itself
    // (its status is in `metadata.operation_result`), or an internal
    // transaction (a contract batching the call; its status is in `result`).
    let mut calls: Vec<(&str, &Value)> = Vec::new();
    let top_applied = metadata
        .get("operation_result")
        .and_then(|r| r.get("status"))
        .and_then(Value::as_str)
        == Some("applied");
    if top_applied && let Some(call) = fast_payout_call_of(content, vaults) {
        calls.push(call);
    }
    for node in internal {
        if status_applied(node, "result")
            && let Some(call) = fast_payout_call_of(node, vaults)
        {
            calls.push(call);
        }
    }

    for node in internal {
        if node.get("kind").and_then(Value::as_str) != Some("event")
            || !status_applied(node, "result")
        {
            continue;
        }
        let Some(vault) = node
            .get("source")
            .and_then(Value::as_str)
            .filter(|s| vaults.contains(*s))
        else {
            continue;
        };
        let tag = node.get("tag").and_then(Value::as_str).unwrap_or_default();
        let undecodable = |reason: String| BlockItem::Undecodable {
            vault: vault.to_string(),
            tag: tag.to_string(),
            operation_hash: hash.to_string(),
            reason,
        };
        let path = match tag {
            FAST_PAYOUT_TAG => PayoutPath::Fast,
            CEMENTED_PAYOUT_TAG => PayoutPath::Cemented,
            SWEEP_TAG => {
                let (Some(ty), Some(payload)) = (node.get("type"), node.get("payload")) else {
                    items.push(undecodable(
                        "the event carries no type or no payload".to_string(),
                    ));
                    continue;
                };
                match decode_sweep(ty, payload) {
                    Err(e) => items.push(undecodable(e.0)),
                    Ok((sweep_id, amount, treasury)) => items.push(BlockItem::Sweep(SweepEvent {
                        vault: vault.to_string(),
                        sweep_id,
                        amount,
                        treasury,
                        operation_hash: hash.to_string(),
                    })),
                }
                continue;
            }
            _ => continue,
        };
        let (Some(ty), Some(payload)) = (node.get("type"), node.get("payload")) else {
            items.push(undecodable(
                "the event carries no type or no payload".to_string(),
            ));
            continue;
        };
        let raw = RawEvent {
            path,
            vault,
            ty,
            payload,
        };
        match decode_event(&raw) {
            Err(e) => items.push(undecodable(e.0)),
            Ok((session_id, amount, paid_now, paid_total)) => {
                let call = match path {
                    PayoutPath::Fast => find_call(&calls, raw.vault, &session_id),
                    PayoutPath::Cemented => None,
                };
                items.push(BlockItem::Event(PayoutEvent {
                    path,
                    vault: vault.to_string(),
                    session_id,
                    amount,
                    paid_now,
                    paid_total,
                    operation_hash: hash.to_string(),
                    chain_id: chain_id.map(str::to_string),
                    call,
                }));
            }
        }
    }
}

/// The call to `vault` naming `session_id`; a call that does not decode is
/// reported as such rather than skipped, so its signatures are never assumed.
fn find_call(
    calls: &[(&str, &Value)],
    vault: &str,
    session_id: &[u8; 16],
) -> Option<Result<FastPayoutCall, String>> {
    let mut undecodable = None;
    for (_, value) in calls.iter().filter(|(to, _)| *to == vault) {
        match decode_fast_payout_call(value) {
            Ok(call) if &call.session_id == session_id => return Some(Ok(call)),
            Ok(_) => {}
            Err(e) => undecodable = Some(Err(e.0)),
        }
    }

    undecodable
}

#[cfg(test)]
mod tests {
    use super::*;

    const VAULT: &str = "KT1BuEZtb68c1Q4yjtckcNjGELqWt56Xyesc";
    const SPPK: &str = "sppk7bWq3wGj9AuTowUc7N2dpRhMCWtw6pmDFcLrSTLyA1mnBJ9hL5T";
    const SPSIG: &str = "spsig1T44Ls6CqyU9xqnDbB7QU4oZRdkXUDbx8Edi2hoPsmxKfmi1nj1GCic3GBzC7xssqPqJwVELB9uzoqEeLYQePdPdLbPDQE";
    const SESSION: &str = "0102030405060708090a0b0c0d0e0f10";

    fn event(tag: &str, amount_field: &str, status: &str) -> Value {
        json!({
            "kind": "event", "source": VAULT, "tag": tag,
            "type": {"prim":"pair","args":[
                {"prim":"mutez","annots":[format!("%{amount_field}")]},
                {"prim":"pair","args":[{"prim":"mutez","annots":["%paid_now"]},
                    {"prim":"pair","args":[{"prim":"mutez","annots":["%paid_total"]},
                        {"prim":"bytes","annots":["%session_id"]}]}]}]},
            "payload": {"prim":"Pair","args":[{"int":"5"},{"int":"5"},{"int":"5"},{"bytes":SESSION}]},
            "result": {"status": status}
        })
    }

    fn call_value() -> Value {
        json!({"prim":"Pair","args":[{"int":"5"},{"prim":"Pair","args":[{"bytes":SESSION},
            [{"prim":"Elt","args":[{"string":SPPK},{"string":SPSIG}]}]]}]})
    }

    fn block(content: Value) -> Value {
        json!([{"hash": "oo1", "chain_id": "NetXdQprcVkpaWU", "contents": [content]}])
    }

    fn watched() -> BTreeSet<String> {
        [VAULT.to_string()].into()
    }

    #[test]
    fn a_fast_payout_is_paired_with_its_direct_call() {
        let items = scan_block(
            &block(json!({
                "kind": "transaction", "destination": VAULT,
                "parameters": {"entrypoint": "fast_payout", "value": call_value()},
                "metadata": {"operation_result": {"status": "applied"},
                    "internal_operation_results": [event("fast_payout", "fast", "applied")]}
            })),
            &watched(),
        );
        let [BlockItem::Event(e)] = items.as_slice() else {
            panic!("{items:?}")
        };

        assert_eq!(e.path, PayoutPath::Fast);
        assert_eq!((e.amount, e.paid_now, e.paid_total), (5, 5, 5));
        assert_eq!(e.chain_id.as_deref(), Some("NetXdQprcVkpaWU"));
        let call = e.call.clone().expect("call").expect("decodes");
        assert_eq!(call.signatures[0].public_key, SPPK);
    }

    #[test]
    fn a_call_batched_through_a_contract_is_found_in_the_internal_results() {
        let items = scan_block(
            &block(json!({
                "kind": "transaction", "destination": "KT1EfTusMLoeCAAGd9MZJn5yKzFr6kJU5U91",
                "parameters": {"entrypoint": "default", "value": {"prim": "Unit"}},
                "metadata": {"operation_result": {"status": "applied"},
                    "internal_operation_results": [
                        {"kind": "transaction", "destination": VAULT,
                         "parameters": {"entrypoint": "fast_payout", "value": call_value()},
                         "result": {"status": "applied"}},
                        event("fast_payout", "fast", "applied")]}
            })),
            &watched(),
        );
        let [BlockItem::Event(e)] = items.as_slice() else {
            panic!("{items:?}")
        };

        assert!(matches!(e.call, Some(Ok(_))));
    }

    #[test]
    fn reverted_events_and_other_vaults_are_ignored() {
        let content = |source: &str, status: &str| {
            let mut ev = event("cemented_payout", "cemented", status);
            ev["source"] = json!(source);
            json!({"kind": "smart_rollup_execute_outbox_message",
                "metadata": {"operation_result": {"status": "applied"},
                    "internal_operation_results": [ev]}})
        };

        assert!(scan_block(&block(content(VAULT, "backtracked")), &watched()).is_empty());
        assert!(
            scan_block(
                &block(content("KT1EfTusMLoeCAAGd9MZJn5yKzFr6kJU5U91", "applied")),
                &watched()
            )
            .is_empty()
        );
        assert_eq!(
            scan_block(&block(content(VAULT, "applied")), &watched()).len(),
            1
        );
    }

    #[test]
    fn an_event_that_does_not_decode_is_reported_not_skipped() {
        let mut ev = event("fast_payout", "fast", "applied");
        ev["payload"] = json!({"int": "5"});
        let items = scan_block(
            &block(json!({"kind": "transaction",
                "metadata": {"operation_result": {"status": "applied"},
                    "internal_operation_results": [ev]}})),
            &watched(),
        );

        assert!(matches!(items.as_slice(), [BlockItem::Undecodable { .. }]));
    }

    /// The sweep generation's `EMIT %sweep`: `pair (mutez %amount) (pair
    /// (bytes %sweep_id) (address %treasury))`, read by annotation in either
    /// form of the address.
    #[test]
    fn a_sweep_event_decodes_its_id_amount_and_treasury() {
        let treasury = "KT1EfTusMLoeCAAGd9MZJn5yKzFr6kJU5U91";
        let sweep = |treasury_node: Value| {
            json!({
                "kind": "event", "source": VAULT, "tag": "sweep",
                "type": {"prim":"pair","args":[
                    {"prim":"mutez","annots":["%amount"]},
                    {"prim":"pair","args":[{"prim":"bytes","annots":["%sweep_id"]},
                        {"prim":"address","annots":["%treasury"]}]}]},
                "payload": {"prim":"Pair","args":[{"int":"7"},{"prim":"Pair","args":[
                    {"bytes":"00000000000000640000000000000003"}, treasury_node]}]},
                "result": {"status": "applied"}
            })
        };
        let decoded = bs58::decode(treasury).with_check(None).into_vec().unwrap();
        let mut forged = vec![0x01];

        forged.extend_from_slice(&decoded[3..]);
        forged.push(0x00);

        for node in [
            json!({ "string": treasury }),
            json!({ "bytes": hex::encode(forged) }),
        ] {
            let items = scan_block(
                &block(json!({"kind": "smart_rollup_execute_outbox_message",
                    "metadata": {"operation_result": {"status": "applied"},
                        "internal_operation_results": [sweep(node)]}})),
                &watched(),
            );
            let [BlockItem::Sweep(e)] = items.as_slice() else {
                panic!("{items:?}")
            };

            assert_eq!(e.vault, VAULT);
            assert_eq!(e.amount, 7);
            assert_eq!(e.treasury, treasury);
            assert_eq!(e.sweep_id[7], 100);
            assert_eq!(e.sweep_id[15], 3);
            assert_eq!(e.operation_hash, "oo1");
        }

        let mut bad = sweep(json!({ "string": treasury }));

        bad["payload"] = json!({"int": "7"});

        let items = scan_block(
            &block(json!({"kind": "smart_rollup_execute_outbox_message",
                "metadata": {"operation_result": {"status": "applied"},
                    "internal_operation_results": [bad]}})),
            &watched(),
        );

        assert!(
            matches!(items.as_slice(), [BlockItem::Undecodable { tag, .. }] if tag == "sweep"),
            "{items:?}"
        );
    }

    #[test]
    fn a_fast_payout_without_its_call_carries_none() {
        let items = scan_block(
            &block(json!({"kind": "transaction",
                "metadata": {"operation_result": {"status": "applied"},
                    "internal_operation_results": [event("fast_payout", "fast", "applied")]}})),
            &watched(),
        );
        let [BlockItem::Event(e)] = items.as_slice() else {
            panic!("{items:?}")
        };

        assert_eq!(e.call, None);
    }
}
