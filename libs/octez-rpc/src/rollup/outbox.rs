//! The rollup node's view of its unexecuted outbox messages
//! (`/local/outbox/pending`), typed.
//!
//! Measured against `octez-smart-rollup-node` v25 (`rollup_node_services.ml`,
//! `Encodings.outbox` merged with `outbox_msg_status`): every entry is one
//! outbox level with the messages of that level the node has not seen
//! executed on L1, and — on the undivided `/local/outbox/pending` list only —
//! the level's `status` under the protocol's execution window, evaluated by
//! the node against its last cemented commitment (LCC):
//!
//! | `status`     | the level `L` is …                                   |
//! | ------------ | ---------------------------------------------------- |
//! | `pending`    | above the LCC: not cemented yet                      |
//! | `executable` | `LCC − max_active_outbox_levels < L ≤ LCC`           |
//! | `lost`       | `L ≤ LCC − max_active_outbox_levels`: never executable again |
//!
//! The two sub-lists (`…/pending/executable`, `…/pending/unexecutable`) carry
//! no `status` and leave the `lost` levels out, so "in neither list" does not
//! mean executed. A message the node has seen executed is in no list at all.
//!
//! The node marks a message executed when it sees an applied
//! `smart_rollup_execute_outbox_message` for it on L1, whoever submitted it,
//! in observer and operator mode alike. That mark is local node state: a
//! wiped data directory or a snapshot import can forget it, so an absent
//! message is "executed, per this node", not a proof.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt;

/// Where a pending level stands under the protocol's execution window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PendingStatus {
    /// Not cemented yet.
    Pending,
    /// Cemented and inside the window: anyone may execute it.
    Executable,
    /// Past the window: it can never be executed.
    Lost,
}

impl fmt::Display for PendingStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Pending => "pending",
            Self::Executable => "executable",
            Self::Lost => "lost",
        })
    }
}

/// One outbox level with its unexecuted messages.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct PendingOutboxEntry {
    pub outbox_level: u32,
    pub messages: Vec<PendingOutboxMessage>,
    /// Only the undivided list carries it; the two sub-lists do not.
    #[serde(default)]
    pub status: Option<PendingStatus>,
}

/// One unexecuted message of a level: its index, and its content when the
/// node could read it back from the PVM state (`message` is optional in the
/// node's encoding).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct PendingOutboxMessage {
    pub message_index: u32,
    /// `{"transactions": [{destination, entrypoint, parameters, …}]}` for a
    /// batch of contract calls, `{"whitelist_update": …}` otherwise.
    #[serde(default)]
    pub message: Option<Value>,
}

/// One contract call of an outbox message, as the node summarises it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxTransaction<'a> {
    pub destination: &'a str,
    /// Without the leading `%` the node sometimes renders; `default` when the
    /// message named none.
    pub entrypoint: &'a str,
    /// The Micheline parameter value.
    pub parameters: &'a Value,
}

impl PendingOutboxMessage {
    /// The message's contract calls; empty for a whitelist update or an
    /// unreadable message.
    pub fn transactions(&self) -> Vec<OutboxTransaction<'_>> {
        self.message
            .as_ref()
            .and_then(|message| message.get("transactions"))
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or(&[])
            .iter()
            .filter_map(|transaction| {
                Some(OutboxTransaction {
                    destination: transaction.get("destination")?.as_str()?,
                    entrypoint: transaction
                        .get("entrypoint")
                        .and_then(Value::as_str)
                        .unwrap_or("default")
                        .trim_start_matches('%'),
                    parameters: transaction.get("parameters")?,
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_undivided_list_carries_a_status_and_the_sub_lists_do_not() {
        let full: Vec<PendingOutboxEntry> = serde_json::from_value(json!([
            {"outbox_level": 42, "messages": [{"message_index": 0}], "status": "lost"},
            {"outbox_level": 43, "messages": [], "status": "executable"},
            {"outbox_level": 44, "messages": [], "status": "pending"}
        ]))
        .expect("decodes");

        assert_eq!(
            full.iter().map(|e| e.status).collect::<Vec<_>>(),
            vec![
                Some(PendingStatus::Lost),
                Some(PendingStatus::Executable),
                Some(PendingStatus::Pending)
            ]
        );
        assert_eq!(full[0].messages[0].message_index, 0);
        assert_eq!(full[0].messages[0].message, None);

        let sub: Vec<PendingOutboxEntry> =
            serde_json::from_value(json!([{"outbox_level": 42, "messages": []}])).expect("decodes");

        assert_eq!(sub[0].status, None);
        assert_eq!(PendingStatus::Lost.to_string(), "lost");
    }

    #[test]
    fn transactions_are_read_with_the_entrypoint_bare() {
        let message: PendingOutboxMessage = serde_json::from_value(json!({
            "message_index": 3,
            "message": {"transactions": [
                {"destination": "KT1a", "entrypoint": "%execute_sweep", "parameters": {"int": "1"}},
                {"destination": "KT1b", "entrypoint": "execute_bounce", "parameters": {"int": "2"}},
                {"destination": "KT1c", "parameters": {"prim": "Unit"}},
                {"destination": "KT1d", "entrypoint": "no_parameters"}
            ]}
        }))
        .expect("decodes");
        let transactions = message.transactions();

        assert_eq!(
            transactions.len(),
            3,
            "a call without parameters is skipped"
        );
        assert_eq!(transactions[0].entrypoint, "execute_sweep");
        assert_eq!(transactions[1].entrypoint, "execute_bounce");
        assert_eq!(transactions[2].entrypoint, "default");
        assert_eq!(transactions[0].parameters, &json!({"int": "1"}));

        let whitelist: PendingOutboxMessage = serde_json::from_value(json!({
            "message_index": 0,
            "message": {"whitelist_update": ["KT1a"]}
        }))
        .expect("decodes");

        assert!(whitelist.transactions().is_empty());
    }
}
