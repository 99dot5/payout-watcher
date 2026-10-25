//! What the watcher reads from a vault's own L1 storage: the scope it was
//! originated for, its current fast-payout signers and, on the sweep
//! generation, the treasury every sweep pays.
//!
//! `tenant_id` and `pool_id` are baked into the vault at origination and
//! immutable, so the kernel records a fast payout is compared with are found
//! from the vault itself, never from configuration. `payout_signers` is read
//! at the block BEFORE the payout, the set the vault checked the signatures
//! against (a rotation in the same block, ahead of the payout, shows up as a
//! signer outside the set — the alarm then names a change of signers either
//! way).

use crate::keys::{address_text, key_text};
use crate::micheline::{MichelineError, as_sequence, as_string, field, fields};
use serde_json::Value;
use std::collections::BTreeSet;

/// The fields of a vault's storage the watcher uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultStorage {
    pub tenant_id: String,
    pub pool_id: String,
    /// Base58check public keys, whatever form the node rendered them in.
    /// `None` on a vault generation without the fast payout (slice 1 of the
    /// ledger design): its cemented payouts are still checked.
    pub payout_signers: Option<BTreeSet<String>>,
    /// The address every `execute_sweep` pays, baked at origination and
    /// never changed. `None` on a vault generation without sweeps, which
    /// emits no `sweep` event.
    pub treasury: Option<String>,
}

/// Decode the node's `/context/contracts/{KT1}/script` answer: the storage
/// value read through the storage type in the script's code.
pub fn decode_script(script: &Value) -> Result<VaultStorage, MichelineError> {
    let storage_type = script
        .get("code")
        .and_then(Value::as_array)
        .and_then(|code| {
            code.iter()
                .find(|section| section.get("prim").and_then(Value::as_str) == Some("storage"))
        })
        .and_then(|section| section.get("args"))
        .and_then(Value::as_array)
        .and_then(|args| args.first())
        .ok_or_else(|| MichelineError("the script has no storage section".to_string()))?;
    let value = script
        .get("storage")
        .ok_or_else(|| MichelineError("the script has no storage value".to_string()))?;
    let f = fields(storage_type, value)?;
    let payout_signers = match f.get("payout_signers") {
        None => None,
        Some(signers) => Some(
            as_sequence(signers)?
                .iter()
                .map(key_text)
                .collect::<Result<_, _>>()?,
        ),
    };

    let treasury = f.get("treasury").map(address_text).transpose()?;

    Ok(VaultStorage {
        tenant_id: as_string(field(&f, "tenant_id")?)?.to_string(),
        pool_id: as_string(field(&f, "pool_id")?)?.to_string(),
        payout_signers,
        treasury,
    })
}
