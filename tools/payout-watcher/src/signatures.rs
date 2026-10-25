//! Re-verifying a submitted fast payout's signatures against the vault's own
//! `payout_signers` (spec D3), with the one shared encoder and verifier
//! (`payout_protocol`).
//!
//! The vault counts an entry only when its key is in the set and its
//! signature verifies over `PACK(("fast-payout:v1", chain_id, vault,
//! session_id, amount))`, and ignores keys outside the set. The watcher
//! reports what the vault ignores, too: an entry from outside the set means a
//! key nobody registered was handed a signing request, and a rotation of the
//! set itself is a change of who can pay.

use crate::events::SignatureEntry;
use payout_protocol::{
    ChainId, PAYOUT_THRESHOLD, VaultAddress, fast_payout_payload, verify_fast_payout_signature,
};
use std::collections::BTreeSet;

/// What the signatures of one fast payout amount to.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SignatureVerdict {
    /// Keys of the set whose signature verifies: what the vault counted.
    pub valid: Vec<String>,
    /// Keys outside the set, with whether their signature verified.
    pub foreign: Vec<(String, bool)>,
    /// Keys of the set whose signature does not verify, and why.
    pub invalid: Vec<(String, String)>,
}

impl SignatureVerdict {
    /// Fewer valid in-set signatures than the vault's threshold.
    pub fn under_threshold(&self) -> bool {
        self.valid.len() < PAYOUT_THRESHOLD
    }
}

/// Verify every entry of a call against `signers`, over the payload the vault
/// would have checked for `(chain_id, vault, session_id, amount_mutez)`.
pub fn verify_call(
    chain_id: &ChainId,
    vault: &VaultAddress,
    session_id: &[u8; 16],
    amount_mutez: u64,
    entries: &[SignatureEntry],
    signers: &BTreeSet<String>,
) -> SignatureVerdict {
    let payload = fast_payout_payload(chain_id, vault, session_id, amount_mutez);
    let mut verdict = SignatureVerdict::default();

    for entry in entries {
        let check = verify_fast_payout_signature(&entry.public_key, &entry.signature, &payload);
        match (signers.contains(&entry.public_key), check) {
            (true, Ok(())) => verdict.valid.push(entry.public_key.clone()),
            (true, Err(e)) => verdict
                .invalid
                .push((entry.public_key.clone(), e.to_string())),
            (false, check) => verdict
                .foreign
                .push((entry.public_key.clone(), check.is_ok())),
        }
    }

    verdict
}
