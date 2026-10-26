//! Comparing a fast payout with what the kernel recorded, read from the
//! watcher's OWN rollup node at its finalised block (ADR 0027 §4.8).
//!
//! The records and keys are the ones the validator signs from
//! (`payout_protocol::kernel_records`): the session at
//! `/tenants/{tenant}/pools/{pool}/sessions/{id}` and its payout at
//! `…/transactions/TEZ/session-{id}-end-payout`. A fast payout is sound only when the
//! session exists, has ended, was funded through the vault that paid, is a
//! TEZ session, and the row at its payout key is the kernel's `SessionEndPayout` (the
//! session's balance leaving the rollup) of at least the amount paid.
//! Anything else is a finding: the fast path paid a number the kernel does
//! not back.
//!
//! Paying LESS than the kernel's number is not a finding. The cemented
//! payout tops it up to the kernel's figure (spec D2), so the player's floor
//! is unaffected; it is reported as a notice.

use payout_protocol::kernel_identity::{RootHash, format_root_hash, root_hash_of};
use payout_protocol::kernel_records::{KERNEL_BOOT_KEY, KERNEL_INFO_KEY};
use payout_protocol::session_payout::{
    NotReady, Read, Refusal, SessionPayoutRead, read_envelope, read_session_payout,
};
use smart_rollup_storage::KernelInfoEnvelope;
use smart_rollup_storage_reader::store::{DurableStore, StoreError};
use uuid::Uuid;

/// What the kernel's records say about one fast payout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KernelFinding {
    /// The kernel recorded at least the amount paid: the payout is backed.
    Backed { kernel_amount: u128 },
    /// Paid less than the kernel recorded; the cemented payout tops it up.
    Short { kernel_amount: u128 },
    /// Paid MORE than the kernel recorded: the overpayment ADR 0027 §4.8
    /// exists to prove.
    AboveKernel { kernel_amount: u128 },
    /// No session record under the paying vault's scope.
    SessionNotRecorded,
    /// The session exists but the kernel has not ended it.
    SessionNotEnded,
    /// The kernel recorded the session against another vault.
    FundingVaultMismatch { recorded: String },
    /// The session is not a TEZ session; a fast payout pays TEZ only.
    SessionAssetNotTez { asset: String },
    /// The session ended with no payout record: the kernel owes nothing.
    PayoutNotRecorded,
    /// The record at the payout key is not the session payout. `EndSession`
    /// writes it as a `SessionEndPayout` (the balance leaving the rollup,
    /// `libs/smart-rollup/src/sessions.rs`); `RoundEndPayout` is the per-round credit
    /// and never reaches L1 on its own.
    PayoutRecordNotASessionEndPayout { kind: String },
    /// A record that does not decode as its envelope.
    CorruptRecord { key: String, reason: String },
}

/// Compare a fast payout of `amount` mutez on `vault` with the kernel's
/// records for `session_id` under `(tenant, pool)`.
pub async fn check_fast_payout<S: DurableStore>(
    store: &S,
    tenant: &str,
    pool: &str,
    vault: &str,
    session_id: &Uuid,
    amount: u128,
) -> Result<KernelFinding, StoreError> {
    // The one read every pricer of a fast payout makes (the sequencer's own
    // read, the validator's), mapped onto this watcher's findings.
    let record = match read_session_payout(store, tenant, pool, vault, session_id).await? {
        SessionPayoutRead::Recorded(record) => record,
        SessionPayoutRead::NotReady(NotReady::SessionNotRecorded) => {
            return Ok(KernelFinding::SessionNotRecorded);
        }
        SessionPayoutRead::NotReady(NotReady::SessionNotEnded) => {
            return Ok(KernelFinding::SessionNotEnded);
        }
        SessionPayoutRead::NotReady(NotReady::PayoutNotRecorded) => {
            return Ok(KernelFinding::PayoutNotRecorded);
        }
        SessionPayoutRead::Refused(Refusal::VaultMismatch { recorded, .. }) => {
            return Ok(KernelFinding::FundingVaultMismatch { recorded });
        }
        SessionPayoutRead::Refused(Refusal::AssetNotTez { asset }) => {
            return Ok(KernelFinding::SessionAssetNotTez { asset });
        }
        SessionPayoutRead::Refused(Refusal::NotASessionEndPayoutRecord { kind }) => {
            return Ok(KernelFinding::PayoutRecordNotASessionEndPayout { kind });
        }
        SessionPayoutRead::Refused(Refusal::CorruptRecord { key, reason }) => {
            return Ok(KernelFinding::CorruptRecord { key, reason });
        }
    };

    Ok(match amount.cmp(&record.amount) {
        core::cmp::Ordering::Greater => KernelFinding::AboveKernel {
            kernel_amount: record.amount,
        },
        core::cmp::Ordering::Less => KernelFinding::Short {
            kernel_amount: record.amount,
        },
        core::cmp::Ordering::Equal => KernelFinding::Backed {
            kernel_amount: record.amount,
        },
    })
}

/// The kernel a runner can pin the comparison to (ADR 0027 §1.3 condition 2):
/// the `/kernel/info` version and the reveal-tree root hash of the installed
/// `/kernel/boot.wasm`. Both optional; set either and every pass checks it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KernelPin {
    pub version: Option<String>,
    pub root_hash: Option<RootHash>,
}

/// Why the node's kernel is not the pinned one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelMismatch {
    pub detail: String,
}

/// Check the node's installed kernel against `pin`; `Ok(None)` when it
/// matches (or nothing is pinned).
pub async fn check_kernel_pin<S: DurableStore>(
    store: &S,
    pin: &KernelPin,
) -> Result<Option<KernelMismatch>, StoreError> {
    let mismatch = |detail: String| Ok(Some(KernelMismatch { detail }));

    if let Some(expected) = &pin.version {
        match read_envelope::<_, KernelInfoEnvelope>(store, KERNEL_INFO_KEY).await? {
            Read::Absent => return mismatch(format!("{KERNEL_INFO_KEY} is absent")),
            Read::Corrupt { reason } => {
                return mismatch(format!("{KERNEL_INFO_KEY} does not decode: {reason}"));
            }
            Read::Value(KernelInfoEnvelope::V1(info)) if &info.version != expected => {
                return mismatch(format!(
                    "the node runs kernel {}, the pin is {expected}",
                    info.version
                ));
            }
            Read::Value(_) => {}
        }
    }
    if let Some(expected) = &pin.root_hash {
        match store.value(KERNEL_BOOT_KEY).await? {
            None => return mismatch(format!("{KERNEL_BOOT_KEY} is absent")),
            Some(bytes) => match root_hash_of(&bytes) {
                Err(reason) => return mismatch(format!("the installed kernel: {reason}")),
                Ok(found) if &found != expected => {
                    return mismatch(format!(
                        "the installed kernel hashes to {}, the pin is {}",
                        format_root_hash(&found),
                        format_root_hash(expected)
                    ));
                }
                Ok(_) => {}
            },
        }
    }

    Ok(None)
}
