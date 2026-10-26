//! The one read of a session's payout from the kernel's records, shared by
//! everything that prices a fast payout against them: the sequencer's own
//! read (ADR 0028 §4.2 step 1), the validator's `decide_and_sign` (§4.3) and
//! the public overpayment watcher (ADR 0027 §4.8). The keys are
//! [`crate::kernel_records`]; this module is the decision over what they
//! hold, so three readers cannot disagree about what a session's row means.
//!
//! What it reads, at whatever block the [`DurableStore`] is bound to (the
//! callers bind it to [`crate::kernel_records::FINALIZED_BLOCK`]):
//!
//! 1. the session record under `(tenant, pool)`: absent is *not ready*, not
//!    `ended` is *not ready*, a `funding_vault_address` other than `vault`
//!    is refused (the signature would be bound to the wrong vault), an asset
//!    other than TEZ is refused (v1 pays TEZ only, ADR 0027 §4.1);
//! 2. the `session-{session_id}-end-payout` row: absent is *not ready*, a kind other
//!    than `SessionEndPayout` is refused. `EndSession` writes the session's
//!    balance leaving the rollup as a `SessionEndPayout`
//!    (`libs/smart-rollup/src/sessions.rs`); `RoundEndPayout` is a round's
//!    credit into the balance and is never at this key.
//!
//! Bytes that do not decode as their envelope are refused with the key, so a
//! layout this build does not know is a verdict, never a guess. A store that
//! does not answer is a [`StoreError`], not a verdict.
//!
//! The amount comes back as the kernel stores it, a `u128` in the atomic
//! units of the session's asset. Zero and anything above `u64` are the
//! callers' business: the sequencer treats zero as `nothing-to-pay`, the
//! validator refuses both before it signs a `mutez` amount.

use crate::kernel_records::{TEZ, session_end_payout_key, session_key};
use borsh::BorshDeserialize;
use core::fmt;
use smart_rollup_storage::v1::StoredTransactionKind;
use smart_rollup_storage::{StoredSessionEnvelope, StoredTransactionEnvelope};
use smart_rollup_storage_reader::store::{DurableStore, StoreError};
use uuid::Uuid;

/// The kernel's record of a session's payout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionPayout {
    /// The session's asset, `TEZ` in v1.
    pub asset: String,
    /// The balance that left the rollup, in atomic units of `asset`; zero
    /// when the session ended owing nothing.
    pub amount: u128,
}

/// The read's verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionPayoutRead {
    /// The kernel recorded the payout.
    Recorded(SessionPayout),
    /// The store has not finalised the session's end yet; retryable.
    NotReady(NotReady),
    /// The records cannot be the basis of a fast payout, however long one
    /// waits.
    Refused(Refusal),
}

/// Why the store is not ready to answer yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotReady {
    /// No session record at the block read.
    SessionNotRecorded,
    /// The session is recorded but `EndSession` has not been processed at
    /// the block read.
    SessionNotEnded,
    /// The session has ended but its `session-{session_id}-end-payout` row is not at
    /// the block read yet.
    PayoutNotRecorded,
}

impl fmt::Display for NotReady {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SessionNotRecorded => {
                write!(f, "the session is not recorded at the finalised block")
            }
            Self::SessionNotEnded => write!(f, "the session has not ended at the finalised block"),
            Self::PayoutNotRecorded => write!(
                f,
                "the session's payout is not recorded at the finalised block"
            ),
        }
    }
}

/// Why the kernel's records refuse to price a fast payout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// The kernel recorded the session against another vault.
    VaultMismatch { recorded: String, requested: String },
    /// The session's asset is not TEZ.
    AssetNotTez { asset: String },
    /// The row at the payout key is not the session payout: a kind other
    /// than the `SessionEndPayout` that `EndSession` writes.
    NotASessionEndPayoutRecord { kind: String },
    /// A record at `key` that does not decode as its envelope: a layout
    /// this build does not know, or a corrupted node.
    CorruptRecord { key: String, reason: String },
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::VaultMismatch {
                recorded,
                requested,
            } => write!(
                f,
                "the kernel recorded the session against vault {recorded}, the request names {requested}"
            ),
            Self::AssetNotTez { asset } => write!(
                f,
                "the session's asset is {asset}; fast payouts pay TEZ only"
            ),
            Self::NotASessionEndPayoutRecord { kind } => write!(
                f,
                "the record at the payout key is a {kind}, not a SessionEndPayout"
            ),
            Self::CorruptRecord { key, reason } => {
                write!(f, "the record at {key} does not decode: {reason}")
            }
        }
    }
}

/// A durable read, classified: the key is absent, holds a `T`, or holds
/// bytes that are not a `T`.
#[derive(Debug)]
pub enum Read<T> {
    Absent,
    Value(T),
    Corrupt { reason: String },
}

/// Read and decode the versioned envelope at `key`.
pub async fn read_envelope<S: DurableStore, T: BorshDeserialize>(
    store: &S,
    key: &str,
) -> Result<Read<T>, StoreError> {
    Ok(match store.value(key).await? {
        None => Read::Absent,
        Some(bytes) => match T::try_from_slice(&bytes) {
            Ok(value) => Read::Value(value),
            Err(e) => Read::Corrupt {
                reason: e.to_string(),
            },
        },
    })
}

/// Read the session under `(tenant, pool)` and its payout row, and decide
/// whether they price a fast payout on `vault`. `vault` is compared as the
/// kernel stores it, a base58 `KT1…`; validating the text is the caller's.
pub async fn read_session_payout<S: DurableStore>(
    store: &S,
    tenant: &str,
    pool: &str,
    vault: &str,
    session_id: &Uuid,
) -> Result<SessionPayoutRead, StoreError> {
    let key = session_key(tenant, pool, session_id);
    let session = match read_envelope::<_, StoredSessionEnvelope>(store, &key).await? {
        Read::Absent => return Ok(SessionPayoutRead::NotReady(NotReady::SessionNotRecorded)),
        Read::Corrupt { reason } => {
            return Ok(SessionPayoutRead::Refused(Refusal::CorruptRecord {
                key,
                reason,
            }));
        }
        Read::Value(StoredSessionEnvelope::V1(session)) => session,
    };

    if !session.ended {
        return Ok(SessionPayoutRead::NotReady(NotReady::SessionNotEnded));
    }

    if session.funding_vault_address != vault {
        return Ok(SessionPayoutRead::Refused(Refusal::VaultMismatch {
            recorded: session.funding_vault_address,
            requested: vault.to_string(),
        }));
    }

    if session.asset != TEZ {
        return Ok(SessionPayoutRead::Refused(Refusal::AssetNotTez {
            asset: session.asset,
        }));
    }

    let key = session_end_payout_key(tenant, pool, &session.asset, session_id);
    let record = match read_envelope::<_, StoredTransactionEnvelope>(store, &key).await? {
        Read::Absent => return Ok(SessionPayoutRead::NotReady(NotReady::PayoutNotRecorded)),
        Read::Corrupt { reason } => {
            return Ok(SessionPayoutRead::Refused(Refusal::CorruptRecord {
                key,
                reason,
            }));
        }
        Read::Value(StoredTransactionEnvelope::V1(record)) => record,
    };

    if record.kind != StoredTransactionKind::SessionEndPayout {
        return Ok(SessionPayoutRead::Refused(
            Refusal::NotASessionEndPayoutRecord {
                kind: format!("{:?}", record.kind),
            },
        ));
    }

    Ok(SessionPayoutRead::Recorded(SessionPayout {
        asset: session.asset,
        amount: record.amount,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use borsh::BorshSerialize;
    use smart_rollup_storage::v1::{StoredSession, StoredTransaction};
    use std::collections::HashMap;
    use std::sync::Mutex;

    const TENANT: &str = "acme";
    const POOL: &str = "main";
    const VAULT: &str = "KT1BuEZtb68c1Q4yjtckcNjGELqWt56Xyesc";
    const OTHER_VAULT: &str = "KT1FNqdhr7P6FM9rx6P1CoPasUYE5JPSCqup";
    const OWNER: &str = "tz1UyQDepgtUBnWjyzzonqeDwaiWoQzRKSP5";

    /// The records a kernel would hold, by key, plus a transport fault.
    #[derive(Default)]
    struct MemoryStore {
        values: HashMap<String, Vec<u8>>,
        fail: Mutex<bool>,
    }

    impl MemoryStore {
        fn put<T: BorshSerialize>(&mut self, key: &str, value: &T) -> &mut Self {
            self.values
                .insert(key.to_string(), borsh::to_vec(value).expect("borsh"));
            self
        }

        fn put_raw(&mut self, key: &str, bytes: &[u8]) -> &mut Self {
            self.values.insert(key.to_string(), bytes.to_vec());
            self
        }

        fn remove(&mut self, key: &str) -> &mut Self {
            self.values.remove(key);
            self
        }

        fn fail_reads(&self) {
            *self.fail.lock().unwrap() = true;
        }
    }

    impl DurableStore for MemoryStore {
        async fn subkeys(&self, _key: &str) -> Result<Vec<String>, StoreError> {
            unimplemented!("the session payout read never lists keys")
        }

        async fn value(&self, key: &str) -> Result<Option<Vec<u8>>, StoreError> {
            if *self.fail.lock().unwrap() {
                return Err(StoreError::Decode("node unreachable (test)".to_string()));
            }
            Ok(self.values.get(key).cloned())
        }

        async fn length(&self, key: &str) -> Result<Option<u64>, StoreError> {
            Ok(self.values.get(key).map(|v| v.len() as u64))
        }
    }

    fn ended_session(vault: &str, asset: &str) -> StoredSessionEnvelope {
        StoredSessionEnvelope::V1(StoredSession {
            owner: OWNER.to_string(),
            asset: asset.to_string(),
            balance: 0,
            funding_vault_address: vault.to_string(),
            ended: true,
            end_reason: Some("player".to_string()),
        })
    }

    /// The row as `EndSession` writes it.
    fn payout_row(kind: StoredTransactionKind, amount: u128) -> StoredTransactionEnvelope {
        StoredTransactionEnvelope::V1(StoredTransaction {
            account_address: OWNER.to_string(),
            asset: TEZ.to_string(),
            kind,
            amount,
        })
    }

    fn store_with(session_id: &Uuid, amount: u128) -> MemoryStore {
        let mut store = MemoryStore::default();
        store
            .put(
                &session_key(TENANT, POOL, session_id),
                &ended_session(VAULT, TEZ),
            )
            .put(
                &session_end_payout_key(TENANT, POOL, TEZ, session_id),
                &payout_row(StoredTransactionKind::SessionEndPayout, amount),
            );
        store
    }

    async fn read(store: &MemoryStore, id: &Uuid) -> SessionPayoutRead {
        read_session_payout(store, TENANT, POOL, VAULT, id)
            .await
            .expect("the store answered")
    }

    #[tokio::test]
    async fn a_recorded_session_end_payout_is_read_with_the_kernels_amount() {
        let id = Uuid::from_u128(7);
        let store = store_with(&id, 1_500_000);

        assert_eq!(
            read(&store, &id).await,
            SessionPayoutRead::Recorded(SessionPayout {
                asset: TEZ.to_string(),
                amount: 1_500_000,
            })
        );
    }

    /// Zero and above-`u64` are read as stored: what to do with them is the
    /// caller's rule, not the read's.
    #[tokio::test]
    async fn zero_and_above_mutez_are_read_as_the_kernel_stored_them() {
        let id = Uuid::from_u128(8);

        for amount in [0, u128::from(u64::MAX) + 1] {
            let store = store_with(&id, amount);
            match read(&store, &id).await {
                SessionPayoutRead::Recorded(record) => assert_eq!(record.amount, amount),
                other => panic!("expected Recorded, got {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn a_lagging_store_is_not_ready_at_each_step() {
        let id = Uuid::from_u128(9);
        let mut store = store_with(&id, 5);

        store.remove(&session_end_payout_key(TENANT, POOL, TEZ, &id));
        assert_eq!(
            read(&store, &id).await,
            SessionPayoutRead::NotReady(NotReady::PayoutNotRecorded)
        );

        let mut open = ended_session(VAULT, TEZ);
        let StoredSessionEnvelope::V1(inner) = &mut open;
        inner.ended = false;
        store.put(&session_key(TENANT, POOL, &id), &open);
        assert_eq!(
            read(&store, &id).await,
            SessionPayoutRead::NotReady(NotReady::SessionNotEnded)
        );

        store.remove(&session_key(TENANT, POOL, &id));
        assert_eq!(
            read(&store, &id).await,
            SessionPayoutRead::NotReady(NotReady::SessionNotRecorded)
        );
    }

    /// The kernel's record decides the vault: a request naming another
    /// vault is refused rather than read under that vault.
    #[tokio::test]
    async fn another_vault_or_another_asset_is_refused() {
        let id = Uuid::from_u128(10);
        let store = store_with(&id, 5);

        assert_eq!(
            read_session_payout(&store, TENANT, POOL, OTHER_VAULT, &id)
                .await
                .expect("read"),
            SessionPayoutRead::Refused(Refusal::VaultMismatch {
                recorded: VAULT.to_string(),
                requested: OTHER_VAULT.to_string(),
            })
        );

        let mut store = store_with(&id, 5);
        store.put(
            &session_key(TENANT, POOL, &id),
            &ended_session(VAULT, "USDC"),
        );
        assert_eq!(
            read(&store, &id).await,
            SessionPayoutRead::Refused(Refusal::AssetNotTez {
                asset: "USDC".to_string(),
            })
        );
    }

    /// Only the kind `EndSession` writes is the session payout: a deposit
    /// row and, above all, a round's `RoundEndPayout` credit are refused.
    #[tokio::test]
    async fn a_row_of_another_kind_at_the_payout_key_is_refused() {
        let id = Uuid::from_u128(11);

        for (kind, name) in [
            (StoredTransactionKind::Deposit, "Deposit"),
            (StoredTransactionKind::RoundEndPayout, "RoundEndPayout"),
        ] {
            let mut store = store_with(&id, 5);
            store.put(
                &session_end_payout_key(TENANT, POOL, TEZ, &id),
                &payout_row(kind, 5),
            );
            assert_eq!(
                read(&store, &id).await,
                SessionPayoutRead::Refused(Refusal::NotASessionEndPayoutRecord {
                    kind: name.to_string(),
                })
            );
        }
    }

    #[tokio::test]
    async fn corrupt_bytes_are_refused_by_key_and_a_dead_store_is_an_error() {
        let id = Uuid::from_u128(12);
        let mut store = store_with(&id, 5);
        let key = session_end_payout_key(TENANT, POOL, TEZ, &id);
        store.put_raw(&key, &[0xff, 0xff]);

        match read(&store, &id).await {
            SessionPayoutRead::Refused(Refusal::CorruptRecord { key: at, .. }) => {
                assert_eq!(at, key);
            }
            other => panic!("expected CorruptRecord, got {other:?}"),
        }

        store.fail_reads();
        assert!(
            read_session_payout(&store, TENANT, POOL, VAULT, &id)
                .await
                .is_err()
        );
    }
}
