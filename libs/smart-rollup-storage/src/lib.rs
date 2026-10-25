//! Durable-storage borsh schemas shared between the rollup (the only **writer**)
//! and off-chain **readers** — the operator CLI's retirement/teardown gates and
//! future storage-inspection utilities — so a reader decodes rollup state from
//! one canonical definition instead of re-deriving the byte layout (which would
//! silently drift). Distinct from `smart-rollup-messages` (the sequencer → rollup
//! *wire* schema); this crate is the durable *storage* schema.
//!
//! ## Versioning
//!
//! Each stored value is wrapped in a **per-type** `XEnvelope` whose Borsh enum
//! tag (leading byte) is the schema version (`0x00` = V1). The V1 structs live
//! in [`v1`]. The layout is frozen **at mainnet origination**: before the first
//! mainnet origination writes a V1 entry there is no durable state to preserve,
//! so a layout fix lands in V1 in place; from that point on a layout change adds
//! a parallel `v2` module + a new `XEnvelope::V2(v2::X)` variant rather than
//! editing V1, so entries written by an earlier kernel keep decoding after an
//! upgrade. The per-type (not one-umbrella) split is intentional: storage
//! records are read at independent paths by independent readers and evolve
//! independently. Each envelope's leading byte is pinned by a test.
//!
//! The session, settlement, transaction and pending-seed envelopes live here;
//! any remaining rollup storage envelopes stay in the rollup crate until a
//! consumer needs them shared.
//!
//! Nineteen envelope types are defined here. [`TenantEntryEnvelope`],
//! [`PoolEntryEnvelope`] and [`VaultEntryEnvelope`] are the per-scope
//! configuration records: each scope stores **one** versioned record at one key
//! (`/tenants/{tenant}/config`, `…/pools/{pool}/config`, `…/vaults/{KT1}`), so a
//! scope's fields are written and read as a unit and a later field is an
//! envelope bump rather than a new path.
//!
//! [`HouseEquityEnvelope`] is the one money record beside those: a vault's
//! house equity at `…/equity/{KT1}` (`docs/specs/house-equity-and-sweeps.md`
//! H1), deliberately a sibling key of the vault's status record and not a
//! field on it — a hot money counter with a strict read posture next to a
//! config record with a lenient one (ADR 0021).
//!
//! [`KernelInfoEnvelope`] is the one value here that is not operator state: the
//! kernel's own version, replayable game set and dispatched administrator
//! subtags at `/kernel/info`, written by the kernel about itself.
//!
//! [`DeferredWithdrawalEnvelope`] and [`DeferredOutboxCursorEnvelope`] are the
//! kernel's deferred-withdrawal FIFO under `/outbox/deferred/` — the
//! vault outbox calls (`execute_bounce` / `execute_cemented_payout`) that did not fit a level's 100-message outbox cap
//! and wait for the next level. Fund-bearing, kernel-written, and
//! rollup-global rather than pool-scoped, because the cap they absorb is.
//!
//! [`InboxAcceptanceEnvelope`] is the kernel's per-`(tenant, pool)`
//! applied-message marker at `/tenants/{tenant}/pools/{pool}/inbox-acceptance`:
//! how many external messages the kernel admitted for the scope,
//! and from which L1 level it has been counting. Kernel-owned diagnostics like
//! [`KernelInfoEnvelope`] — written by the kernel about its own behaviour, never
//! by an admin op — and the record the reconciler diffs against the sequencer's
//! `final` outbox rows to see a message that reached L1 but was thrown away.
//!
//! [`CommittedSeedRangesEnvelope`] is the per-`(tenant, pool)` record of every
//! seed index the pool has ever accepted a commitment for, at
//! `/tenants/{tenant}/pools/{pool}/seeds/committed-ranges`. It is
//! what lets the kernel refuse a re-posted `SeedBatch` after the seeds it
//! committed have been consumed and deleted. Kernel-written safety state, so
//! the opposite corruption posture to the two diagnostics records above: an
//! undecodable record is **refused, never overwritten** — rewriting it would
//! reopen every index it had closed.
//!
//! [`SeedBeaconsEnvelope`] is the per-`(tenant, pool)` record of the drand
//! beacons the pool's stored `SeedBatch`es named — one entry per chain hash
//! with its round range and level range, at most eight — at
//! `/tenants/{tenant}/pools/{pool}/seeds/beacons`. It gates one
//! rule (a round below its hash's high-water mark is refused), but an
//! undecodable record is overwritten with an `ERROR` line rather than
//! refusing the batch in front of it: losing the record only readmits old
//! rounds, the state a fresh pool starts in.
//!
//! [`SeedUsageEnvelope`] is the per-`(tenant, pool)` tally of how those seeds
//! have been used, at `/tenants/{tenant}/pools/{pool}/seeds/usage`: how many
//! are pending, how many have been consumed or burned, and
//! the highest index spent so far. Kernel-owned diagnostics like
//! [`InboxAcceptanceEnvelope`] — the kernel settles a round against any
//! pending seed, and this record is what lets a reader see a backlog of
//! committed seeds left unused below the frontier. Logged and skipped when
//! undecodable, never refused (a transcript settles whatever state its
//! diagnostics are in) and never reset (a counter cannot be re-derived).

#![no_std]
extern crate alloc;

use alloc::string::String;
use borsh::{BorshDeserialize, BorshSerialize};

pub mod paths;
pub mod v1;

/// Versioned envelope around [`v1::StoredSession`].
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub enum StoredSessionEnvelope {
    V1(v1::StoredSession),
}

/// Versioned envelope around [`v1::SettlementEntry`].
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub enum SettlementEntryEnvelope {
    V1(v1::SettlementEntry),
}

/// Versioned envelope around [`v1::StoredTransaction`].
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub enum StoredTransactionEnvelope {
    V1(v1::StoredTransaction),
}

/// Versioned envelope around [`v1::PendingSeed`].
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub enum PendingSeedEnvelope {
    V1(v1::PendingSeed),
}

/// Versioned envelope for the byte payload stored at `/vault-routing/{KT1}`.
///
/// **Wire format is permanent storage**, not a transient message. Once
/// any rollup origination on mainnet writes a `V1` entry, the V1 variant
/// is byte-frozen forever — the kernel must keep reading historical
/// entries with their original layout (deterministic replay).
///
/// The Borsh enum tag (first byte) is the schema-version discriminant.
/// Adding/removing/renaming fields on `V1` would silently corrupt every
/// existing entry; field changes require a new `V2` variant on this enum,
/// just like `smart_rollup_messages::VersionedEnvelope` for sequencer →
/// rollup messages.
///
/// `/vault-routing/` entries are written by the `RegisterPoolVault` admin
/// subtag (`0x01`), which uses this envelope; origination seeds only the
/// rollup-global `/config/*` block, never a vault entry.
///
/// Kept as a struct-variant enum (the `(tenant_id, pool_id)` data is inline on
/// the variant, not a separate `v1::` struct) so the byte layout is provably
/// identical to the pre-move definition.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub enum VaultRoutingEnvelope {
    V1 { tenant_id: String, pool_id: String },
}

/// Per-type versioned envelope for [`v1::PreviousSequencerKey`] in durable
/// storage. Same discipline as [`VaultRoutingEnvelope`]: the Borsh enum tag
/// (leading byte) is the schema version, pinned by a test; a layout change
/// requires a new `V2` variant rather than an in-place edit.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub enum PreviousSequencerKeyEnvelope {
    V1(v1::PreviousSequencerKey),
}

/// Per-type versioned envelope for [`v1::PendingAdminContract`] in durable
/// storage. Same discipline as [`VaultRoutingEnvelope`]: the Borsh enum tag
/// (leading byte) is the schema version, pinned by a test.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub enum PendingAdminContractEnvelope {
    V1(v1::PendingAdminContract),
}

/// Per-type versioned envelope for [`v1::PoolEntry`] — the whole pool
/// configuration record stored at `/tenants/{tenant}/pools/{pool}/config`.
///
/// Status, asset and cap are one record under one key, so a reader cannot
/// observe a pool whose status and cap disagree, and a later field is a `V2`
/// variant rather than a new path. Same discipline as the others: the Borsh
/// enum tag (leading byte) is the schema version, pinned by a test plus a
/// golden-hex layout vector.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub enum PoolEntryEnvelope {
    V1(v1::PoolEntry),
}

/// Per-type versioned envelope for [`v1::VaultEntry`] — the pool-vault record
/// stored at `/tenants/{tenant}/pools/{pool}/vaults/{KT1}`.
///
/// The path is unchanged; the value stopped being a raw UTF-8 status string.
/// A vault carries only a status today, so the record has one field — the
/// envelope is what lets a second one land as `V2` instead of as a sibling key.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub enum VaultEntryEnvelope {
    V1(v1::VaultEntry),
}

/// Per-type versioned envelope for [`v1::HouseEquity`] — a vault's house
/// equity counters at `/tenants/{tenant}/pools/{pool}/equity/{KT1}`.
///
/// Money, so the kernel reads it strictly (an undecodable record is fatal,
/// like a session record: it is kernel-written, and corruption there is a
/// kernel bug rather than inbox content) and treats absence as "the vault
/// predates sweeps" (a settlement skips the update, a `Sweep` is refused).
/// Same discipline as the others otherwise: the Borsh enum tag (leading byte)
/// is the schema version, pinned by a test plus a golden-hex layout vector
/// whose four counters are each above `u64::MAX` and pairwise distinct.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub enum HouseEquityEnvelope {
    V1(v1::HouseEquity),
}

/// Per-type versioned envelope for [`v1::TenantEntry`] — the tenant
/// configuration record stored at `/tenants/{tenant}/config`.
///
/// The tenant's sequencer keys are deliberately NOT in this record: they stay
/// at `/tenants/{tenant}/sequencer-keys/{current,previous}`, so a status write
/// structurally cannot touch a value that has no on-chain recovery path.
/// Same discipline as the others: the Borsh enum tag (leading byte) is the
/// schema version, pinned by a test plus a golden-hex layout vector.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub enum TenantEntryEnvelope {
    V1(v1::TenantEntry),
}

/// Per-type versioned envelope for [`v1::KernelInfo`] — the running kernel's
/// self-description, stored at `/kernel/info`.
///
/// Version, game list and administrator-subtag list are one record so the set
/// is atomic: a reader cannot observe a new version alongside the previous
/// build's game list or dispatch table. The global
/// `/config/` block holds none of it — that block stays operator state.
///
/// Unlike every other envelope here, the value is kernel-owned diagnostics
/// rather than operator state, so an undecodable record is **overwritten** by
/// the next run instead of refused (ADR 0021 §corruption postures).
/// Same discipline as the others otherwise: the Borsh enum tag (leading byte)
/// is the schema version, pinned by a test plus a golden-hex layout vector.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub enum KernelInfoEnvelope {
    V1(v1::KernelInfo),
}

/// Per-type versioned envelope for [`v1::PendingKernelUpgrade`] in durable
/// storage. Same discipline as [`PendingAdminContractEnvelope`]: the Borsh enum
/// tag (leading byte) is the schema version, pinned by a test; a layout change
/// requires a new `V2` variant rather than an in-place edit.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub enum PendingKernelUpgradeEnvelope {
    V1(v1::PendingKernelUpgrade),
}

/// Per-type versioned envelope for [`v1::DeferredWithdrawal`] — one queued
/// vault outbox call (`execute_bounce` or `execute_cemented_payout`) at `/outbox/deferred/entries/{index}`.
///
/// Same discipline as the others: the Borsh enum tag (leading byte) is the
/// schema version, pinned by a test plus a golden-hex layout vector. The golden
/// carries an `amount_mutez` above `u32::MAX` so the 8-byte width is pinned —
/// this is the one stored amount that is deliberately `u64`, see the struct.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub enum DeferredWithdrawalEnvelope {
    V1(v1::DeferredWithdrawal),
}

/// Per-type versioned envelope for [`v1::DeferredOutboxCursor`] — the FIFO's
/// `head`/`tail` pair at `/outbox/deferred/cursor`. Same discipline as the
/// others.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub enum DeferredOutboxCursorEnvelope {
    V1(v1::DeferredOutboxCursor),
}

/// Per-type versioned envelope for [`v1::InboxAcceptance`] — the kernel's
/// per-scope applied-message marker at
/// `/tenants/{tenant}/pools/{pool}/inbox-acceptance`.
///
/// Kernel-owned diagnostics, so the same corruption posture as
/// [`KernelInfoEnvelope`]: an undecodable record is **overwritten** by the next
/// admitted message (with `since_level` reset to that level, so the restarted
/// count stays honest) rather than refused — a marker that could never be
/// rewritten would page the reconciler forever. Same discipline as the others
/// otherwise: the Borsh enum tag (leading byte) is the schema version, pinned
/// by a test plus a golden-hex layout vector.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub enum InboxAcceptanceEnvelope {
    V1(v1::InboxAcceptance),
}

/// Per-type versioned envelope for [`v1::CommittedSeedRanges`] — the runs of
/// seed indices a pool has ever accepted a commitment for, at
/// `/tenants/{tenant}/pools/{pool}/seeds/committed-ranges`.
///
/// Safety state, not diagnostics: the kernel refuses a `SeedBatch` whose
/// record it cannot decode and leaves the bytes as found, because overwriting
/// them would make every index the record had closed committable again. Same
/// discipline as the others otherwise: the Borsh enum tag (leading byte) is
/// the schema version, pinned by a test plus a golden-hex layout vector.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub enum CommittedSeedRangesEnvelope {
    V1(v1::CommittedSeedRanges),
}

/// Per-type versioned envelope for [`v1::SeedBeacons`] — the per-chain-hash
/// drand beacon claims of the `SeedBatch`es a pool stored, at
/// `/tenants/{tenant}/pools/{pool}/seeds/beacons`.
///
/// Overwritten, not refused, when undecodable (logging `ERROR`) — the
/// [`KernelInfoEnvelope`] posture, and the opposite of
/// [`CommittedSeedRangesEnvelope`]'s: a lost record only readmits rounds the
/// round rule would have refused, while refusing every batch behind it would
/// starve the pool. Same discipline otherwise: the Borsh enum tag (leading
/// byte) is the schema version, pinned by a test plus a golden-hex layout
/// vector.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub enum SeedBeaconsEnvelope {
    V1(v1::SeedBeacons),
}

/// Per-type versioned envelope for [`v1::SeedUsage`] — the kernel's tally of
/// a pool's pending, consumed and highest-consumed seed indices, at
/// `/tenants/{tenant}/pools/{pool}/seeds/usage`.
///
/// Diagnostics, not safety state: nothing gates on it, so the kernel logs and
/// skips an undecodable record rather than refusing the message in front of
/// it. Unlike the other diagnostics records it is also never overwritten with
/// a fresh one — `pending_count` cannot be re-derived without walking every
/// pending leaf. Same discipline as the others otherwise: the Borsh enum tag
/// (leading byte) is the schema version, pinned by a test plus a golden-hex
/// layout vector.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub enum SeedUsageEnvelope {
    V1(v1::SeedUsage),
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use alloc::vec;

    // Every golden sample below carries at least one amount ABOVE `u64::MAX`.
    // That is load-bearing, not decoration: a small `u128` value's 16-byte
    // little-endian form is the 8-byte one followed by eight zero bytes, so a
    // decoder that still reads 8 bytes would pass a small-value golden and
    // silently drop the high half. Each constant is guarded by a compile-time
    // assertion, so shrinking one below `u64::MAX` breaks the build rather
    // than quietly weakening the vector.
    const SESSION_BALANCE: u128 = 0x090a_0b0c_0d0e_0f10_0102_0304_0506_0708;
    const SETTLEMENT_STAKE: u128 = 0x1213_1415_1617_1819_0a0b_0c0d_0e0f_1011;
    const SETTLEMENT_PAYOUT: u128 = 0x2a2b_2c2d_2e2f_3031_2223_2425_2627_2829;
    const DISCREPANCY_CLAIMED_PAYOUT: u128 = 0x3839_3a3b_3c3d_3e3f_3031_3233_3435_3637;
    const DISCREPANCY_COMPUTED_PAYOUT: u128 = 0x4849_4a4b_4c4d_4e4f_4041_4243_4445_4647;
    const CLAMP_CAP: u128 = 0xd1d2_d3d4_d5d6_d7d8_e1e2_e3e4_e5e6_e7e8;
    const CLAMP_STAKE: u128 = 0xc1c2_c3c4_c5c6_c7c8_f1f2_f3f4_f5f6_f7f8;
    const CLAMP_BANKED: u128 = 0x1222_3242_5262_7282_1121_3141_5161_7181;
    const CLAMP_ORIGINAL_LIVE: u128 = 0x1323_3343_5363_7383_2232_4252_6272_8292;
    const CLAMP_CLAMPED_LIVE: u128 = 0x1424_3444_5464_7484_3343_5363_7383_93a3;
    const TRANSACTION_AMOUNT: u128 = 0x5859_5a5b_5c5d_5e5f_5051_5253_5455_5657;
    const POOL_MAX_WIN: u128 = 0x6162_6364_6566_6768_7172_7374_7576_7778;
    const EQUITY_FUNDED: u128 = 0x8182_8384_8586_8788_9192_9394_9596_9798;
    const EQUITY_STAKES: u128 = 0x9a9b_9c9d_9e9f_a0a1_a2a3_a4a5_a6a7_a8a9;
    const EQUITY_PAYOUTS: u128 = 0xb1b2_b3b4_b5b6_b7b8_c1c2_c3c4_c5c6_c7c8;
    const EQUITY_SWEPT: u128 = 0xd9da_dbdc_dddf_e0e1_e2e3_e4e5_e6e7_e8e9;

    const _: () = assert!(SESSION_BALANCE > u64::MAX as u128);
    const _: () = assert!(SETTLEMENT_STAKE > u64::MAX as u128);
    const _: () = assert!(SETTLEMENT_PAYOUT > u64::MAX as u128);
    const _: () = assert!(DISCREPANCY_CLAIMED_PAYOUT > u64::MAX as u128);
    const _: () = assert!(DISCREPANCY_COMPUTED_PAYOUT > u64::MAX as u128);
    const _: () = assert!(CLAMP_CAP > u64::MAX as u128);
    const _: () = assert!(CLAMP_STAKE > u64::MAX as u128);
    const _: () = assert!(CLAMP_BANKED > u64::MAX as u128);
    const _: () = assert!(CLAMP_ORIGINAL_LIVE > u64::MAX as u128);
    const _: () = assert!(CLAMP_CLAMPED_LIVE > u64::MAX as u128);
    const _: () = assert!(TRANSACTION_AMOUNT > u64::MAX as u128);
    const _: () = assert!(POOL_MAX_WIN > u64::MAX as u128);
    const _: () = assert!(EQUITY_FUNDED > u64::MAX as u128);
    const _: () = assert!(EQUITY_STAKES > u64::MAX as u128);
    const _: () = assert!(EQUITY_PAYOUTS > u64::MAX as u128);
    const _: () = assert!(EQUITY_SWEPT > u64::MAX as u128);
    // Pairwise distinct, so a swapped pair of counters fails the golden.
    const _: () = assert!(EQUITY_FUNDED != EQUITY_STAKES);
    const _: () = assert!(EQUITY_STAKES != EQUITY_PAYOUTS);
    const _: () = assert!(EQUITY_PAYOUTS != EQUITY_SWEPT);
    const _: () = assert!(EQUITY_FUNDED != EQUITY_SWEPT);

    fn sample_stored_session() -> v1::StoredSession {
        v1::StoredSession {
            owner: "tz1owner".to_string(),
            asset: "TEZ".to_string(),
            balance: SESSION_BALANCE,
            funding_vault_address: "KT1vault".to_string(),
            ended: true,
            end_reason: Some("user-requested".to_string()),
        }
    }

    /// A distinct ascending run `0xa0..=0xbf`, which appears nowhere else in
    /// the golden vector — neither the amount patterns (`0x0a..0x4f`) nor the
    /// clamp's (`0xc1..0xf8`, and the strided `0x11..0xa3`) reach it. A
    /// zero-filled or repeated commitment would encode identically however it
    /// were spliced, so it could not pin the field's offset.
    const SETTLEMENT_PLAYER_COMMITMENT: [u8; 32] = [
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae,
        0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd,
        0xbe, 0xbf,
    ];

    fn sample_settlement_entry() -> v1::SettlementEntry {
        v1::SettlementEntry {
            session_id: "sess-id".to_string(),
            player: "tz1player".to_string(),
            game_type: "plinko:v1".to_string(),
            asset: "TEZ".to_string(),
            stake: SETTLEMENT_STAKE,
            payout: SETTLEMENT_PAYOUT,
            outcome: "win".to_string(),
            validated: true,
            player_commitment: SETTLEMENT_PLAYER_COMMITMENT,
            discrepancy: Some(sample_discrepancy()),
            clamp: Some(sample_max_win_clamp()),
        }
    }

    fn sample_discrepancy() -> v1::Discrepancy {
        v1::Discrepancy {
            claimed_payout: DISCREPANCY_CLAIMED_PAYOUT,
            computed_payout: DISCREPANCY_COMPUTED_PAYOUT,
            computed_outcome: "lose".to_string(),
            reason: "payout-mismatch".to_string(),
        }
    }

    fn sample_max_win_clamp() -> v1::MaxWinClamp {
        v1::MaxWinClamp {
            cap: CLAMP_CAP,
            stake: CLAMP_STAKE,
            banked: CLAMP_BANKED,
            original_live: CLAMP_ORIGINAL_LIVE,
            clamped_live: CLAMP_CLAMPED_LIVE,
        }
    }

    fn sample_stored_transaction() -> v1::StoredTransaction {
        v1::StoredTransaction {
            account_address: "tz1acct".to_string(),
            asset: "TEZ".to_string(),
            // Payout is variant index 3 → non-zero enum tag, so a reorder of the
            // kind enum is also caught by the golden vector.
            kind: v1::StoredTransactionKind::RoundEndPayout,
            amount: TRANSACTION_AMOUNT,
        }
    }

    fn sample_pending_seed() -> v1::PendingSeed {
        v1::PendingSeed {
            hash: [
                0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e,
                0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c,
                0x9d, 0x9e, 0x9f, 0xa0,
            ],
            commitment_level: 0xb1b2_b3b4,
        }
    }

    fn sample_previous_sequencer_key() -> v1::PreviousSequencerKey {
        v1::PreviousSequencerKey {
            public_key: vec![0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6],
            valid_until_level: 0xd1d2_d3d4,
        }
    }

    fn sample_pending_admin_contract() -> v1::PendingAdminContract {
        v1::PendingAdminContract {
            new_admin: "KT1admin".to_string(),
            activate_at_level: 0xe1e2_e3e4,
        }
    }

    fn sample_pending_kernel_upgrade() -> v1::PendingKernelUpgrade {
        v1::PendingKernelUpgrade {
            // 33 distinct non-zero bytes (0x01..=0x21) so a field reorder or a
            // width drift is caught by the golden-hex vector below.
            root_hash: [
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
                0x1d, 0x1e, 0x1f, 0x20, 0x21,
            ],
            activate_at_level: 0x1122_3344,
        }
    }

    fn sample_pool_entry() -> v1::PoolEntry {
        v1::PoolEntry {
            // Not `"active"`: a status that is nobody's default is what makes a
            // decoder that hands back a hardcoded status fail the golden.
            status: "draining".to_string(),
            asset: "TEZ".to_string(),
            max_win: POOL_MAX_WIN,
        }
    }

    fn sample_tenant_entry() -> v1::TenantEntry {
        v1::TenantEntry {
            // Not `"active"` (nobody's default) and a different length from
            // BOTH `sample_pool_entry` (`"draining"`) and `sample_vault_entry`
            // (`"deprecated"`), so no two of the three status-record golden
            // vectors can pass each other's bytes. `"paused"` is a legal tenant
            // status; `"draining"` is not.
            status: "paused".to_string(),
        }
    }

    fn sample_kernel_info() -> v1::KernelInfo {
        // Distinct from every other golden's values, and the two game strings
        // have DIFFERENT lengths so the `Vec` length prefix and each element's
        // own length prefix are each pinned separately — a swap of the two
        // elements, or a `Vec` that silently lost its count, changes the bytes.
        // The subtags are three bytes out of ascending order, so their count,
        // stride and order are pinned too — a sorted or deduplicated rewrite
        // changes the bytes.
        v1::KernelInfo {
            version: "4.2.1".to_string(),
            supported_games: vec!["hilo:v1".to_string(), "plinko:v1".to_string()],
            admin_subtags: vec![0x0D, 0x02, 0x7F],
        }
    }

    fn sample_house_equity() -> v1::HouseEquity {
        v1::HouseEquity {
            funded: EQUITY_FUNDED,
            stakes: EQUITY_STAKES,
            payouts: EQUITY_PAYOUTS,
            swept: EQUITY_SWEPT,
        }
    }

    fn sample_vault_entry() -> v1::VaultEntry {
        v1::VaultEntry {
            // Deliberately different from `sample_pool_entry`'s status, and a
            // different length, so neither golden vector can pass the other's
            // bytes.
            status: "deprecated".to_string(),
        }
    }

    // --- StoredSession -----------------------------------------------------

    #[test]
    fn stored_session_envelope_v1_leading_byte_is_zero() {
        let encoded = borsh::to_vec(&StoredSessionEnvelope::V1(sample_stored_session())).unwrap();

        assert_eq!(encoded[0], 0x00, "V1 must encode as enum tag 0x00");
    }

    #[test]
    fn stored_session_envelope_v1_golden_hex_layout() {
        // DO NOT EDIT — V1 layout, frozen at mainnet origination. Field order/width:
        // tag 0x00, owner (len-prefixed String), asset, balance
        // (u128 LE atomic units), funding_vault_address,
        // ended:bool, end_reason:Option<String>.
        let expected: vec::Vec<u8> = vec![
            0x00, 0x08, 0x00, 0x00, 0x00, 0x74, 0x7a, 0x31, 0x6f, 0x77, 0x6e, 0x65, 0x72, 0x03,
            0x00, 0x00, 0x00, 0x54, 0x45, 0x5a, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
            0x10, 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x00, 0x00, 0x00, 0x4b, 0x54,
            0x31, 0x76, 0x61, 0x75, 0x6c, 0x74, 0x01, 0x01, 0x0e, 0x00, 0x00, 0x00, 0x75, 0x73,
            0x65, 0x72, 0x2d, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x65, 0x64,
        ];
        let encoded = borsh::to_vec(&StoredSessionEnvelope::V1(sample_stored_session())).unwrap();

        assert_eq!(encoded, expected, "V1 byte layout drifted");
    }

    #[test]
    fn stored_session_envelope_round_trip() {
        let value = sample_stored_session();
        let encoded = borsh::to_vec(&StoredSessionEnvelope::V1(value.clone())).unwrap();
        let decoded = StoredSessionEnvelope::try_from_slice(&encoded).unwrap();

        assert_eq!(decoded, StoredSessionEnvelope::V1(value));
    }

    // --- SettlementEntry ---------------------------------------------------

    #[test]
    fn settlement_entry_envelope_v1_leading_byte_is_zero() {
        let encoded =
            borsh::to_vec(&SettlementEntryEnvelope::V1(sample_settlement_entry())).unwrap();

        assert_eq!(encoded[0], 0x00, "V1 must encode as enum tag 0x00");
    }

    #[test]
    fn settlement_entry_envelope_v1_golden_hex_layout() {
        // DO NOT EDIT — V1 layout, frozen at mainnet origination. Field order/width:
        // tag 0x00, session_id, player, game_type, asset (Strings), stake,
        // payout (u128 LE each), outcome (String), validated:bool,
        // player_commitment: [u8; 32] (raw, no length prefix),
        // discrepancy:Option<Discrepancy> (0x01 tag, then claimed_payout,
        // computed_payout as u128 LE each, computed_outcome, reason as Strings),
        // clamp:Option<MaxWinClamp> (0x01 tag, then cap, stake, banked,
        // original_live, clamped_live as u128 LE each).
        let expected: vec::Vec<u8> = vec![
            0x00, 0x07, 0x00, 0x00, 0x00, 0x73, 0x65, 0x73, 0x73, 0x2d, 0x69, 0x64, 0x09, 0x00,
            0x00, 0x00, 0x74, 0x7a, 0x31, 0x70, 0x6c, 0x61, 0x79, 0x65, 0x72, 0x09, 0x00, 0x00,
            0x00, 0x70, 0x6c, 0x69, 0x6e, 0x6b, 0x6f, 0x3a, 0x76, 0x31, 0x03, 0x00, 0x00, 0x00,
            0x54, 0x45, 0x5a, 0x11, 0x10, 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x19, 0x18, 0x17,
            0x16, 0x15, 0x14, 0x13, 0x12, 0x29, 0x28, 0x27, 0x26, 0x25, 0x24, 0x23, 0x22, 0x31,
            0x30, 0x2f, 0x2e, 0x2d, 0x2c, 0x2b, 0x2a, 0x03, 0x00, 0x00, 0x00, 0x77, 0x69, 0x6e,
            0x01, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac,
            0xad, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba,
            0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0x01, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0x30,
            0x3f, 0x3e, 0x3d, 0x3c, 0x3b, 0x3a, 0x39, 0x38, 0x47, 0x46, 0x45, 0x44, 0x43, 0x42,
            0x41, 0x40, 0x4f, 0x4e, 0x4d, 0x4c, 0x4b, 0x4a, 0x49, 0x48, 0x04, 0x00, 0x00, 0x00,
            0x6c, 0x6f, 0x73, 0x65, 0x0f, 0x00, 0x00, 0x00, 0x70, 0x61, 0x79, 0x6f, 0x75, 0x74,
            0x2d, 0x6d, 0x69, 0x73, 0x6d, 0x61, 0x74, 0x63, 0x68, 0x01, 0xe8, 0xe7, 0xe6, 0xe5,
            0xe4, 0xe3, 0xe2, 0xe1, 0xd8, 0xd7, 0xd6, 0xd5, 0xd4, 0xd3, 0xd2, 0xd1, 0xf8, 0xf7,
            0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xc8, 0xc7, 0xc6, 0xc5, 0xc4, 0xc3, 0xc2, 0xc1,
            0x81, 0x71, 0x61, 0x51, 0x41, 0x31, 0x21, 0x11, 0x82, 0x72, 0x62, 0x52, 0x42, 0x32,
            0x22, 0x12, 0x92, 0x82, 0x72, 0x62, 0x52, 0x42, 0x32, 0x22, 0x83, 0x73, 0x63, 0x53,
            0x43, 0x33, 0x23, 0x13, 0xa3, 0x93, 0x83, 0x73, 0x63, 0x53, 0x43, 0x33, 0x84, 0x74,
            0x64, 0x54, 0x44, 0x34, 0x24, 0x14,
        ];
        let encoded =
            borsh::to_vec(&SettlementEntryEnvelope::V1(sample_settlement_entry())).unwrap();

        assert_eq!(encoded, expected, "V1 byte layout drifted");

        // 258 = 85  the pre-fold V1 record (1 tag + 11 session_id + 13 player
        //           + 13 game_type + 7 asset + 16 stake + 16 payout + 7 outcome
        //           + 1 validated)
        //     + 32  player_commitment, spliced in at offset 85 — immediately
        //           after `validated` and ahead of the discrepancy Option tag
        //     +  1  discrepancy: Some
        //     + 59  Discrepancy without `asset` (16 claimed + 16 computed
        //           + 8 "lose" + 19 "payout-mismatch")
        //     +  1  clamp: Some
        //     + 80  MaxWinClamp without `asset` (5 x 16)
        assert_eq!(encoded.len(), 258, "V1 encoded length drifted");

        // The nested discrepancy is really in there: the length-prefixed
        // `"payout-mismatch"` reason string occurs exactly once. A "both
        // `Option` tags are 0x01 0x01" check would prove nothing — 0x01 is
        // also `validated`'s value and a byte of `SETTLEMENT_STAKE`, so it can
        // match by accident. The reason string cannot.
        let reason_run: &[u8] = b"\x0f\x00\x00\x00payout-mismatch";
        assert_eq!(
            encoded
                .windows(reason_run.len())
                .filter(|w| *w == reason_run)
                .count(),
            1,
            "nested discrepancy reason must appear exactly once",
        );
    }

    #[test]
    fn settlement_entry_envelope_round_trip() {
        let value = sample_settlement_entry();
        let encoded = borsh::to_vec(&SettlementEntryEnvelope::V1(value.clone())).unwrap();
        let decoded = SettlementEntryEnvelope::try_from_slice(&encoded).unwrap();

        assert_eq!(decoded, SettlementEntryEnvelope::V1(value));
    }

    /// Both `Option`s absent is the common case — an honest round with no
    /// divergence and no clamp — and it must round-trip as cleanly as the
    /// both-`Some` golden. Borsh writes a single `0x00` tag per absent option;
    /// this test is what proves the reader does not mistake the two trailing
    /// zero bytes for a truncated struct.
    #[test]
    fn settlement_entry_envelope_round_trip_with_neither_option() {
        let mut value = sample_settlement_entry();
        value.discrepancy = None;
        value.clamp = None;

        let encoded = borsh::to_vec(&SettlementEntryEnvelope::V1(value.clone())).unwrap();
        let decoded = SettlementEntryEnvelope::try_from_slice(&encoded).unwrap();

        assert_eq!(decoded, SettlementEntryEnvelope::V1(value));
        assert_eq!(
            encoded[encoded.len() - 2..],
            [0x00, 0x00],
            "absent options are two 0x00 tags"
        );
    }

    // --- StoredTransaction -------------------------------------------------

    #[test]
    fn stored_transaction_envelope_v1_leading_byte_is_zero() {
        let encoded =
            borsh::to_vec(&StoredTransactionEnvelope::V1(sample_stored_transaction())).unwrap();

        assert_eq!(encoded[0], 0x00, "V1 must encode as enum tag 0x00");
    }

    #[test]
    fn stored_transaction_envelope_v1_golden_hex_layout() {
        // DO NOT EDIT — V1 layout, frozen at mainnet origination. Field order/width:
        // tag 0x00, account_address, asset (Strings), kind
        // (StoredTransactionKind enum tag: RoundEndPayout = 0x03), amount (u128 LE).
        let expected: vec::Vec<u8> = vec![
            0x00, 0x07, 0x00, 0x00, 0x00, 0x74, 0x7a, 0x31, 0x61, 0x63, 0x63, 0x74, 0x03, 0x00,
            0x00, 0x00, 0x54, 0x45, 0x5a, 0x03, 0x57, 0x56, 0x55, 0x54, 0x53, 0x52, 0x51, 0x50,
            0x5f, 0x5e, 0x5d, 0x5c, 0x5b, 0x5a, 0x59, 0x58,
        ];
        let encoded =
            borsh::to_vec(&StoredTransactionEnvelope::V1(sample_stored_transaction())).unwrap();

        assert_eq!(encoded, expected, "V1 byte layout drifted");
    }

    #[test]
    fn stored_transaction_envelope_round_trip() {
        let value = sample_stored_transaction();
        let encoded = borsh::to_vec(&StoredTransactionEnvelope::V1(value.clone())).unwrap();
        let decoded = StoredTransactionEnvelope::try_from_slice(&encoded).unwrap();

        assert_eq!(decoded, StoredTransactionEnvelope::V1(value));
    }

    /// The kind enum's borsh tags are the ledger's vocabulary on chain: a
    /// reorder would relabel every row ever written. `Fund` and `Sweep` were
    /// appended (`docs/specs/house-equity-and-sweeps.md`); anything later
    /// appends after `Sweep`.
    #[test]
    fn stored_transaction_kind_tags_are_frozen() {
        use v1::StoredTransactionKind as K;

        for (kind, tag) in [
            (K::Deposit, 0x00),
            (K::SessionEndPayout, 0x01),
            (K::Stake, 0x02),
            (K::RoundEndPayout, 0x03),
            (K::Fund, 0x04),
            (K::Sweep, 0x05),
        ] {
            assert_eq!(borsh::to_vec(&kind).unwrap(), [tag], "{kind:?}");
        }
    }

    // --- HouseEquity -------------------------------------------------------

    #[test]
    fn house_equity_envelope_v1_leading_byte_is_zero() {
        let encoded = borsh::to_vec(&HouseEquityEnvelope::V1(sample_house_equity())).unwrap();

        assert_eq!(encoded[0], 0x00, "V1 must encode as enum tag 0x00");
    }

    #[test]
    fn house_equity_envelope_v1_golden_hex_layout() {
        // DO NOT EDIT — V1 layout, frozen at mainnet origination. Field order/width:
        // tag 0x00, funded, stakes, payouts, swept (each a u128 LE). Every
        // counter is above u64::MAX and pairwise distinct, so a width drift or
        // a swapped pair fails the golden.
        let expected: vec::Vec<u8> = vec![
            0x00, // envelope tag: V1
            0x98, 0x97, 0x96, 0x95, 0x94, 0x93, 0x92, 0x91, 0x88, 0x87, 0x86, 0x85, 0x84, 0x83,
            0x82, 0x81, // funded LE
            0xa9, 0xa8, 0xa7, 0xa6, 0xa5, 0xa4, 0xa3, 0xa2, 0xa1, 0xa0, 0x9f, 0x9e, 0x9d, 0x9c,
            0x9b, 0x9a, // stakes LE
            0xc8, 0xc7, 0xc6, 0xc5, 0xc4, 0xc3, 0xc2, 0xc1, 0xb8, 0xb7, 0xb6, 0xb5, 0xb4, 0xb3,
            0xb2, 0xb1, // payouts LE
            0xe9, 0xe8, 0xe7, 0xe6, 0xe5, 0xe4, 0xe3, 0xe2, 0xe1, 0xe0, 0xdf, 0xdd, 0xdc, 0xdb,
            0xda, 0xd9, // swept LE
        ];
        let encoded = borsh::to_vec(&HouseEquityEnvelope::V1(sample_house_equity())).unwrap();

        assert_eq!(encoded, expected, "V1 byte layout drifted");
        assert_eq!(encoded.len(), 1 + 4 * 16, "V1 encoded length drifted");
    }

    #[test]
    fn house_equity_envelope_round_trip() {
        let value = sample_house_equity();
        let encoded = borsh::to_vec(&HouseEquityEnvelope::V1(value)).unwrap();
        let decoded = HouseEquityEnvelope::try_from_slice(&encoded).unwrap();

        assert_eq!(decoded, HouseEquityEnvelope::V1(value));
    }

    /// A fresh record is all zeros — what `RegisterPoolVault` writes — and the
    /// `Default` the kernel creates it from says so.
    #[test]
    fn house_equity_default_is_the_zero_record() {
        assert_eq!(
            v1::HouseEquity::default(),
            v1::HouseEquity {
                funded: 0,
                stakes: 0,
                payouts: 0,
                swept: 0
            }
        );
    }

    // --- PendingSeed -------------------------------------------------------

    #[test]
    fn pending_seed_envelope_v1_leading_byte_is_zero() {
        let encoded = borsh::to_vec(&PendingSeedEnvelope::V1(sample_pending_seed())).unwrap();

        assert_eq!(encoded[0], 0x00, "V1 must encode as enum tag 0x00");
    }

    #[test]
    fn pending_seed_envelope_v1_golden_hex_layout() {
        // DO NOT EDIT — V1 layout, frozen at mainnet origination. Field order/width:
        // tag 0x00, hash:[u8;32], commitment_level:u32 LE.
        let expected: vec::Vec<u8> = vec![
            0x00, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d,
            0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
            0x9c, 0x9d, 0x9e, 0x9f, 0xa0, 0xb4, 0xb3, 0xb2, 0xb1,
        ];
        let encoded = borsh::to_vec(&PendingSeedEnvelope::V1(sample_pending_seed())).unwrap();

        assert_eq!(encoded, expected, "V1 byte layout drifted");
    }

    #[test]
    fn pending_seed_envelope_round_trip() {
        let value = sample_pending_seed();
        let encoded = borsh::to_vec(&PendingSeedEnvelope::V1(value.clone())).unwrap();
        let decoded = PendingSeedEnvelope::try_from_slice(&encoded).unwrap();

        assert_eq!(decoded, PendingSeedEnvelope::V1(value));
    }

    // --- VaultRoutingEnvelope ----------------------------------------------

    fn sample_vault_routing() -> VaultRoutingEnvelope {
        VaultRoutingEnvelope::V1 {
            tenant_id: "99dot5-com-shadownet".to_string(),
            pool_id: "main".to_string(),
        }
    }

    #[test]
    fn vault_routing_envelope_v1_leading_byte_is_zero() {
        let encoded = borsh::to_vec(&sample_vault_routing()).unwrap();

        assert_eq!(encoded[0], 0x00, "V1 must encode as enum tag 0x00");
    }

    #[test]
    fn vault_routing_envelope_v1_golden_hex_layout() {
        // DO NOT EDIT — V1 layout, frozen at mainnet origination. Field order/width:
        // tag 0x00, tenant_id (String), pool_id (String).
        let expected: vec::Vec<u8> = vec![
            0x00, 0x14, 0x00, 0x00, 0x00, 0x39, 0x39, 0x64, 0x6f, 0x74, 0x35, 0x2d, 0x63, 0x6f,
            0x6d, 0x2d, 0x73, 0x68, 0x61, 0x64, 0x6f, 0x77, 0x6e, 0x65, 0x74, 0x04, 0x00, 0x00,
            0x00, 0x6d, 0x61, 0x69, 0x6e,
        ];
        let encoded = borsh::to_vec(&sample_vault_routing()).unwrap();

        assert_eq!(encoded, expected, "V1 byte layout drifted");
    }

    #[test]
    fn vault_routing_envelope_round_trip() {
        let value = sample_vault_routing();
        let encoded = borsh::to_vec(&value).unwrap();
        let decoded = VaultRoutingEnvelope::try_from_slice(&encoded).unwrap();

        assert_eq!(decoded, value);
    }

    // --- PreviousSequencerKey ----------------------------------------------

    #[test]
    fn previous_sequencer_key_envelope_v1_leading_byte_is_zero() {
        let encoded = borsh::to_vec(&PreviousSequencerKeyEnvelope::V1(
            sample_previous_sequencer_key(),
        ))
        .unwrap();

        assert_eq!(encoded[0], 0x00, "V1 must encode as enum tag 0x00");
    }

    #[test]
    fn previous_sequencer_key_envelope_v1_golden_hex_layout() {
        // DO NOT EDIT — V1 layout, frozen at mainnet origination. Field order/width:
        // tag 0x00, public_key (len-prefixed Vec<u8>), valid_until_level:u32 LE.
        let expected: vec::Vec<u8> = vec![
            0x00, 0x06, 0x00, 0x00, 0x00, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xd4, 0xd3, 0xd2,
            0xd1,
        ];
        let encoded = borsh::to_vec(&PreviousSequencerKeyEnvelope::V1(
            sample_previous_sequencer_key(),
        ))
        .unwrap();

        assert_eq!(encoded, expected, "V1 byte layout drifted");
    }

    #[test]
    fn previous_sequencer_key_envelope_round_trip() {
        let value = sample_previous_sequencer_key();
        let encoded = borsh::to_vec(&PreviousSequencerKeyEnvelope::V1(value.clone())).unwrap();
        let decoded = PreviousSequencerKeyEnvelope::try_from_slice(&encoded).unwrap();

        assert_eq!(decoded, PreviousSequencerKeyEnvelope::V1(value));
    }

    // --- PendingAdminContract ----------------------------------------------

    #[test]
    fn pending_admin_contract_envelope_v1_leading_byte_is_zero() {
        let encoded = borsh::to_vec(&PendingAdminContractEnvelope::V1(
            sample_pending_admin_contract(),
        ))
        .unwrap();

        assert_eq!(encoded[0], 0x00, "V1 must encode as enum tag 0x00");
    }

    #[test]
    fn pending_admin_contract_envelope_v1_golden_hex_layout() {
        // DO NOT EDIT — V1 layout, frozen at mainnet origination. Field order/width:
        // tag 0x00, new_admin (String), activate_at_level:u32 LE.
        let expected: vec::Vec<u8> = vec![
            0x00, 0x08, 0x00, 0x00, 0x00, 0x4b, 0x54, 0x31, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0xe4,
            0xe3, 0xe2, 0xe1,
        ];
        let encoded = borsh::to_vec(&PendingAdminContractEnvelope::V1(
            sample_pending_admin_contract(),
        ))
        .unwrap();

        assert_eq!(encoded, expected, "V1 byte layout drifted");
    }

    #[test]
    fn pending_admin_contract_envelope_round_trip() {
        let value = sample_pending_admin_contract();
        let encoded = borsh::to_vec(&PendingAdminContractEnvelope::V1(value.clone())).unwrap();
        let decoded = PendingAdminContractEnvelope::try_from_slice(&encoded).unwrap();

        assert_eq!(decoded, PendingAdminContractEnvelope::V1(value));
    }

    // --- PendingKernelUpgrade (Phase 1 exemplar) ---------------------------

    #[test]
    fn pending_kernel_upgrade_envelope_v1_leading_byte_is_zero() {
        // Pinned wire shape: V1 entries MUST encode with `0x00` as the first
        // byte (Borsh enum tag for the first variant). Drift here would silently
        // invalidate every `/config/kernel-upgrade/pending` entry written by an
        // earlier kernel after a deploy.
        let encoded = borsh::to_vec(&PendingKernelUpgradeEnvelope::V1(
            sample_pending_kernel_upgrade(),
        ))
        .unwrap();

        assert_eq!(encoded[0], 0x00, "V1 must encode as enum tag 0x00");
    }

    #[test]
    fn pending_kernel_upgrade_envelope_v1_golden_hex_layout() {
        // DO NOT EDIT — V1 layout, frozen at mainnet origination. Freezes field order/width:
        // enum tag `0x00`, then `root_hash: [u8; 33]` as 33 raw bytes, then
        // `activate_at_level: u32` little-endian. The leading-byte test alone
        // only pins the enum tag; this pins the full struct layout.
        let expected: vec::Vec<u8> = vec![
            0x00, // enum tag: V1
            // root_hash: [u8; 33] (0x01..=0x21)
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20, 0x21, //
            0x44, 0x33, 0x22, 0x11, // activate_at_level: 0x11223344 LE
        ];
        let encoded = borsh::to_vec(&PendingKernelUpgradeEnvelope::V1(
            sample_pending_kernel_upgrade(),
        ))
        .unwrap();

        assert_eq!(encoded, expected, "V1 byte layout drifted");
    }

    #[test]
    fn pending_kernel_upgrade_envelope_round_trip() {
        let value = sample_pending_kernel_upgrade();
        let encoded = borsh::to_vec(&PendingKernelUpgradeEnvelope::V1(value.clone())).unwrap();
        let decoded = PendingKernelUpgradeEnvelope::try_from_slice(&encoded).unwrap();

        assert_eq!(decoded, PendingKernelUpgradeEnvelope::V1(value));
    }

    // --- PoolEntry ---------------------------------------------------------

    #[test]
    fn pool_entry_envelope_v1_leading_byte_is_zero() {
        let encoded = borsh::to_vec(&PoolEntryEnvelope::V1(sample_pool_entry())).unwrap();

        assert_eq!(encoded[0], 0x00, "V1 must encode as enum tag 0x00");
    }

    #[test]
    fn pool_entry_envelope_v1_golden_hex_layout() {
        // DO NOT EDIT — V1 layout, frozen at mainnet origination. Field order/width:
        // tag 0x00, status (len-prefixed String, FIELD 0), asset
        // (len-prefixed String), max_win (u128 LE atomic units). The cap is
        // above `u64::MAX`, so an 8-byte decoder cannot pass this vector.
        let expected: vec::Vec<u8> = vec![
            0x00, 0x08, 0x00, 0x00, 0x00, 0x64, 0x72, 0x61, 0x69, 0x6e, 0x69, 0x6e, 0x67, 0x03,
            0x00, 0x00, 0x00, 0x54, 0x45, 0x5a, 0x78, 0x77, 0x76, 0x75, 0x74, 0x73, 0x72, 0x71,
            0x68, 0x67, 0x66, 0x65, 0x64, 0x63, 0x62, 0x61,
        ];
        let encoded = borsh::to_vec(&PoolEntryEnvelope::V1(sample_pool_entry())).unwrap();

        assert_eq!(encoded, expected, "V1 byte layout drifted");
    }

    /// `status` is field 0 (design §3), so a reader that has only the first
    /// bytes of the value sees `tag 0x00 | u32 LE length | status bytes` and
    /// nothing else in front of it. The golden vector above would also fail on
    /// a reorder, but it fails on *any* drift; this test states the positional
    /// claim on its own so the reason survives the next layout edit.
    #[test]
    fn pool_entry_v1_status_is_field_zero() {
        let value = sample_pool_entry();
        let encoded = borsh::to_vec(&PoolEntryEnvelope::V1(value.clone())).unwrap();
        let len = value.status.len();

        assert_eq!(encoded[0], 0x00, "V1 must encode as enum tag 0x00");
        assert_eq!(
            encoded[1..5],
            (len as u32).to_le_bytes(),
            "status length prefix must follow the envelope tag"
        );
        assert_eq!(
            &encoded[5..5 + len],
            value.status.as_bytes(),
            "status bytes must be field 0"
        );
    }

    #[test]
    fn pool_entry_envelope_round_trip() {
        let value = sample_pool_entry();
        let encoded = borsh::to_vec(&PoolEntryEnvelope::V1(value.clone())).unwrap();
        let decoded = PoolEntryEnvelope::try_from_slice(&encoded).unwrap();

        assert_eq!(decoded, PoolEntryEnvelope::V1(value));
    }

    // --- VaultEntry --------------------------------------------------------

    #[test]
    fn vault_entry_envelope_v1_leading_byte_is_zero() {
        let encoded = borsh::to_vec(&VaultEntryEnvelope::V1(sample_vault_entry())).unwrap();

        assert_eq!(encoded[0], 0x00, "V1 must encode as enum tag 0x00");
    }

    #[test]
    fn vault_entry_envelope_v1_golden_hex_layout() {
        // DO NOT EDIT — V1 layout, frozen at mainnet origination. Field order/width:
        // tag 0x00, status (len-prefixed String, FIELD 0). The status differs
        // from `PoolEntry`'s so the two goldens cannot pass each other's bytes.
        let expected: vec::Vec<u8> = vec![
            0x00, 0x0a, 0x00, 0x00, 0x00, 0x64, 0x65, 0x70, 0x72, 0x65, 0x63, 0x61, 0x74, 0x65,
            0x64,
        ];
        let encoded = borsh::to_vec(&VaultEntryEnvelope::V1(sample_vault_entry())).unwrap();

        assert_eq!(encoded, expected, "V1 byte layout drifted");
    }

    /// Same field-0 claim as [`pool_entry_v1_status_is_field_zero`]. It is not
    /// redundant on a one-field struct: it is what keeps `status` at position
    /// zero when a second field is appended.
    #[test]
    fn vault_entry_v1_status_is_field_zero() {
        let value = sample_vault_entry();
        let encoded = borsh::to_vec(&VaultEntryEnvelope::V1(value.clone())).unwrap();
        let len = value.status.len();

        assert_eq!(encoded[0], 0x00, "V1 must encode as enum tag 0x00");
        assert_eq!(
            encoded[1..5],
            (len as u32).to_le_bytes(),
            "status length prefix must follow the envelope tag"
        );
        assert_eq!(
            &encoded[5..5 + len],
            value.status.as_bytes(),
            "status bytes must be field 0"
        );
    }

    #[test]
    fn vault_entry_envelope_round_trip() {
        let value = sample_vault_entry();
        let encoded = borsh::to_vec(&VaultEntryEnvelope::V1(value.clone())).unwrap();
        let decoded = VaultEntryEnvelope::try_from_slice(&encoded).unwrap();

        assert_eq!(decoded, VaultEntryEnvelope::V1(value));
    }
    // --- TenantEntry -------------------------------------------------------

    #[test]
    fn tenant_entry_envelope_v1_leading_byte_is_zero() {
        let encoded = borsh::to_vec(&TenantEntryEnvelope::V1(sample_tenant_entry())).unwrap();

        assert_eq!(encoded[0], 0x00, "V1 must encode as enum tag 0x00");
    }

    #[test]
    fn tenant_entry_envelope_v1_golden_hex_layout() {
        // DO NOT EDIT — V1 layout, frozen at mainnet origination. Field order/width:
        // tag 0x00, status (len-prefixed String, FIELD 0). The status differs in
        // both value and length from `PoolEntry`'s and `VaultEntry`'s, so none of
        // the three goldens can pass another's bytes.
        let expected: vec::Vec<u8> = vec![
            0x00, 0x06, 0x00, 0x00, 0x00, 0x70, 0x61, 0x75, 0x73, 0x65, 0x64,
        ];
        let encoded = borsh::to_vec(&TenantEntryEnvelope::V1(sample_tenant_entry())).unwrap();

        assert_eq!(encoded, expected, "V1 byte layout drifted");
    }

    /// Same field-0 claim as [`pool_entry_v1_status_is_field_zero`]. It is not
    /// redundant on a one-field struct: it is what keeps `status` at position
    /// zero when a second field is appended — and the tenant's sequencer keys,
    /// which stay at their own path, are exactly the kind of value that must
    /// never be appended ahead of it.
    #[test]
    fn tenant_entry_v1_status_is_field_zero() {
        let value = sample_tenant_entry();
        let encoded = borsh::to_vec(&TenantEntryEnvelope::V1(value.clone())).unwrap();
        let len = value.status.len();

        assert_eq!(encoded[0], 0x00, "V1 must encode as enum tag 0x00");
        assert_eq!(
            encoded[1..5],
            (len as u32).to_le_bytes(),
            "status length prefix must follow the envelope tag"
        );
        assert_eq!(
            &encoded[5..5 + len],
            value.status.as_bytes(),
            "status bytes must be field 0"
        );
    }

    #[test]
    fn tenant_entry_envelope_round_trip() {
        let value = sample_tenant_entry();
        let encoded = borsh::to_vec(&TenantEntryEnvelope::V1(value.clone())).unwrap();
        let decoded = TenantEntryEnvelope::try_from_slice(&encoded).unwrap();

        assert_eq!(decoded, TenantEntryEnvelope::V1(value));
    }

    // --- KernelInfo --------------------------------------------------------

    #[test]
    fn kernel_info_envelope_v1_leading_byte_is_zero() {
        let encoded = borsh::to_vec(&KernelInfoEnvelope::V1(sample_kernel_info())).unwrap();

        assert_eq!(encoded[0], 0x00, "V1 must encode as enum tag 0x00");
    }

    #[test]
    fn kernel_info_envelope_v1_golden_hex_layout() {
        // DO NOT EDIT — V1 layout, frozen at mainnet origination. Field order/width:
        // tag 0x00, version (len-prefixed String, FIELD 0), supported_games
        // (u32 LE element count, then one len-prefixed String per element, in
        // order), admin_subtags (u32 LE element count, then one raw byte per
        // element, in order). Two games of unequal length, so the vector
        // count, both element prefixes and the element order are all pinned.
        let expected: vec::Vec<u8> = vec![
            0x00, // envelope tag: V1
            0x05, 0x00, 0x00, 0x00, // version length
            0x34, 0x2e, 0x32, 0x2e, 0x31, // "4.2.1"
            0x02, 0x00, 0x00, 0x00, // supported_games element count
            0x07, 0x00, 0x00, 0x00, // element 0 length
            0x68, 0x69, 0x6c, 0x6f, 0x3a, 0x76, 0x31, // "hilo:v1"
            0x09, 0x00, 0x00, 0x00, // element 1 length
            0x70, 0x6c, 0x69, 0x6e, 0x6b, 0x6f, 0x3a, 0x76, 0x31, // "plinko:v1"
            0x03, 0x00, 0x00, 0x00, // admin_subtags element count
            0x0D, 0x02, 0x7F, // the three subtag bytes, in order
        ];
        let encoded = borsh::to_vec(&KernelInfoEnvelope::V1(sample_kernel_info())).unwrap();

        assert_eq!(encoded, expected, "V1 byte layout drifted");
    }

    /// Same field-0 claim the status records make, and it earns its keep for a
    /// different reason here: this struct has further fields, so the
    /// test is what keeps `version` ahead of `supported_games` — the shell
    /// readers scan the fixed-width prefix for the version and would otherwise
    /// read a game-list length as a version length.
    #[test]
    fn kernel_info_v1_version_is_field_zero() {
        let value = sample_kernel_info();
        let encoded = borsh::to_vec(&KernelInfoEnvelope::V1(value.clone())).unwrap();
        let len = value.version.len();

        assert_eq!(encoded[0], 0x00, "V1 must encode as enum tag 0x00");
        assert_eq!(
            encoded[1..5],
            (len as u32).to_le_bytes(),
            "version length prefix must follow the envelope tag"
        );
        assert_eq!(
            &encoded[5..5 + len],
            value.version.as_bytes(),
            "version bytes must be field 0"
        );
    }

    #[test]
    fn kernel_info_envelope_round_trip() {
        let value = sample_kernel_info();
        let encoded = borsh::to_vec(&KernelInfoEnvelope::V1(value.clone())).unwrap();
        let decoded = KernelInfoEnvelope::try_from_slice(&encoded).unwrap();

        assert_eq!(decoded, KernelInfoEnvelope::V1(value));
    }

    // --- DeferredWithdrawal ------------------------------------------------

    // Above `u32::MAX`: `amount_mutez` is the one stored amount that is `u64`
    // (the post-narrowing L1 argument), so the width to pin is 8 bytes and a
    // decoder that read 4 would pass a small value. Guarded like the u128 ones.
    const DEFERRED_AMOUNT_MUTEZ: u64 = 0x1112_1314_1516_1718;
    const CURSOR_HEAD: u64 = 0x2122_2324_2526_2728;
    const CURSOR_TAIL: u64 = 0x3132_3334_3536_3738;

    const _: () = assert!(DEFERRED_AMOUNT_MUTEZ > u32::MAX as u64);
    const _: () = assert!(CURSOR_HEAD > u32::MAX as u64);
    const _: () = assert!(CURSOR_TAIL > CURSOR_HEAD);

    fn sample_deferred_withdrawal() -> v1::DeferredWithdrawal {
        // Every string has a different length from its neighbours, so a field
        // swap moves the length prefixes and fails the golden.
        v1::DeferredWithdrawal {
            tenant_id: "acme".to_string(),
            pool_id: "vip".to_string(),
            reference: "deposit-7-3".to_string(),
            vault: "KT1vault".to_string(),
            target: v1::DeferredTarget::Bounce {
                recipient: "tz1owner".to_string(),
            },
            amount_mutez: DEFERRED_AMOUNT_MUTEZ,
        }
    }

    /// The session-payout arm: 16 raw session-id bytes, distinct and non-zero
    /// so a truncated or reordered read cannot pass.
    const DEFERRED_SESSION_ID: [u8; 16] = [
        0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
        0xb0,
    ];

    fn sample_deferred_cemented_payout() -> v1::DeferredWithdrawal {
        v1::DeferredWithdrawal {
            tenant_id: "acme".to_string(),
            pool_id: "vip".to_string(),
            reference: "payout-x".to_string(),
            vault: "KT1vault".to_string(),
            target: v1::DeferredTarget::CementedPayout {
                session_id: DEFERRED_SESSION_ID,
            },
            amount_mutez: DEFERRED_AMOUNT_MUTEZ,
        }
    }

    /// The sweep arm: 16 raw sweep-id bytes, `u64 BE level ‖ u64 BE id`
    /// (level 0x0102_0304_0506_0708, id 0x1112_1314_1516_1718), distinct and
    /// non-zero so a truncated or reordered read cannot pass.
    const DEFERRED_SWEEP_ID: [u8; 16] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18,
    ];

    fn sample_deferred_sweep() -> v1::DeferredWithdrawal {
        v1::DeferredWithdrawal {
            tenant_id: "acme".to_string(),
            pool_id: "vip".to_string(),
            reference: "sweep-7-3".to_string(),
            vault: "KT1vault".to_string(),
            target: v1::DeferredTarget::Sweep {
                sweep_id: DEFERRED_SWEEP_ID,
            },
            amount_mutez: DEFERRED_AMOUNT_MUTEZ,
        }
    }

    fn sample_deferred_outbox_cursor() -> v1::DeferredOutboxCursor {
        v1::DeferredOutboxCursor {
            head: CURSOR_HEAD,
            tail: CURSOR_TAIL,
        }
    }

    #[test]
    fn deferred_withdrawal_envelope_v1_leading_byte_is_zero() {
        let encoded =
            borsh::to_vec(&DeferredWithdrawalEnvelope::V1(sample_deferred_withdrawal())).unwrap();

        assert_eq!(encoded[0], 0x00, "V1 must encode as enum tag 0x00");
    }

    #[test]
    fn deferred_withdrawal_envelope_v1_golden_hex_layout() {
        // DO NOT EDIT — V1 layout, frozen at mainnet origination. Field order/width:
        // tag 0x00, tenant_id, pool_id, reference, vault (each a len-prefixed
        // String), target (borsh enum: 0x00 Bounce + len-prefixed recipient),
        // amount_mutez (u64 LE — the ONE u64 amount). Edited in place once,
        // pre-origination, when the session payout got its own entrypoint
        // (`docs/specs/session-payout-ledger.md` slice 1).
        let expected: vec::Vec<u8> = vec![
            0x00, // envelope tag: V1
            0x04, 0x00, 0x00, 0x00, 0x61, 0x63, 0x6d, 0x65, // "acme"
            0x03, 0x00, 0x00, 0x00, 0x76, 0x69, 0x70, // "vip"
            0x0b, 0x00, 0x00, 0x00, 0x64, 0x65, 0x70, 0x6f, 0x73, 0x69, 0x74, 0x2d, 0x37, 0x2d,
            0x33, // "deposit-7-3"
            0x08, 0x00, 0x00, 0x00, 0x4b, 0x54, 0x31, 0x76, 0x61, 0x75, 0x6c,
            0x74, // "KT1vault"
            0x00, // target tag: Bounce
            0x08, 0x00, 0x00, 0x00, 0x74, 0x7a, 0x31, 0x6f, 0x77, 0x6e, 0x65,
            0x72, // "tz1owner"
            0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11, // amount_mutez LE
        ];
        let encoded =
            borsh::to_vec(&DeferredWithdrawalEnvelope::V1(sample_deferred_withdrawal())).unwrap();

        assert_eq!(encoded, expected, "V1 byte layout drifted");
        assert_eq!(encoded.len(), 64, "V1 encoded length drifted");
    }

    #[test]
    fn deferred_cemented_payout_v1_golden_hex_layout() {
        // DO NOT EDIT — V1 layout, frozen at mainnet origination. The
        // CementedPayout arm: target tag 0x01 followed by the 16 raw session-id
        // bytes (a fixed-width array carries no length prefix).
        let expected: vec::Vec<u8> = vec![
            0x00, // envelope tag: V1
            0x04, 0x00, 0x00, 0x00, 0x61, 0x63, 0x6d, 0x65, // "acme"
            0x03, 0x00, 0x00, 0x00, 0x76, 0x69, 0x70, // "vip"
            0x08, 0x00, 0x00, 0x00, 0x70, 0x61, 0x79, 0x6f, 0x75, 0x74, 0x2d,
            0x78, // "payout-x"
            0x08, 0x00, 0x00, 0x00, 0x4b, 0x54, 0x31, 0x76, 0x61, 0x75, 0x6c,
            0x74, // "KT1vault"
            0x01, // target tag: CementedPayout
            0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae,
            0xaf, 0xb0, // session_id, 16 raw bytes
            0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11, // amount_mutez LE
        ];
        let encoded = borsh::to_vec(&DeferredWithdrawalEnvelope::V1(
            sample_deferred_cemented_payout(),
        ))
        .unwrap();

        assert_eq!(encoded, expected, "V1 byte layout drifted");
        // 1 + (4+4) + (4+3) + (4+8) + (4+8) + 1 + 16 + 8.
        assert_eq!(encoded.len(), 65, "V1 encoded length drifted");
    }

    #[test]
    fn deferred_sweep_v1_golden_hex_layout() {
        // DO NOT EDIT — V1 layout, frozen at mainnet origination. The Sweep
        // arm, appended (`docs/specs/house-equity-and-sweeps.md`): target tag
        // 0x02 followed by the 16 raw sweep-id bytes (a fixed-width array
        // carries no length prefix), the same shape as the payout arm.
        let expected: vec::Vec<u8> = vec![
            0x00, // envelope tag: V1
            0x04, 0x00, 0x00, 0x00, 0x61, 0x63, 0x6d, 0x65, // "acme"
            0x03, 0x00, 0x00, 0x00, 0x76, 0x69, 0x70, // "vip"
            0x09, 0x00, 0x00, 0x00, 0x73, 0x77, 0x65, 0x65, 0x70, 0x2d, 0x37, 0x2d,
            0x33, // "sweep-7-3"
            0x08, 0x00, 0x00, 0x00, 0x4b, 0x54, 0x31, 0x76, 0x61, 0x75, 0x6c,
            0x74, // "KT1vault"
            0x02, // target tag: Sweep
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
            0x17, 0x18, // sweep_id, 16 raw bytes
            0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11, // amount_mutez LE
        ];
        let encoded =
            borsh::to_vec(&DeferredWithdrawalEnvelope::V1(sample_deferred_sweep())).unwrap();

        assert_eq!(encoded, expected, "V1 byte layout drifted");
        // 1 + (4+4) + (4+3) + (4+9) + (4+8) + 1 + 16 + 8.
        assert_eq!(encoded.len(), 66, "V1 encoded length drifted");
    }

    #[test]
    fn deferred_withdrawal_envelope_round_trip() {
        for value in [
            sample_deferred_withdrawal(),
            sample_deferred_cemented_payout(),
            sample_deferred_sweep(),
        ] {
            let encoded = borsh::to_vec(&DeferredWithdrawalEnvelope::V1(value.clone())).unwrap();
            let decoded = DeferredWithdrawalEnvelope::try_from_slice(&encoded).unwrap();

            assert_eq!(decoded, DeferredWithdrawalEnvelope::V1(value));
        }
    }

    // --- DeferredOutboxCursor ----------------------------------------------

    #[test]
    fn deferred_outbox_cursor_envelope_v1_leading_byte_is_zero() {
        let encoded = borsh::to_vec(&DeferredOutboxCursorEnvelope::V1(
            sample_deferred_outbox_cursor(),
        ))
        .unwrap();

        assert_eq!(encoded[0], 0x00, "V1 must encode as enum tag 0x00");
    }

    #[test]
    fn deferred_outbox_cursor_envelope_v1_golden_hex_layout() {
        // DO NOT EDIT — V1 layout, frozen at mainnet origination. Field order/width:
        // tag 0x00, head (u64 LE), tail (u64 LE). Distinct non-zero bytes in
        // every position, so a head/tail swap fails the golden.
        let expected: vec::Vec<u8> = vec![
            0x00, // envelope tag: V1
            0x28, 0x27, 0x26, 0x25, 0x24, 0x23, 0x22, 0x21, // head LE
            0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, // tail LE
        ];
        let encoded = borsh::to_vec(&DeferredOutboxCursorEnvelope::V1(
            sample_deferred_outbox_cursor(),
        ))
        .unwrap();

        assert_eq!(encoded, expected, "V1 byte layout drifted");
    }

    #[test]
    fn deferred_outbox_cursor_envelope_round_trip() {
        let value = sample_deferred_outbox_cursor();
        let encoded = borsh::to_vec(&DeferredOutboxCursorEnvelope::V1(value)).unwrap();
        let decoded = DeferredOutboxCursorEnvelope::try_from_slice(&encoded).unwrap();

        assert_eq!(decoded, DeferredOutboxCursorEnvelope::V1(value));
    }

    // --- InboxAcceptance ---------------------------------------------------

    // Above `u32::MAX`, so the 8-byte width of the count is pinned — a decoder
    // that read 4 bytes would pass a small value. The two levels are distinct
    // non-zero patterns so a `since`/`last` swap fails the golden.
    const ACCEPTANCE_ADMITTED_COUNT: u64 = 0x4142_4344_4546_4748;
    const ACCEPTANCE_SINCE_LEVEL: u32 = 0x5152_5354;
    const ACCEPTANCE_LAST_ADMITTED_LEVEL: u32 = 0x6162_6364;

    const _: () = assert!(ACCEPTANCE_ADMITTED_COUNT > u32::MAX as u64);
    const _: () = assert!(ACCEPTANCE_LAST_ADMITTED_LEVEL > ACCEPTANCE_SINCE_LEVEL);

    fn sample_inbox_acceptance() -> v1::InboxAcceptance {
        v1::InboxAcceptance {
            admitted_count: ACCEPTANCE_ADMITTED_COUNT,
            since_level: ACCEPTANCE_SINCE_LEVEL,
            last_admitted_level: ACCEPTANCE_LAST_ADMITTED_LEVEL,
        }
    }

    #[test]
    fn inbox_acceptance_envelope_v1_leading_byte_is_zero() {
        let encoded =
            borsh::to_vec(&InboxAcceptanceEnvelope::V1(sample_inbox_acceptance())).unwrap();

        assert_eq!(encoded[0], 0x00, "V1 must encode as enum tag 0x00");
    }

    #[test]
    fn inbox_acceptance_envelope_v1_golden_hex_layout() {
        // DO NOT EDIT — V1 layout, frozen at mainnet origination. Field order/width:
        // tag 0x00, admitted_count (u64 LE, FIELD 0), since_level (u32 LE),
        // last_admitted_level (u32 LE). Distinct non-zero bytes in every
        // position, so a field swap or a width drift fails the golden.
        let expected: vec::Vec<u8> = vec![
            0x00, // envelope tag: V1
            0x48, 0x47, 0x46, 0x45, 0x44, 0x43, 0x42, 0x41, // admitted_count LE
            0x54, 0x53, 0x52, 0x51, // since_level LE
            0x64, 0x63, 0x62, 0x61, // last_admitted_level LE
        ];
        let encoded =
            borsh::to_vec(&InboxAcceptanceEnvelope::V1(sample_inbox_acceptance())).unwrap();

        assert_eq!(encoded, expected, "V1 byte layout drifted");
        assert_eq!(encoded.len(), 17, "V1 encoded length drifted");
    }

    /// Same field-0 claim the status records make: the count is what a prefix
    /// reader wants, so it sits immediately after the envelope tag and the two
    /// levels follow it.
    #[test]
    fn inbox_acceptance_v1_admitted_count_is_field_zero() {
        let value = sample_inbox_acceptance();
        let encoded = borsh::to_vec(&InboxAcceptanceEnvelope::V1(value)).unwrap();

        assert_eq!(encoded[0], 0x00, "V1 must encode as enum tag 0x00");
        assert_eq!(
            encoded[1..9],
            value.admitted_count.to_le_bytes(),
            "admitted_count must follow the envelope tag"
        );
    }

    #[test]
    fn inbox_acceptance_envelope_round_trip() {
        let value = sample_inbox_acceptance();
        let encoded = borsh::to_vec(&InboxAcceptanceEnvelope::V1(value)).unwrap();
        let decoded = InboxAcceptanceEnvelope::try_from_slice(&encoded).unwrap();

        assert_eq!(decoded, InboxAcceptanceEnvelope::V1(value));
    }

    // --- CommittedSeedRanges -----------------------------------------------

    // Every bound is above `u32::MAX`, so the 8-byte width of an index is
    // pinned — a decoder that read 4 bytes would pass a small value. Two runs,
    // so the vector's length prefix and the element stride are pinned too, and
    // all four bounds are distinct patterns so a `start`/`end` swap or a run
    // reorder fails the golden.
    const FIRST_RANGE_START: u64 = 0x7172_7374_7576_7778;
    const FIRST_RANGE_END: u64 = 0x8182_8384_8586_8788;
    const SECOND_RANGE_START: u64 = 0x9192_9394_9596_9798;
    const SECOND_RANGE_END: u64 = 0xa1a2_a3a4_a5a6_a7a8;

    const _: () = assert!(FIRST_RANGE_START > u32::MAX as u64);
    const _: () = assert!(FIRST_RANGE_START < FIRST_RANGE_END);
    const _: () = assert!(FIRST_RANGE_END < SECOND_RANGE_START);
    const _: () = assert!(SECOND_RANGE_START < SECOND_RANGE_END);

    fn sample_committed_seed_ranges() -> v1::CommittedSeedRanges {
        v1::CommittedSeedRanges {
            ranges: vec![
                v1::SeedIndexRange {
                    start: FIRST_RANGE_START,
                    end: FIRST_RANGE_END,
                },
                v1::SeedIndexRange {
                    start: SECOND_RANGE_START,
                    end: SECOND_RANGE_END,
                },
            ],
        }
    }

    #[test]
    fn committed_seed_ranges_envelope_v1_leading_byte_is_zero() {
        let encoded = borsh::to_vec(&CommittedSeedRangesEnvelope::V1(
            sample_committed_seed_ranges(),
        ))
        .unwrap();

        assert_eq!(encoded[0], 0x00, "V1 must encode as enum tag 0x00");
    }

    #[test]
    fn committed_seed_ranges_envelope_v1_golden_hex_layout() {
        // DO NOT EDIT — V1 layout, frozen at mainnet origination. Field order/width:
        // tag 0x00, ranges: u32 LE length then per run start (u64 LE),
        // end (u64 LE).
        let expected: vec::Vec<u8> = vec![
            0x00, // envelope tag: V1
            0x02, 0x00, 0x00, 0x00, // ranges.len() LE
            0x78, 0x77, 0x76, 0x75, 0x74, 0x73, 0x72, 0x71, // ranges[0].start LE
            0x88, 0x87, 0x86, 0x85, 0x84, 0x83, 0x82, 0x81, // ranges[0].end LE
            0x98, 0x97, 0x96, 0x95, 0x94, 0x93, 0x92, 0x91, // ranges[1].start LE
            0xa8, 0xa7, 0xa6, 0xa5, 0xa4, 0xa3, 0xa2, 0xa1, // ranges[1].end LE
        ];
        let encoded = borsh::to_vec(&CommittedSeedRangesEnvelope::V1(
            sample_committed_seed_ranges(),
        ))
        .unwrap();

        assert_eq!(encoded, expected, "V1 byte layout drifted");
        assert_eq!(encoded.len(), 37, "V1 encoded length drifted");
    }

    /// The record of a pool that has committed nothing in a decodable form —
    /// five bytes, the tag and a zero length. Pinned because the kernel's size
    /// bound on the record is computed from this prefix plus 16 bytes a run.
    #[test]
    fn committed_seed_ranges_envelope_v1_empty_is_the_tag_and_a_zero_length() {
        let encoded = borsh::to_vec(&CommittedSeedRangesEnvelope::V1(v1::CommittedSeedRanges {
            ranges: vec![],
        }))
        .unwrap();

        assert_eq!(encoded, vec![0x00, 0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn committed_seed_ranges_envelope_round_trip() {
        let value = sample_committed_seed_ranges();
        let encoded = borsh::to_vec(&CommittedSeedRangesEnvelope::V1(value.clone())).unwrap();
        let decoded = CommittedSeedRangesEnvelope::try_from_slice(&encoded).unwrap();

        assert_eq!(decoded, CommittedSeedRangesEnvelope::V1(value));
    }

    // --- SeedUsage ------------------------------------------------------------

    // Every counter is above `u32::MAX`, so the 8-byte width is pinned, and
    // the three are distinct patterns so a field swap fails the golden.
    const SEED_USAGE_CONSUMED: u64 = 0x4142_4344_4546_4748;
    const SEED_USAGE_PENDING: u64 = 0x5152_5354_5556_5758;
    const SEED_USAGE_HIGHEST: u64 = 0x6162_6364_6566_6768;

    const _: () = assert!(SEED_USAGE_CONSUMED > u32::MAX as u64);
    const _: () = assert!(SEED_USAGE_PENDING > u32::MAX as u64);
    const _: () = assert!(SEED_USAGE_HIGHEST > u32::MAX as u64);

    fn sample_seed_usage() -> v1::SeedUsage {
        v1::SeedUsage {
            consumed_count: SEED_USAGE_CONSUMED,
            pending_count: SEED_USAGE_PENDING,
            highest_consumed: Some(SEED_USAGE_HIGHEST),
        }
    }

    #[test]
    fn seed_usage_envelope_v1_leading_byte_is_zero() {
        let encoded = borsh::to_vec(&SeedUsageEnvelope::V1(sample_seed_usage())).unwrap();

        assert_eq!(encoded[0], 0x00, "V1 must encode as enum tag 0x00");
    }

    #[test]
    fn seed_usage_envelope_v1_golden_hex_layout() {
        // DO NOT EDIT — V1 layout, frozen at mainnet origination. Field order/width:
        // tag 0x00, consumed_count (u64 LE), pending_count (u64 LE),
        // highest_consumed (Option: 0x01 then u64 LE; 0x00 alone for None).
        let expected: vec::Vec<u8> = vec![
            0x00, // envelope tag: V1
            0x48, 0x47, 0x46, 0x45, 0x44, 0x43, 0x42, 0x41, // consumed_count LE
            0x58, 0x57, 0x56, 0x55, 0x54, 0x53, 0x52, 0x51, // pending_count LE
            0x01, // highest_consumed: Some
            0x68, 0x67, 0x66, 0x65, 0x64, 0x63, 0x62, 0x61, // highest_consumed LE
        ];
        let encoded = borsh::to_vec(&SeedUsageEnvelope::V1(sample_seed_usage())).unwrap();

        assert_eq!(encoded, expected, "V1 byte layout drifted");
        assert_eq!(encoded.len(), 26, "V1 encoded length drifted");
    }

    /// The record of a pool that has consumed nothing yet: both counters and
    /// a `None`, eighteen bytes. Pinned because `None` is the one state the
    /// kernel writes with no index behind it.
    #[test]
    fn seed_usage_envelope_v1_none_highest_is_a_zero_tag() {
        let encoded = borsh::to_vec(&SeedUsageEnvelope::V1(v1::SeedUsage {
            consumed_count: 0,
            pending_count: 50,
            highest_consumed: None,
        }))
        .unwrap();

        assert_eq!(encoded.len(), 18);
        assert_eq!(encoded[17], 0x00, "None encodes as a bare zero tag");
    }

    #[test]
    fn seed_usage_envelope_round_trip() {
        let value = sample_seed_usage();
        let encoded = borsh::to_vec(&SeedUsageEnvelope::V1(value)).unwrap();
        let decoded = SeedUsageEnvelope::try_from_slice(&encoded).unwrap();

        assert_eq!(decoded, SeedUsageEnvelope::V1(value));
    }

    // --- SeedBeacons ---------------------------------------------------------

    // Both `u64` rounds sit above `u32::MAX` so their 8-byte width is pinned
    // (a decoder reading 4 bytes would pass a small value), every field is a
    // distinct pattern so a swap fails the golden, the chain hash is 32
    // distinct bytes with no length prefix (a fixed array, not a `Vec`), and
    // there are two entries so the vector's length prefix is visibly its own.
    const BEACON_MIN_ROUND: u64 = 0x4142_4344_4546_4748;
    const BEACON_MAX_ROUND: u64 = 0x5152_5354_5556_5758;
    const BEACON_FIRST_LEVEL: u32 = 0x6162_6364;
    const BEACON_LAST_LEVEL: u32 = 0x7172_7374;

    const _: () = assert!(BEACON_MIN_ROUND > u32::MAX as u64);
    const _: () = assert!(BEACON_MAX_ROUND > u32::MAX as u64);

    fn sample_seed_beacons() -> v1::SeedBeacons {
        let mut first_hash = [0u8; 32];
        let mut second_hash = [0u8; 32];
        for (i, (a, b)) in first_hash
            .iter_mut()
            .zip(second_hash.iter_mut())
            .enumerate()
        {
            *a = 0x80 + i as u8;
            *b = 0xc0 + i as u8;
        }
        v1::SeedBeacons {
            entries: vec![
                v1::SeedBeaconEntry {
                    chain_hash: first_hash,
                    min_drand_round: BEACON_MIN_ROUND,
                    max_drand_round: BEACON_MAX_ROUND,
                    first_level: BEACON_FIRST_LEVEL,
                    last_level: BEACON_LAST_LEVEL,
                },
                v1::SeedBeaconEntry {
                    chain_hash: second_hash,
                    min_drand_round: 1,
                    max_drand_round: 2,
                    first_level: 3,
                    last_level: 4,
                },
            ],
        }
    }

    #[test]
    fn seed_beacons_envelope_v1_leading_byte_is_zero() {
        let encoded = borsh::to_vec(&SeedBeaconsEnvelope::V1(sample_seed_beacons())).unwrap();

        assert_eq!(encoded[0], 0x00, "V1 must encode as enum tag 0x00");
    }

    #[test]
    fn seed_beacons_envelope_v1_golden_hex_layout() {
        // DO NOT EDIT — V1 layout, frozen at mainnet origination. Field order/width:
        // tag 0x00, entries: u32 LE length then per entry chain_hash (32 raw
        // bytes, no length prefix), min_drand_round (u64 LE), max_drand_round
        // (u64 LE), first_level (u32 LE), last_level (u32 LE).
        let mut expected: vec::Vec<u8> = vec![
            0x00, // envelope tag: V1
            0x02, 0x00, 0x00, 0x00, // entries.len() LE
        ];
        // entries[0]
        expected.extend((0u8..32).map(|i| 0x80 + i)); // chain_hash
        expected.extend([0x48, 0x47, 0x46, 0x45, 0x44, 0x43, 0x42, 0x41]); // min_drand_round LE
        expected.extend([0x58, 0x57, 0x56, 0x55, 0x54, 0x53, 0x52, 0x51]); // max_drand_round LE
        expected.extend([0x64, 0x63, 0x62, 0x61]); // first_level LE
        expected.extend([0x74, 0x73, 0x72, 0x71]); // last_level LE
        // entries[1]
        expected.extend((0u8..32).map(|i| 0xc0 + i)); // chain_hash
        expected.extend([0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // min_drand_round LE
        expected.extend([0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // max_drand_round LE
        expected.extend([0x03, 0x00, 0x00, 0x00]); // first_level LE
        expected.extend([0x04, 0x00, 0x00, 0x00]); // last_level LE
        let encoded = borsh::to_vec(&SeedBeaconsEnvelope::V1(sample_seed_beacons())).unwrap();

        assert_eq!(encoded, expected, "V1 byte layout drifted");
        assert_eq!(encoded.len(), 5 + 2 * 56, "V1 encoded length drifted");
    }

    #[test]
    fn seed_beacons_envelope_round_trip() {
        let value = sample_seed_beacons();
        let encoded = borsh::to_vec(&SeedBeaconsEnvelope::V1(value.clone())).unwrap();
        let decoded = SeedBeaconsEnvelope::try_from_slice(&encoded).unwrap();

        assert_eq!(decoded, SeedBeaconsEnvelope::V1(value));
    }
}
