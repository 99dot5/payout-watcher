//! V1 durable-storage schemas — **frozen at mainnet origination**.
//!
//! Until the first mainnet origination writes a V1 entry there is no durable
//! state to preserve, so a layout fix lands in V1 in place. From that
//! origination onward the layout is frozen: a replay- or layout-affecting
//! change needs a parallel `v2` module plus a new `XEnvelope::V2(v2::X)`
//! variant in [`crate`], never an in-place edit of a V1 struct — so storage
//! entries written by an earlier kernel keep decoding after an upgrade. This
//! mirrors the `smart_rollup_messages::v1` discipline on the wire side.
//!
//! **Amounts are `u128` atomic units of the record's `asset`** — mutez, at
//! 6 decimal places, for TEZ — the same grain the wire uses. The asset string
//! next to each amount already fixes the precision, so a `(units, scale)`
//! pair would state it twice. The width is `u128` rather than `u64` so it is
//! not TEZ-shaped: an 18-decimal asset overflows a `u64` at about 18 tokens,
//! which would have forced a `v2` layout for the second asset. It matches
//! `smart_rollup_messages::v1::RoundTranscript::stake`. The L1 mutez width
//! stays `u64`, and the refund path narrows to it explicitly.

use alloc::{string::String, vec::Vec};
use borsh::{BorshDeserialize, BorshSerialize};

/// A session's canonical balance record, keyed in durable storage at
/// `/tenants/{tenant}/pools/{pool}/sessions/{session_id}`.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct StoredSession {
    pub owner: String,
    pub asset: String,
    /// Atomic units of `asset`.
    pub balance: u128,
    /// KT1 of the vault that accepted the first deposit. EndSession refunds
    /// target this exact contract for the session's entire lifetime.
    pub funding_vault_address: String,
    /// Refund **EMITTED** — the rollup processed `EndSession` and queued the
    /// `execute_withdrawal` outbox message. **Not** proof the withdrawal
    /// executed on L1 (observable only via the rollup-node outbox RPC).
    pub ended: bool,
    pub end_reason: Option<String>,
}

/// A settled round's outcome record, keyed in durable storage at
/// `/tenants/{tenant}/pools/{pool}/settlements/{round_id}`. Written when a round
/// settles — the kernel keeps no transient per-round subtree, so this entry is
/// the round's only durable trace.
///
/// The two `Option` fields are last by convention (design §3): it buys a stable
/// prefix for a prefix reader and nothing else. Borsh has no positional
/// compatibility — any layout change is a new `SettlementEntryEnvelope::V2`,
/// never an edit of this struct once mainnet has originated.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct SettlementEntry {
    pub session_id: String,
    pub player: String,
    pub game_type: String,
    pub asset: String,
    /// Atomic units of `asset`, as is every amount below and in both nested
    /// records.
    pub stake: u128,
    pub payout: u128,
    /// The replayed round's ending (`cashed-out`/`completed`/`bust`/
    /// `abandoned`, `game_engine_core::Ending::as_str`) of an accepted round,
    /// or the `reject-*` marker of a rejected one — so this
    /// column DOES carry a reject class. [`Discrepancy::computed_outcome`] is
    /// the one that never does.
    pub outcome: String,
    pub validated: bool,
    /// The transcript's `player_commitment` (ADR 0022 D1/D12), copied
    /// verbatim: blake2b-256 over the archived player commands the sequencer
    /// committed to at settle. The kernel never validates or compares it —
    /// it is recorded so a rejected round, whose transcript is only somewhere
    /// in the inbox, still has its commitment reachable from state. Fixed
    /// width, so it sits with the primitives ahead of the two `Option`s.
    pub player_commitment: [u8; 32],
    /// Present when the rollup did not accept the settlement as claimed — a
    /// payout mismatch, actions after the settling one, or a `reject-*`
    /// marker from a transcript that never reached replay. `validated` is
    /// `false` exactly when this is present.
    pub discrepancy: Option<Discrepancy>,
    /// Present only when the settle-time max-win backstop actually clamped a
    /// breaching payout (`docs/specs/max-win-cap.md` slice 3).
    pub clamp: Option<MaxWinClamp>,
}

/// Why the rollup did not accept a settlement as claimed. Nested in
/// [`SettlementEntry`] rather than keyed separately: the two are always written
/// in the same settle transition, so a separate key bought a second decoder, a
/// second path template, and a second write whose failure was logged and
/// swallowed. Carries no `asset` — the parent record's `asset` is the same
/// value at every populate site.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct Discrepancy {
    /// Atomic units of the parent record's `asset`, as is `computed_payout`.
    pub claimed_payout: u128,
    pub computed_payout: u128,
    /// The replayed ending (`cashed-out`/`completed`/`bust`/`abandoned`), or
    /// empty on a reject that never reached replay.
    pub computed_outcome: String,
    /// Why this record exists: `"payout-mismatch"`; `"actions-after-settle"`
    /// (the payout matched, but the transcript carries actions after the one
    /// that settled the round — paid as computed, never read; a mismatch takes
    /// precedence); or one of the `reject-*` markers. A dedicated field, so a
    /// reject class is never smuggled through `computed_outcome`. (The parent
    /// record's top-level `outcome` does carry the marker on a reject.)
    pub reason: String,
}

/// The kernel's max-win settle-time backstop clamp. `clamped_live` is
/// `max(cap, stake)`, never below stake, so a push cannot pay back less than
/// staked; the settle credit becomes `banked + clamped_live`. Absent on an
/// honestly-delevered round. Amounts are atomic units of the parent record's
/// `asset`.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct MaxWinClamp {
    pub cap: u128,
    pub stake: u128,
    pub banked: u128,
    pub original_live: u128,
    pub clamped_live: u128,
}

/// The class of an asset-affecting operation recorded in the transaction
/// ledger. Borsh variant order is frozen on mainnet: `Deposit` = 0, `SessionEndPayout`
/// = 1, `Stake` = 2, `RoundEndPayout` = 3, `Fund` = 4, `Sweep` = 5, pinned by
/// `stored_transaction_kind_tags_are_frozen`. Append, never reorder.
///
/// Each kind is one direction of money, named from the rollup's side; the
/// row per kind (reference, writer, counterparty) is tabulated in
/// `docs/architecture.md` §8.3. Two kinds are easy to confuse: `RoundEndPayout` is a
/// round's credit INTO a session's balance, `SessionEndPayout` is the session's
/// balance LEAVING the rollup at session end, the row the fast-payout
/// readers price a payout against.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoredTransactionKind {
    /// An L1 deposit credited to (or bounced from) a session: the dedup row
    /// `deposit-{level}-{id}`, `account_address` the depositor. Taken before
    /// the status gate, so a bounced deposit leaves the same row kind.
    Deposit,
    /// The session's remaining balance leaving the rollup at `EndSession`
    /// (the **session payout**, paid on L1 by `execute_cemented_payout` or
    /// the signed `fast_payout`): the row `payout-{session_id}`,
    /// `account_address` the session owner, `amount` the balance paid out,
    /// written even when it is zero.
    SessionEndPayout,
    /// A settled round's stake, debited from the session's balance: the row
    /// `round-{round_id}-stake`, `account_address` the session owner.
    Stake,
    /// A settled round's credited payout INTO the session's balance (the
    /// **round payout**, what house equity's `payouts` sums): the row
    /// `round-{round_id}-payout`, written only when the credit is non-zero,
    /// `account_address` the session owner. Never at `payout-{session_id}`.
    RoundEndPayout,
    /// Bankroll paid into a vault through its `fund` entrypoint
    /// (`docs/specs/house-equity-and-sweeps.md` H3): the dedup row
    /// `fund-{level}-{id}`, `account_address` the funder (any wallet, the
    /// treasury KT1 included), `amount` what was booked as house equity.
    Fund,
    /// House equity reserved for a sweep to the treasury (H4): the row
    /// `sweep-{level}-{id}` the `execute_sweep` outbox message names by its
    /// `sweep_id`, `account_address` the VAULT the sweep leaves (the
    /// destination is baked into the vault, so no other address is on
    /// record), `amount` what left equity at request time.
    Sweep,
}

/// A pre-committed seed hash awaiting use by a round, keyed in durable storage
/// at `/tenants/{tenant}/pools/{pool}/seeds/pending/{index}`. The rollup later
/// verifies a consumed seed was committed **before** the round that used it.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct PendingSeed {
    pub hash: [u8; 32],
    pub commitment_level: u32,
}

/// One run of seed indices, **inclusive at both ends**: `start..=end`.
///
/// Inclusive so the run ending at `u64::MAX` is representable — an exclusive
/// end would need `u64::MAX + 1`.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub struct SeedIndexRange {
    pub start: u64,
    pub end: u64,
}

/// Every seed index a pool has ever accepted a commitment for, as a list of
/// index runs, keyed in durable storage at
/// `/tenants/{tenant}/pools/{pool}/seeds/committed-ranges`.
///
/// This is the memory [`PendingSeed`] cannot be. A pending seed is deleted
/// when a round consumes it, so "is index `i` pending" cannot tell an index
/// that was never committed from one that was committed and used — and a
/// `SeedBatch` carries no nonce, so the identical signed message can be
/// re-posted to the public inbox by anyone. A batch is applied only when none
/// of its indices is in this record, which makes an index committable once,
/// ever, however often its batch is redelivered.
///
/// A list of runs rather than one "next index" number because batches are not
/// guaranteed to land in index order (the injector is at-least-once with no
/// leader), and a single high-water mark would refuse a batch that merely
/// arrived after its successor. In the steady state the list is one run,
/// `0..=N`; a second run exists only while an earlier batch is still in
/// flight, and the two merge when it lands.
///
/// The kernel keeps `ranges` sorted by `start`, pairwise disjoint and
/// non-adjacent (touching runs are merged), and bounded in length; off-chain
/// readers must not rely on more than "a set of runs".
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct CommittedSeedRanges {
    pub ranges: Vec<SeedIndexRange>,
}

/// The drand beacons a pool's stored `SeedBatch`es have named, one entry per
/// chain hash, keyed in durable storage at
/// `/tenants/{tenant}/pools/{pool}/seeds/beacons`.
///
/// Every `SeedBatch` carries `drand_round` and `drand_chain_hash` (32 raw
/// bytes) on the wire.
/// This record is the kernel's copy of those claims, folded per chain hash:
/// the lowest and highest round stored under the hash and the first and last
/// L1 level a batch under it was stored at. Kept per hash rather than as one
/// "last batch" so a chain change does not erase the history of the chain it
/// replaced, and so the round rule below has a high-water mark per beacon.
///
/// A **claim**, never verified (the kernel cannot check a drand BLS signature
/// in `no_std`), but it gates one thing: a batch naming a round below its
/// hash's `max_drand_round` is refused, because a provisioner only ever moves
/// forward on one beacon and an older round is a replay of a stale beacon.
/// Equal rounds are accepted — one provisioning cycle writes several batches
/// under one round, and they land in any order. The kernel holds at most
/// eight entries and evicts the one with the oldest `last_level` to admit a
/// ninth. An undecodable record is overwritten with an `ERROR`, the
/// [`KernelInfo`] posture: losing a high-water mark readmits an old round,
/// which is the state a fresh pool starts in, whereas refusing every batch
/// behind a corrupt record would starve the pool of seeds.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct SeedBeacons {
    pub entries: Vec<SeedBeaconEntry>,
}

/// One drand beacon's entry in [`SeedBeacons`].
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct SeedBeaconEntry {
    /// The drand chain hash, the 32 bytes behind the 64 lowercase hex
    /// characters the wire carries.
    pub chain_hash: [u8; 32],
    /// The lowest drand round a stored batch named under this hash.
    pub min_drand_round: u64,
    /// The highest drand round a stored batch named under this hash — the
    /// high-water mark a later batch may not fall below.
    pub max_drand_round: u64,
    /// The L1 level the first batch under this hash was stored at.
    pub first_level: u32,
    /// The L1 level the latest batch under this hash was stored at — its
    /// seeds' `commitment_level`, and the eviction key.
    pub last_level: u32,
}

/// How a pool's committed seeds have been used, keyed in durable storage at
/// `/tenants/{tenant}/pools/{pool}/seeds/usage`.
///
/// Kernel-owned **diagnostics**: the kernel accepts a transcript against any
/// pending seed, deliberately — it cannot tell a round that honestly settled
/// late from a seed the sequencer skipped, because claim order is not on
/// chain and an honest round's lifetime is unbounded. What it CAN do is make
/// the shape of consumption readable from one record, so a reader can see
/// how many committed seeds sit unused below the highest index already spent.
/// For an honest pool that number is the rounds still open plus the seeds
/// promised to live sessions; a dishonest sequencer that evaluates the
/// player's client seed against every pending seed and picks the worst leaves
/// the rest behind, and they show up here as a backlog that never clears.
///
/// Three counters, each a plain tally the kernel bumps in the same
/// `kernel_run` as the write it describes: `pending_count` rises by a batch's
/// size when the batch is stored and falls by one when a seed is consumed or
/// burned, `consumed_count` rises by one on the same event, and
/// `highest_consumed` is the largest index ever consumed or burned (`None`
/// until the first). `pending_count` equals the number of `pending/{index}`
/// leaves exactly on a rollup originated with a kernel that keeps this
/// record; after an in-place upgrade it undercounts the seeds committed
/// before the record existed until they are used, which only ever makes the
/// derived backlog smaller — the conservative direction.
///
/// Nothing gates on it, so an undecodable record is logged and skipped,
/// never refused and never fatal: a transcript must settle whatever state its
/// diagnostics are in. It is also never overwritten with a fresh record,
/// because a reset `pending_count` could not be re-derived without walking
/// the pending leaves.
///
/// `consumed_count` is **field 0**, the same rule the status records follow,
/// so a prefix reader sees the headline number immediately after the envelope
/// tag. The `Option` is last by convention.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub struct SeedUsage {
    /// Seeds consumed by a settlement or burned by a reject, ever.
    pub consumed_count: u64,
    /// Seeds currently pending — committed and neither consumed nor burned.
    pub pending_count: u64,
    /// The highest index ever consumed or burned; `None` before the first.
    pub highest_consumed: Option<u64>,
}

/// An idempotency-ledger row for an asset-affecting operation, keyed in durable
/// storage at `/tenants/{tenant}/pools/{pool}/transactions/{asset}/{reference}`.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct StoredTransaction {
    /// The L1-visible counterparty: depositor for `Deposit`, refund recipient
    /// for `SessionEndPayout`, session owner for `Stake`/`RoundEndPayout`. Kept for audit; no
    /// balance logic reads this field anymore.
    pub account_address: String,
    pub asset: String,
    pub kind: StoredTransactionKind,
    /// Atomic units of `asset`.
    pub amount: u128,
}

/// The prior sequencer public key plus the L1 level through which it is still
/// accepted — the rotation grace window. Key and deadline are
/// one unit: a key without a deadline (or vice versa) is meaningless, so they
/// live in one record rather than two storage keys. Keyed in durable storage at
/// `/tenants/{tenant}/sequencer-keys/previous` — a sibling of the tenant's
/// [`TenantEntry`] record, deliberately not under it, so a status write cannot
/// reach the key pair.
///
/// `public_key` is kept as raw bytes (not `[u8; 32]`) to mirror how the
/// `current` key is handled — it is validated as an Ed25519 key only at
/// verification time via `PublicKeyEd25519::try_from`.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct PreviousSequencerKey {
    pub public_key: Vec<u8>,
    pub valid_until_level: u32,
}

/// A proposed replacement administrator contract plus the L1 level at or after
/// which it may be activated. Address and activation level are
/// one unit: a pending replacement is meaningless without its maturity level,
/// so they live in one record rather than two storage keys (same rationale as
/// [`PreviousSequencerKey`]). Keyed in durable storage at
/// `/config/admin-contract/pending`.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct PendingAdminContract {
    pub new_admin: String,
    pub activate_at_level: u32,
}

/// A proposed governed kernel upgrade plus the L1 level at or after which it
/// may be activated. Root hash and activation level are one unit: a pending
/// upgrade is meaningless without its maturity level, so they live in one
/// record rather than two storage keys (same rationale as
/// [`PendingAdminContract`]). Keyed in durable storage at
/// `/config/kernel-upgrade/pending`.
///
/// `root_hash` is the content-addressed reveal-tree root the activation handler
/// reveals against. It is **33 bytes** — the reveal preimage hash is a `0x00`
/// prefix byte followed by a 32-byte Blake2b digest (`PREIMAGE_HASH_SIZE = 33`
/// in the smart-rollup SDK), not a bare 32-byte hash.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct PendingKernelUpgrade {
    pub root_hash: [u8; 33],
    pub activate_at_level: u32,
}

/// A pool's configuration record, keyed at
/// `/tenants/{tenant}/pools/{pool}/config`. Created by admin subtag `0x0C`
/// `RegisterPool` (create-only) and mutated by `SetPoolStatus` (`0x03`) and the
/// pool max-win setter (`0x0B`), both update-only.
///
/// `status` is **field 0** so a prefix reader sees `00 | u32 LE len | bytes`
/// immediately after the envelope tag (design §3), and so the shell readers'
/// decoder renders it first. That buys a stable prefix, nothing more: borsh has
/// no positional compatibility, so any layout change is a new
/// `PoolEntryEnvelope::V2`, never an edit of this struct once mainnet has
/// originated.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct PoolEntry {
    /// `"pending" | "active" | "paused" | "draining" | "deprecated"`.
    pub status: String,
    /// Set once at registration, validated against `money::ASSET_REGISTRY`.
    /// Immutable: sessions bind to it and the transaction ledger is keyed by it.
    pub asset: String,
    /// Atomic units of `asset`. Never absent — every pool has a cap from its
    /// first block, which is why this is not an `Option`.
    pub max_win: u128,
}

/// A pool vault's record, keyed at
/// `/tenants/{tenant}/pools/{pool}/vaults/{KT1}` (path unchanged; the value
/// stopped being a raw UTF-8 status). Same field-0 rule as [`PoolEntry`].
///
/// The vault's money counters deliberately do NOT live here but in the
/// sibling [`HouseEquity`] record at `…/equity/{KT1}`: a hot money counter
/// with a strict read posture beside a config record with a lenient one
/// (ADR 0021), so a status setter can never touch equity and an undecodable
/// status can never make equity unreadable.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct VaultEntry {
    /// `"active" | "paused" | "draining" | "deprecated"` — a vault has no
    /// `pending`.
    pub status: String,
}

/// One vault's **house equity**, keyed at
/// `/tenants/{tenant}/pools/{pool}/equity/{KT1}`
/// (`docs/specs/house-equity-and-sweeps.md` H1): what the house may take out
/// of the vault without touching anything a player is owed, as four monotone
/// counters in atomic units of the pool's asset:
///
/// ```text
/// equity = (funded + stakes) − (payouts + swept)      // floored at zero
/// ```
///
/// Three events move it, each in the `kernel_run` that books the money: a
/// settled round (`stakes += stake`, `payouts += credited_payout` — the
/// max-win-clamped payout the session received, so equity and the session
/// move by the same number), an accepted `fund` message (`funded += amount`)
/// and an accepted `Sweep` admin op (`swept += amount`, reserved at request
/// rather than at execution). Deposits, bounces and `EndSession` are
/// equity-neutral (a deposit raises a liability by exactly what came in), so
/// no sum over sessions is needed. Additions are saturating: `u128`
/// saturation is unreachable for any asset, and a settlement must not fail
/// after its session write.
///
/// Counters, not one signed number: amounts are `u128` only, the kernel does
/// no signed arithmetic, each counter is a figure the operator and the
/// reconciler want on its own, and a wrong one is attributable.
///
/// **Money, read strictly**: kernel-written, so an undecodable record is a
/// kernel bug, not inbox content, and the kernel treats it as fatal like a
/// session record. An **absent** record is not an error: the vault predates
/// sweeps (H9) — a settlement then skips the update and a `Sweep` is refused.
/// Created, zeroed, by `RegisterPoolVault` and by the first `fund`.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HouseEquity {
    /// Bankroll booked in through `fund`.
    pub funded: u128,
    /// Stakes the house took from settled rounds.
    pub stakes: u128,
    /// Credited (clamped) payouts the house paid on settled rounds.
    pub payouts: u128,
    /// Equity reserved for sweeps at request time.
    pub swept: u128,
}

/// A tenant's configuration record, keyed at `/tenants/{tenant}/config`.
/// Created by admin subtag `0x00` `RegisterTenant` (create-only, seeded
/// `pending`) and mutated by `SetTenantStatus` (`0x02`), which is update-only:
/// a status write cannot conjure a tenant that has no sequencer key.
///
/// The tenant's sequencer keys deliberately do **not** live here. They sit at
/// `/tenants/{tenant}/sequencer-keys/{current,previous}`, so a status write
/// cannot rewrite the bytes holding a value with no on-chain recovery path
/// (ADR 0021, "a value with no recovery stays at its own key"). That also keeps
/// `/tenants/{tenant}/config` a leaf.
///
/// **An undecodable record is refused, not repaired, and the blast radius is
/// the whole tenant.** Both admin setters refuse a `Corrupt` record with no
/// write (ADR 0021 §corruption postures), so there is no on-chain repair: every
/// pool under the tenant denies admission, every deposit bounces, and because
/// the external gate covers `Cleanup` as well as `NewPlay`, `EndSession`
/// refunds stop too — in-flight balances are stranded until the rollup is
/// re-originated. That is accepted deliberately. The alternative,
/// `RegisterTenant` overwriting a corrupt record, would let a routine
/// re-registration reset a live tenant's status, and it is the shape that
/// erodes the guarantee above one exception at a time.
///
/// `status` is **field 0** so a prefix reader sees `00 | u32 LE len | bytes`
/// immediately after the envelope tag, and so the shell readers' decoder
/// renders it first. That buys a stable prefix, nothing more: borsh has no
/// positional compatibility, so any layout change is a new
/// `TenantEntryEnvelope::V2`, never an edit of this struct once mainnet has
/// originated.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct TenantEntry {
    /// `"pending" | "active" | "paused" | "deprecated"` — a tenant has no
    /// `draining`.
    pub status: String,
}

/// The running kernel's self-description, keyed at `/kernel/info`. Written by
/// `entry()` on every run, but only when the decoded record differs from what
/// this build would write — i.e. once, on the first run after an actual kernel
/// upgrade.
///
/// Kernel-owned diagnostics: nothing here is operator state, which is why an
/// undecodable record is **overwritten** rather than refused (ADR 0021
/// §corruption postures). A record that could never be rewritten would page the
/// reconciler forever. That self-healing write is also what makes the unbounded
/// `Vec` below safe to decode in a `no_std` kernel: the kernel is this record's
/// only writer, a `Vec` in a durable record is not a new class here
/// ([`PreviousSequencerKey::public_key`] is already one on the signature hot
/// path), and a `Corrupt` read is overwritten rather than propagated.
///
/// `version` is **field 0**, the same rule the status records follow, so the
/// shell readers see `00 | u32 LE len | bytes` after the envelope tag.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct KernelInfo {
    /// The kernel crate's `CARGO_PKG_VERSION`, e.g. `"0.4.0"`.
    pub version: String,
    /// Every game type this build can replay, in `kernel_replay_dispatch!`
    /// order. A `Vec<String>`, not a comma-joined scalar: the record is borsh,
    /// so a list costs nothing here and no reader has to re-split a string. The
    /// off-chain decoder renders it comma-joined for the shell readers.
    pub supported_games: Vec<String>,
    /// Every class-`0x01` administrator subtag `handle_admin_message` routes
    /// to a handler, as the raw wire byte, ascending, in the kernel's
    /// dispatch-table order. A `Vec<u8>`, not a bitmask: a `u8` has 256
    /// values and a reader should not have to know a ceiling to decode the set.
    ///
    /// Why it is published: an admin op the kernel does not know is
    /// soft-dropped rollup-side AFTER the multisig `execute` succeeded on L1
    /// and spent its nonce, so a newer administrator (or a rolled-back kernel)
    /// burns k-of-n ceremonies with a kernel log line as the only signal. The
    /// reconciler diffs the tooling's subtag vocabulary against this list, and
    /// the operator CLI refuses to render an intent whose subtag is not in it.
    ///
    /// Added to V1 in place, which was possible only because no rollup held a
    /// `KernelInfo` that had to stay decodable (pre-origination). Once V1 is
    /// frozen, a further capability list is a sibling record or a `V2`, not
    /// another field here.
    pub admin_subtags: Vec<u8>,
}

/// One vault outbox call — an `execute_bounce` or an `execute_cemented_payout`
/// (`docs/specs/session-payout-ledger.md` D1) — the kernel could not emit
/// because the level's outbox was already full, queued in durable storage at
/// `/outbox/deferred/entries/{index}` until a later level's `StartOfLevel`
/// drains it.
///
/// The protocol caps the outbox at `max_outbox_messages_per_level` (100)
/// messages per inbox level, and the 101st `write_output` returns
/// `FullOutbox`. Both of the kernel's withdrawal producers — the deposit
/// bounce and the `EndSession` payout — used to treat that as fatal, which on
/// committed inbox content is a deterministic panic on every replica: a
/// permanent wedge reachable by anyone who can land 101 top-ups in one block,
/// and by an honest mass-expiry sweep. A withdrawal that does not fit is now
/// written here instead and emitted at the next level that has room.
///
/// **The fields are the outbox call, not a pre-encoded message.** The kernel
/// re-encodes at drain time from `vault`/`target`/`amount_mutez`, so an
/// operator reading the queue with the storage explorer sees who is owed what
/// from where, and a future encoder change cannot leave a stale byte string in
/// the queue. `target` says which entrypoint and carries the one payee field
/// that entrypoint takes: a bounce names its `recipient` (the depositor), a
/// cemented payout names its `session_id` (the vault pays the owner it bound,
/// so no recipient rides the wire). `tenant_id`/`pool_id`/`reference` are
/// diagnostics only: they name the idempotency record (`deposit-{level}-{id}`
/// or `payout-{session_id}` under that pool's `transactions/`) whose emission
/// this entry carries, so a queued withdrawal is traceable to its cause. Dedup
/// is that record's job, not this entry's — a redelivered inbox message
/// short-circuits there and never enqueues twice.
///
/// **`amount_mutez` is a `u64`, unlike every other stored amount.** It is not a
/// balance: it is the exact `nat` argument of the outbox call, which the
/// producer has already narrowed from the `u128` balance (refusing, not
/// truncating, above `u64::MAX` — the L1 vault multiplies it into `mutez`, an
/// `int64`). Storing the post-narrowing width means a drain can never emit a
/// message the vault cannot execute.
///
/// The queue is rollup-global, not pool-scoped, because the cap it absorbs is
/// rollup-global: a level's 100 slots are shared by every tenant's refunds and
/// every vault's bounces, and one FIFO across all of them is what makes the
/// drain order fair.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct DeferredWithdrawal {
    pub tenant_id: String,
    pub pool_id: String,
    /// The idempotency reference of the record whose emission this is.
    pub reference: String,
    /// KT1 of the vault whose `execute_*` entrypoint pays.
    pub vault: String,
    /// Which vault entrypoint the call lands on, and its payee field.
    pub target: DeferredTarget,
    /// Mutez, already narrowed to the L1 `int64` range.
    pub amount_mutez: u64,
}

/// The vault entrypoint a [`DeferredWithdrawal`] re-encodes to, with the one
/// payee field that entrypoint takes. A borsh enum: `Bounce` is tag `0x00`,
/// `CementedPayout` is tag `0x01`, `Sweep` is tag `0x02`, pinned by the
/// golden-hex vectors. A further outbox destination is a new variant appended
/// here — never a repurposed field — and ships reader-first like every other
/// storage change.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub enum DeferredTarget {
    /// `execute_bounce((recipient, amount))`: one deposit the kernel could not
    /// credit goes back to the L1 address that sent it.
    Bounce { recipient: String },
    /// `execute_cemented_payout((session_id, amount))`: the session payout.
    /// The 16 raw bytes, as on every wire; the vault pays the owner it bound to
    /// them at first deposit.
    CementedPayout { session_id: [u8; 16] },
    /// `execute_sweep((sweep_id, amount))`: house equity leaving the vault for
    /// the treasury address baked into it (`docs/specs/house-equity-and-sweeps.md`
    /// H4/H5). `sweep_id` is the 16 raw bytes `u64 BE level ‖ u64 BE id` of
    /// the admin message that requested it — the name of the kernel's
    /// `sweep-{level}-{id}` record, so an execution matches one record even
    /// when two sweeps of one amount are pending. Rides the encoder's 16-byte
    /// `bytes` branch like the session id.
    Sweep { sweep_id: [u8; 16] },
}

/// The kernel's acknowledgement that it **admitted** external messages for one
/// `(tenant, pool)` — the per-scope applied-message marker, keyed at
/// `/tenants/{tenant}/pools/{pool}/inbox-acceptance`.
///
/// Every message the sequencer injects reaches L1 (the inclusion tracker can
/// prove that much), but until this record existed nothing on chain said
/// whether the kernel *accepted* it: a signature the kernel could not verify —
/// the injector signing with a key the rollup holds as neither `current` nor
/// `previous` — was an `Ok(None)` and a log line, and the injector had already
/// marked the row sent. This record is the other half of that acknowledgement:
/// the reconciler counts the scope's `final` outbox rows since `since_level`
/// and pages when the kernel admitted fewer.
///
/// **What is counted.** A message increments `admitted_count` when it has
/// verified under the tenant's key AND passed the status gate — i.e. exactly
/// when it is dispatched to a handler. A handler's own outcome (a settlement
/// entry, a `reject-*` marker, a duplicate short-circuit) is recorded by that
/// handler; this counter says only that the kernel took the message. Drops at
/// the signature (the failure this record exists to show), at the slug grammar and at the
/// status gate all leave it unmoved, which is what makes it a detector.
///
/// **Why per pool.** The signing key is per tenant, so a key skew drops every
/// pool of the tenant at once — but the outbox rows the count is diffed
/// against are keyed `(tenant_id, pool_id)`, and a pool the sequencer sends to
/// that the kernel gate refuses (never registered, `pending`) is drift worth
/// naming at the pool.
///
/// **`since_level` is where the count begins**, so a reader diffing it against
/// rows knows which rows to exclude. On first creation it is copied from the
/// rollup-global marker at `/kernel/inbox-acceptance/since-level` (the first
/// level a counting kernel ran), not the current level — a scope whose first
/// admitted message came late must not hide the drops before it. It moves only
/// when the kernel overwrites an undecodable record (kernel-owned diagnostics,
/// so self-healed rather than refused, like [`KernelInfo`]): then it is the
/// level of the rewrite, and the count restarts honestly from there.
///
/// `admitted_count` is **field 0**, the same rule the status records follow,
/// so a prefix reader sees the number immediately after the envelope tag.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub struct InboxAcceptance {
    /// Messages admitted for this scope since `since_level`. Monotone; never
    /// decremented, never reset except by the corrupt-record rewrite above.
    pub admitted_count: u64,
    /// The L1 level from which `admitted_count` counts (inclusive).
    pub since_level: u32,
    /// The L1 level of the most recent admitted message — "when did the
    /// kernel last take anything for this pool", for the operator.
    pub last_admitted_level: u32,
}

/// The two ends of the deferred-withdrawal FIFO, stored once at
/// `/outbox/deferred/cursor`. Entries live at indices `head..tail`; `head` is
/// the next index to drain and `tail` the next index to write. Both only ever
/// grow — an index is never reused, so a queued or skipped entry's index stays
/// a stable identifier in the kernel log and for the storage explorer.
///
/// One record rather than two raw scalars for the same reason the pool's
/// status and cap share a record: a reader cannot observe a `head` from one
/// write and a `tail` from another, and a later field is a `V2` variant rather
/// than a sibling key.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeferredOutboxCursor {
    /// Next index to drain. `head == tail` is the empty queue.
    pub head: u64,
    /// Next index to write.
    pub tail: u64,
}
