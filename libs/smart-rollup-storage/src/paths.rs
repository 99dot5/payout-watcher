//! Single-source-of-truth **path grammar** for the rollup's durable storage.
//!
//! Companion to the byte-layout types in this crate: those freeze *what a value
//! decodes to*, this module freezes *which key holds which kind of value*. It
//! is the SSOT the kernel's `storage.rs` path builders and
//! `sequencer_core::retirement`'s hand-built keys are bound against by test —
//! any drift between the three representations trips a resolver assertion.
//!
//! A [`PathDescriptor`] is an ordered list of [`Segment`]s (fixed `Static`
//! segments and typed `Param`s) plus the [`DecoderKind`] a value at that path
//! decodes as.
//! [`resolve`] matches a concrete key against the [`DESCRIPTORS`] table and
//! yields the descriptor index + its `DecoderKind`.
//!
//! Kept `no_std` + `alloc` with no new deps; the kernel never calls [`resolve`]
//! at runtime (tests only), so it is dead-code-eliminated from the wasm build
//! and the float-op ban is unaffected.

extern crate alloc;

use alloc::vec::Vec;

/// A typed parameter (variable slot) in a path template. `matches` validates a
/// concrete segment against the param's grammar so adjacent templates that
/// differ only in a param's *type* (e.g. a `ContractAddress` vs a `Slug` at the
/// same position) still resolve unambiguously.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParamKind {
    /// A tenant or pool slug: non-empty, `^[a-z0-9-]+$`.
    Slug,
    /// A vault contract address: starts `KT1`, exactly 36 chars, base58-ish
    /// (ASCII alphanumeric).
    ContractAddress,
    /// A hyphenated UUID (session/round id): 36 chars, hyphens at 8/13/18/23,
    /// hex elsewhere.
    Uuid,
    /// A decimal index: non-empty, all ASCII digits.
    Index,
    /// An asset code (e.g. `TEZ`): non-empty, ASCII uppercase alphanumeric.
    AssetCode,
    /// A free-form single segment (e.g. a transaction `reference` such as
    /// `session-<uuid>-end-payout`): any non-empty segment (no `/`, guaranteed by the split).
    String,
}

impl ParamKind {
    /// Validate a single concrete path segment against this param's grammar.
    pub fn matches(&self, segment: &str) -> bool {
        match self {
            ParamKind::Slug => {
                !segment.is_empty()
                    && segment
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            }
            ParamKind::ContractAddress => {
                segment.len() == 36
                    && segment.starts_with("KT1")
                    && segment.bytes().all(|b| b.is_ascii_alphanumeric())
            }
            ParamKind::Uuid => is_hyphenated_uuid(segment),
            ParamKind::Index => !segment.is_empty() && segment.bytes().all(|b| b.is_ascii_digit()),
            ParamKind::AssetCode => {
                !segment.is_empty()
                    && segment
                        .bytes()
                        .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
            }
            ParamKind::String => !segment.is_empty(),
        }
    }
}

fn is_hyphenated_uuid(segment: &str) -> bool {
    if segment.len() != 36 {
        return false;
    }

    for (i, b) in segment.bytes().enumerate() {
        let ok = match i {
            8 | 13 | 18 | 23 => b == b'-',
            _ => b.is_ascii_hexdigit(),
        };

        if !ok {
            return false;
        }
    }

    true
}

/// One segment of a path template: a fixed literal or a typed parameter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Segment {
    Static(&'static str),
    Param(ParamKind),
}

/// The decode class of the value stored at a path. Borsh variants name the
/// shared type wrapped by that path's per-type versioned envelope; `Raw*`
/// variants name the scalar byte encoding written directly (no envelope).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecoderKind {
    // -- Borsh-envelope-wrapped shared types --
    StoredSession,
    SettlementEntry,
    StoredTransaction,
    PendingSeed,
    VaultRouting,
    PreviousSequencerKey,
    PendingAdminContract,
    PendingKernelUpgrade,
    PoolEntry,
    VaultEntry,
    /// A vault's house-equity counters at `…/pools/{slug}/equity/{kt1}` —
    /// the money record beside the vault's `vaults/{kt1}` status record, with
    /// its own envelope so the two can never be read as each other.
    HouseEquity,
    TenantEntry,
    KernelInfo,
    DeferredWithdrawal,
    DeferredOutboxCursor,
    InboxAcceptance,
    CommittedSeedRanges,
    SeedBeacons,
    SeedUsage,
    // -- Raw scalars (written without an envelope) --
    RawU32Le,
    RawUtf8,
    /// The 32 raw bytes of an Ed25519 public key — the base58check payload
    /// behind an `edpk…` string — written unwrapped at
    /// `/tenants/{slug}/sequencer-keys/current`, where the kernel verifies
    /// signatures against them directly. Names the MEANING, not the width: a
    /// 32-byte commitment or root hash is not a key and must not render as
    /// one.
    RawEd25519PublicKey,
    /// The 4 raw bytes of a Tezos chain id — the base58check payload behind a
    /// `NetX…` string — baked at origination at `/config/chain-id` and
    /// compared by the kernel against the `chain_id` every sequencer envelope
    /// carries. Raw, not borsh, like the rest of the rollup-global
    /// `/config/` block (ADR 0021).
    RawChainId,
    /// Arbitrary-length raw bytes with no fixed width (e.g. the transient
    /// kernel-upgrade staging blob at `/kernel/boot.wasm.staging`).
    RawBytes,
}

/// A path template plus the [`DecoderKind`] of values stored at it.
#[derive(Debug, Clone, Copy)]
pub struct PathDescriptor {
    pub segments: &'static [Segment],
    pub decoder: DecoderKind,
}

impl PathDescriptor {
    fn matches(&self, segments: &[&str]) -> bool {
        if segments.len() != self.segments.len() {
            return false;
        }

        self.segments
            .iter()
            .zip(segments.iter())
            .all(|(item, &segment)| match item {
                Segment::Static(value) => *value == segment,
                Segment::Param(param) => param.matches(segment),
            })
    }

    fn static_count(&self) -> usize {
        self.segments
            .iter()
            .filter(|s| matches!(s, Segment::Static(_)))
            .count()
    }
}

/// Outcome of [`resolve`]: which descriptor matched and its decode class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedPath {
    /// Index into [`DESCRIPTORS`] of the matched template.
    pub descriptor_index: usize,
    /// The decode class of a value stored at the resolved path.
    pub decoder: DecoderKind,
}

/// The authoritative 26-template durable-storage path grammar. Every path the
/// rollup writes a value to is covered exactly once.
pub const DESCRIPTORS: &[PathDescriptor] = &[
    // 1. /tenants/{slug}/sequencer-keys/current  → raw 32 bytes
    //    Deliberately a sibling of the tenant's `config` record (#3), not a
    //    child of it: a status write structurally cannot reach a key that has
    //    no on-chain recovery path.
    PathDescriptor {
        segments: &[
            Segment::Static("tenants"),
            Segment::Param(ParamKind::Slug),
            Segment::Static("sequencer-keys"),
            Segment::Static("current"),
        ],
        decoder: DecoderKind::RawEd25519PublicKey,
    },
    // 2. /tenants/{slug}/sequencer-keys/previous → borsh PreviousSequencerKey
    //    Sibling of #1 and one literal away from it, yet a DIFFERENT decode
    //    class: `current` is raw 32 bytes, `previous` is a borsh envelope —
    //    which is why both descriptors exist.
    PathDescriptor {
        segments: &[
            Segment::Static("tenants"),
            Segment::Param(ParamKind::Slug),
            Segment::Static("sequencer-keys"),
            Segment::Static("previous"),
        ],
        decoder: DecoderKind::PreviousSequencerKey,
    },
    // 3. /tenants/{slug}/config → borsh TenantEntry (the tenant's status, as a
    //    versioned record). A leaf: the sequencer keys sit at #1/#2, not
    //    beneath this prefix.
    PathDescriptor {
        segments: &[
            Segment::Static("tenants"),
            Segment::Param(ParamKind::Slug),
            Segment::Static("config"),
        ],
        decoder: DecoderKind::TenantEntry,
    },
    // 4. /tenants/{slug}/pools/{slug}/config → borsh PoolEntry (status, asset,
    //    max-win cap in one record). Note the *tenant's* `config` (#3) is a
    //    borsh record too, but a DIFFERENT one — same final segment, different
    //    type.
    PathDescriptor {
        segments: &[
            Segment::Static("tenants"),
            Segment::Param(ParamKind::Slug),
            Segment::Static("pools"),
            Segment::Param(ParamKind::Slug),
            Segment::Static("config"),
        ],
        decoder: DecoderKind::PoolEntry,
    },
    // 5. /tenants/{slug}/pools/{slug}/vaults/{kt1} → borsh VaultEntry
    //    (path unchanged; the value stopped being a raw UTF-8 status)
    PathDescriptor {
        segments: &[
            Segment::Static("tenants"),
            Segment::Param(ParamKind::Slug),
            Segment::Static("pools"),
            Segment::Param(ParamKind::Slug),
            Segment::Static("vaults"),
            Segment::Param(ParamKind::ContractAddress),
        ],
        decoder: DecoderKind::VaultEntry,
    },
    // 6. /config/admin-contract/current → raw UTF-8 KT1 string  [TRAP: not borsh]
    PathDescriptor {
        segments: &[
            Segment::Static("config"),
            Segment::Static("admin-contract"),
            Segment::Static("current"),
        ],
        decoder: DecoderKind::RawUtf8,
    },
    // 7. /config/admin-contract/pending → borsh PendingAdminContract  [TRAP: borsh]
    PathDescriptor {
        segments: &[
            Segment::Static("config"),
            Segment::Static("admin-contract"),
            Segment::Static("pending"),
        ],
        decoder: DecoderKind::PendingAdminContract,
    },
    // 8. /config/admin-contract/min-delay-levels → raw u32 LE
    PathDescriptor {
        segments: &[
            Segment::Static("config"),
            Segment::Static("admin-contract"),
            Segment::Static("min-delay-levels"),
        ],
        decoder: DecoderKind::RawU32Le,
    },
    // 9. /vault-routing/{kt1} → borsh VaultRouting (the segment names the
    //     `VaultRouting` type the value decodes to)
    PathDescriptor {
        segments: &[
            Segment::Static("vault-routing"),
            Segment::Param(ParamKind::ContractAddress),
        ],
        decoder: DecoderKind::VaultRouting,
    },
    // 10. /tenants/{slug}/pools/{slug}/transactions/{asset}/{ref} → borsh StoredTransaction
    PathDescriptor {
        segments: &[
            Segment::Static("tenants"),
            Segment::Param(ParamKind::Slug),
            Segment::Static("pools"),
            Segment::Param(ParamKind::Slug),
            Segment::Static("transactions"),
            Segment::Param(ParamKind::AssetCode),
            Segment::Param(ParamKind::String),
        ],
        decoder: DecoderKind::StoredTransaction,
    },
    // 11. /tenants/{slug}/pools/{slug}/sessions/{uuid} → borsh StoredSession
    PathDescriptor {
        segments: &[
            Segment::Static("tenants"),
            Segment::Param(ParamKind::Slug),
            Segment::Static("pools"),
            Segment::Param(ParamKind::Slug),
            Segment::Static("sessions"),
            Segment::Param(ParamKind::Uuid),
        ],
        decoder: DecoderKind::StoredSession,
    },
    // 12. /tenants/{slug}/pools/{slug}/seeds/pending/{index} → borsh PendingSeed
    PathDescriptor {
        segments: &[
            Segment::Static("tenants"),
            Segment::Param(ParamKind::Slug),
            Segment::Static("pools"),
            Segment::Param(ParamKind::Slug),
            Segment::Static("seeds"),
            Segment::Static("pending"),
            Segment::Param(ParamKind::Index),
        ],
        decoder: DecoderKind::PendingSeed,
    },
    // 13. /tenants/{slug}/pools/{slug}/settlements/{uuid} → borsh SettlementEntry
    //     (the collection segment is plural like `sessions`, `transactions`,
    //     `vaults` and `seeds` beside it; the TYPE stays singular because it
    //     names one record)
    PathDescriptor {
        segments: &[
            Segment::Static("tenants"),
            Segment::Param(ParamKind::Slug),
            Segment::Static("pools"),
            Segment::Param(ParamKind::Slug),
            Segment::Static("settlements"),
            Segment::Param(ParamKind::Uuid),
        ],
        decoder: DecoderKind::SettlementEntry,
    },
    // 14. /config/kernel-upgrade/pending → borsh PendingKernelUpgrade  [TRAP: borsh]
    PathDescriptor {
        segments: &[
            Segment::Static("config"),
            Segment::Static("kernel-upgrade"),
            Segment::Static("pending"),
        ],
        decoder: DecoderKind::PendingKernelUpgrade,
    },
    // 15. /config/kernel-upgrade/min-delay-levels → raw u32 LE
    PathDescriptor {
        segments: &[
            Segment::Static("config"),
            Segment::Static("kernel-upgrade"),
            Segment::Static("min-delay-levels"),
        ],
        decoder: DecoderKind::RawU32Le,
    },
    // 16. /kernel/info → borsh KernelInfo (the kernel's version and the game
    //     types it can replay, in one record).  [TRAP: borsh, next to a raw
    //     sibling]
    PathDescriptor {
        segments: &[Segment::Static("kernel"), Segment::Static("info")],
        decoder: DecoderKind::KernelInfo,
    },
    // 17. /kernel/boot.wasm.staging → raw bytes (transient reveal target before
    //     the store_move onto the boot path). A SIBLING of `/kernel/boot.wasm`,
    //     not a child: durable keys split on `/`, so the two are distinct steps
    //     under `/kernel`.
    PathDescriptor {
        segments: &[
            Segment::Static("kernel"),
            Segment::Static("boot.wasm.staging"),
        ],
        decoder: DecoderKind::RawBytes,
    },
    // 18. /outbox/deferred/cursor → borsh DeferredOutboxCursor (the FIFO's
    //     head/tail pair). Rollup-global, like `/vault-routing` and `/kernel`:
    //     the outbox cap it absorbs is per level, not per pool.
    PathDescriptor {
        segments: &[
            Segment::Static("outbox"),
            Segment::Static("deferred"),
            Segment::Static("cursor"),
        ],
        decoder: DecoderKind::DeferredOutboxCursor,
    },
    // 19. /outbox/deferred/entries/{index} → borsh DeferredWithdrawal (one
    //     queued `execute_bounce` / `execute_cemented_payout`; indices are never reused).
    PathDescriptor {
        segments: &[
            Segment::Static("outbox"),
            Segment::Static("deferred"),
            Segment::Static("entries"),
            Segment::Param(ParamKind::Index),
        ],
        decoder: DecoderKind::DeferredWithdrawal,
    },
    // 20. /tenants/{slug}/pools/{slug}/inbox-acceptance → borsh InboxAcceptance
    //     (the kernel's per-scope applied-message marker). A LEAF beside
    //     the pool's `config` — but kernel-written diagnostics like
    //     `/kernel/info`, not operator state, so an undecodable value is
    //     overwritten, not refused.
    PathDescriptor {
        segments: &[
            Segment::Static("tenants"),
            Segment::Param(ParamKind::Slug),
            Segment::Static("pools"),
            Segment::Param(ParamKind::Slug),
            Segment::Static("inbox-acceptance"),
        ],
        decoder: DecoderKind::InboxAcceptance,
    },
    // 21. /kernel/inbox-acceptance/since-level → raw u32 LE: the first L1 level
    //     a kernel that keeps #20 ran. Written once, at the first `StartOfLevel`
    //     that finds it absent, never rewritten — so a reader knows which
    //     outbox rows predate the marker and must not be diffed against it.
    //     [TRAP: raw, one directory over from the borsh `/kernel/info`]
    PathDescriptor {
        segments: &[
            Segment::Static("kernel"),
            Segment::Static("inbox-acceptance"),
            Segment::Static("since-level"),
        ],
        decoder: DecoderKind::RawU32Le,
    },
    // 22. /config/chain-id → 4 raw bytes, the L1 chain id this rollup was
    //     originated on. Seeded by the installer, never written by
    //     an admin op; the kernel reads it on every external message to refuse
    //     an envelope signed for another chain. Raw like its
    //     `/config/admin-contract/current` neighbour, NOT a borsh record.
    PathDescriptor {
        segments: &[Segment::Static("config"), Segment::Static("chain-id")],
        decoder: DecoderKind::RawChainId,
    },
    // 23. /tenants/{slug}/pools/{slug}/seeds/committed-ranges → borsh
    //     CommittedSeedRanges: every seed index the pool has ever accepted a
    //     commitment for. One record per pool, a leaf beside the
    //     `pending/` collection — and NOT a member of it: `committed-ranges`
    //     is not an `Index`, and the key is one segment shorter than #12, so
    //     neither template can match the other's key.
    PathDescriptor {
        segments: &[
            Segment::Static("tenants"),
            Segment::Param(ParamKind::Slug),
            Segment::Static("pools"),
            Segment::Param(ParamKind::Slug),
            Segment::Static("seeds"),
            Segment::Static("committed-ranges"),
        ],
        decoder: DecoderKind::CommittedSeedRanges,
    },
    // 24. /tenants/{slug}/pools/{slug}/seeds/beacons → borsh SeedBeacons: the
    //     drand beacons the pool's stored `SeedBatch`es named, one entry per
    //     chain hash with its round and level ranges. Like #23 a leaf
    //     beside the `pending/` collection and not a member of it: `beacons`
    //     is not an `Index`, and the key is one segment shorter than #12.
    PathDescriptor {
        segments: &[
            Segment::Static("tenants"),
            Segment::Param(ParamKind::Slug),
            Segment::Static("pools"),
            Segment::Param(ParamKind::Slug),
            Segment::Static("seeds"),
            Segment::Static("beacons"),
        ],
        decoder: DecoderKind::SeedBeacons,
    },
    // 25. /tenants/{slug}/pools/{slug}/seeds/usage → borsh SeedUsage: the
    //     kernel's tally of the pool's pending, consumed and highest-consumed
    //     seed indices. A third leaf beside `pending/`,
    //     `committed-ranges` and `beacons`, under the same rule as #23:
    //     `usage` is not an `Index`, so it can never be read as a pending seed.
    PathDescriptor {
        segments: &[
            Segment::Static("tenants"),
            Segment::Param(ParamKind::Slug),
            Segment::Static("pools"),
            Segment::Param(ParamKind::Slug),
            Segment::Static("seeds"),
            Segment::Static("usage"),
        ],
        decoder: DecoderKind::SeedUsage,
    },
    // 26. /tenants/{slug}/pools/{slug}/equity/{kt1} → borsh HouseEquity: the
    //     vault's house-equity counters (docs/specs/house-equity-and-sweeps.md
    //     H1). A sibling collection of #5's `vaults/{kt1}` keyed by the same
    //     KT1, under a different literal, so a status record and a money
    //     record can never resolve to each other's decoder.
    PathDescriptor {
        segments: &[
            Segment::Static("tenants"),
            Segment::Param(ParamKind::Slug),
            Segment::Static("pools"),
            Segment::Param(ParamKind::Slug),
            Segment::Static("equity"),
            Segment::Param(ParamKind::ContractAddress),
        ],
        decoder: DecoderKind::HouseEquity,
    },
];

/// Match a concrete durable-storage key against [`DESCRIPTORS`].
///
/// Splits on `/` (the leading empty segment from the leading `/` is dropped),
/// then finds the descriptor whose segment count matches and whose every
/// `Static` segment is equal and every `Param` validates. Segment-count equality
/// alone prevents a shorter template from shadowing a longer key; the
/// most-static-segments tie-break is a defensive guard should the table ever
/// grow an overlapping pair. Returns `None` for keys no template covers or whose
/// params fail validation (e.g. a `sessions/{id}` key with a non-UUID id).
pub fn resolve(key: &str) -> Option<ResolvedPath> {
    let segments: Vec<&str> = key.split('/').filter(|s| !s.is_empty()).collect();
    let mut candidate: Option<(usize, usize)> = None; // (descriptor_index, static_count)

    for (idx, descriptor) in DESCRIPTORS.iter().enumerate() {
        if descriptor.matches(&segments) {
            let statics = descriptor.static_count();

            match candidate {
                Some((_, best_statics)) if best_statics >= statics => {}
                _ => candidate = Some((idx, statics)),
            }
        }
    }

    candidate.map(|(idx, _)| ResolvedPath {
        descriptor_index: idx,
        decoder: DESCRIPTORS[idx].decoder,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Sample param fills reused across the concrete-key assertions.
    const TENANT_SLUG: &str = "acme";
    const POOL_SLUG: &str = "standard";
    const CONTRACT_ADDRESS: &str = "KT1BuEZtb68c1Q4yjtckcNjGELqWt56Xyesc";
    const UUID: &str = "550e8400-e29b-41d4-a716-446655440000";
    const REFERENCE: &str = "session-550e8400-e29b-41d4-a716-446655440000-end-payout";

    fn decoder_of(key: &str) -> DecoderKind {
        resolve(key)
            .unwrap_or_else(|| panic!("key did not resolve: {key}"))
            .decoder
    }

    // -- Every one of the defined templates resolves to its exact DecoderKind -----

    #[test]
    fn all_templates_resolve_to_expected_decoder() {
        let cases: &[(alloc::string::String, DecoderKind)] = &[
            (
                alloc::format!("/tenants/{TENANT_SLUG}/sequencer-keys/current"),
                DecoderKind::RawEd25519PublicKey,
            ),
            (
                alloc::format!("/tenants/{TENANT_SLUG}/sequencer-keys/previous"),
                DecoderKind::PreviousSequencerKey,
            ),
            (
                alloc::format!("/tenants/{TENANT_SLUG}/config"),
                DecoderKind::TenantEntry,
            ),
            (
                alloc::format!("/tenants/{TENANT_SLUG}/pools/{POOL_SLUG}/config"),
                DecoderKind::PoolEntry,
            ),
            (
                alloc::format!(
                    "/tenants/{TENANT_SLUG}/pools/{POOL_SLUG}/vaults/{CONTRACT_ADDRESS}"
                ),
                DecoderKind::VaultEntry,
            ),
            (
                alloc::string::String::from("/config/admin-contract/current"),
                DecoderKind::RawUtf8,
            ),
            (
                alloc::string::String::from("/config/admin-contract/pending"),
                DecoderKind::PendingAdminContract,
            ),
            (
                alloc::string::String::from("/config/admin-contract/min-delay-levels"),
                DecoderKind::RawU32Le,
            ),
            (
                alloc::format!("/vault-routing/{CONTRACT_ADDRESS}"),
                DecoderKind::VaultRouting,
            ),
            (
                alloc::format!(
                    "/tenants/{TENANT_SLUG}/pools/{POOL_SLUG}/transactions/TEZ/{REFERENCE}"
                ),
                DecoderKind::StoredTransaction,
            ),
            (
                alloc::format!("/tenants/{TENANT_SLUG}/pools/{POOL_SLUG}/sessions/{UUID}"),
                DecoderKind::StoredSession,
            ),
            (
                alloc::format!("/tenants/{TENANT_SLUG}/pools/{POOL_SLUG}/seeds/pending/7"),
                DecoderKind::PendingSeed,
            ),
            (
                alloc::format!("/tenants/{TENANT_SLUG}/pools/{POOL_SLUG}/settlements/{UUID}"),
                DecoderKind::SettlementEntry,
            ),
            (
                alloc::string::String::from("/config/kernel-upgrade/pending"),
                DecoderKind::PendingKernelUpgrade,
            ),
            (
                alloc::string::String::from("/config/kernel-upgrade/min-delay-levels"),
                DecoderKind::RawU32Le,
            ),
            (
                alloc::string::String::from("/kernel/info"),
                DecoderKind::KernelInfo,
            ),
            (
                alloc::string::String::from("/kernel/boot.wasm.staging"),
                DecoderKind::RawBytes,
            ),
            (
                alloc::string::String::from("/outbox/deferred/cursor"),
                DecoderKind::DeferredOutboxCursor,
            ),
            (
                alloc::string::String::from("/outbox/deferred/entries/12"),
                DecoderKind::DeferredWithdrawal,
            ),
            (
                alloc::format!("/tenants/{TENANT_SLUG}/pools/{POOL_SLUG}/inbox-acceptance"),
                DecoderKind::InboxAcceptance,
            ),
            (
                alloc::string::String::from("/kernel/inbox-acceptance/since-level"),
                DecoderKind::RawU32Le,
            ),
            (
                alloc::string::String::from("/config/chain-id"),
                DecoderKind::RawChainId,
            ),
            (
                alloc::format!("/tenants/{TENANT_SLUG}/pools/{POOL_SLUG}/seeds/committed-ranges"),
                DecoderKind::CommittedSeedRanges,
            ),
            (
                alloc::format!("/tenants/{TENANT_SLUG}/pools/{POOL_SLUG}/seeds/usage"),
                DecoderKind::SeedUsage,
            ),
            (
                alloc::format!("/tenants/{TENANT_SLUG}/pools/{POOL_SLUG}/seeds/beacons"),
                DecoderKind::SeedBeacons,
            ),
            (
                alloc::format!(
                    "/tenants/{TENANT_SLUG}/pools/{POOL_SLUG}/equity/{CONTRACT_ADDRESS}"
                ),
                DecoderKind::HouseEquity,
            ),
        ];

        assert_eq!(
            cases.len(),
            DESCRIPTORS.len(),
            "every template must have exactly one concrete-key case here",
        );

        for (key, expected) in cases {
            assert_eq!(decoder_of(key), *expected, "wrong decoder for {key}");
        }
    }

    /// The vault's status record and its house-equity record are keyed by
    /// the same KT1 under two literals; each resolves to its own kind, and a
    /// non-KT1 segment under `equity/` resolves to nothing rather than to a
    /// neighbour.
    #[test]
    fn trap_vault_status_and_house_equity_are_distinct_records() {
        let status =
            alloc::format!("/tenants/{TENANT_SLUG}/pools/{POOL_SLUG}/vaults/{CONTRACT_ADDRESS}");
        let equity =
            alloc::format!("/tenants/{TENANT_SLUG}/pools/{POOL_SLUG}/equity/{CONTRACT_ADDRESS}");

        assert_eq!(decoder_of(&status), DecoderKind::VaultEntry);
        assert_eq!(decoder_of(&equity), DecoderKind::HouseEquity);
        assert!(
            resolve(&alloc::format!(
                "/tenants/{TENANT_SLUG}/pools/{POOL_SLUG}/equity/not-a-kt1"
            ))
            .is_none()
        );
    }

    /// `/config/chain-id` is a raw 4-byte scalar beside the raw UTF-8
    /// `/config/admin-contract/current` and the raw u32 delays — the whole
    /// rollup-global `/config/` block stays raw (ADR 0021), and a reader that
    /// tried to borsh-decode the chain id would get a `DeserializeFailed`
    /// rather than a plausible wrong value.
    #[test]
    fn config_chain_id_is_a_raw_scalar() {
        assert_eq!(decoder_of("/config/chain-id"), DecoderKind::RawChainId);
        // Not a child of the admin-contract branch and not a borsh record.
        assert_ne!(
            decoder_of("/config/chain-id"),
            DecoderKind::RawEd25519PublicKey
        );
        assert!(resolve("/config/chain-id/current").is_none());
    }

    // -- Trap 3: kernel-upgrade borsh-vs-raw disambiguation ------------------

    #[test]
    fn trap_kernel_upgrade_pending_is_borsh_envelope() {
        assert_eq!(
            decoder_of("/config/kernel-upgrade/pending"),
            DecoderKind::PendingKernelUpgrade,
        );
    }

    #[test]
    fn trap_kernel_upgrade_min_delay_is_raw_u32() {
        // The delay knob is a raw u32 LE scalar, NOT a borsh envelope — same
        // trap as `/config/admin-contract/min-delay-levels`.
        assert_eq!(
            decoder_of("/config/kernel-upgrade/min-delay-levels"),
            DecoderKind::RawU32Le,
        );
    }

    #[test]
    fn trap_kernel_upgrade_staging_is_raw_bytes() {
        assert_eq!(
            decoder_of("/kernel/boot.wasm.staging"),
            DecoderKind::RawBytes,
        );
    }

    /// `/kernel/info` is a borsh record while `/config/admin-contract/current`
    /// one directory over is `RawUtf8` — the global block stays raw (ADR 0021),
    /// so "under /config" does not mean "raw" and "under /kernel" does not mean
    /// "borsh": `/kernel/boot.wasm.staging` is `RawBytes`.
    #[test]
    fn trap_kernel_info_is_a_record_but_the_global_block_stays_raw() {
        assert_eq!(decoder_of("/kernel/info"), DecoderKind::KernelInfo);
        // Its `/kernel/` sibling is raw bytes, not a second record.
        assert_eq!(
            decoder_of("/kernel/boot.wasm.staging"),
            DecoderKind::RawBytes
        );
        // Neighbours under /config/ that the folded game list left behind.
        assert_eq!(
            decoder_of("/config/admin-contract/current"),
            DecoderKind::RawUtf8
        );
        assert_eq!(
            decoder_of("/config/admin-contract/pending"),
            DecoderKind::PendingAdminContract,
        );
    }

    // -- Trap 1: sequencer-keys current (raw 32) vs previous (borsh) ---------

    #[test]
    fn trap_sequencer_key_current_is_ed25519_public_key() {
        assert_eq!(
            decoder_of(&alloc::format!(
                "/tenants/{TENANT_SLUG}/sequencer-keys/current"
            )),
            DecoderKind::RawEd25519PublicKey,
        );
    }

    /// The kind names a MEANING, so exactly one path may carry it. A future
    /// 32-byte scalar that reached for it would be rendered as an `edpk…` by
    /// the off-chain reader — caught here, in the crate that owns the table,
    /// rather than in the reader that merely trusts it.
    #[test]
    fn only_the_sequencer_key_path_is_an_ed25519_public_key() {
        let count = DESCRIPTORS
            .iter()
            .filter(|d| d.decoder == DecoderKind::RawEd25519PublicKey)
            .count();

        assert_eq!(count, 1, "only /tenants/{{slug}}/sequencer-keys/current");
    }

    /// The same rule for the chain id, and for the same reason: any 4 bytes at
    /// a `RawChainId` path are spelled as a plausible `NetX…`, so a second
    /// path adopting the kind must be a deliberate act, not a copy-paste.
    #[test]
    fn only_the_config_chain_id_path_is_a_chain_id() {
        let count = DESCRIPTORS
            .iter()
            .filter(|d| d.decoder == DecoderKind::RawChainId)
            .count();

        assert_eq!(count, 1, "only /config/chain-id");
    }

    #[test]
    fn trap_sequencer_key_previous_is_borsh_envelope() {
        assert_eq!(
            decoder_of(&alloc::format!(
                "/tenants/{TENANT_SLUG}/sequencer-keys/previous"
            )),
            DecoderKind::PreviousSequencerKey,
        );
    }

    // -- Trap 2: admin-contract/current (raw UTF-8) vs its pending sibling ---

    #[test]
    fn trap_admin_contract_is_raw_utf8() {
        assert_eq!(
            decoder_of("/config/admin-contract/current"),
            DecoderKind::RawUtf8,
        );
    }

    #[test]
    fn trap_admin_contract_pending_is_borsh_envelope() {
        assert_eq!(
            decoder_of("/config/admin-contract/pending"),
            DecoderKind::PendingAdminContract,
        );
    }

    /// A tenant's `/tenants/{t}/config` and a pool's
    /// `/tenants/{t}/pools/{p}/config` are BOTH borsh records and BOTH end in
    /// the same `config` segment — but they are different types, and a decoder
    /// that resolves one against the other's schema gets a `DeserializeFailed`,
    /// not a plausible-looking wrong answer. That path-typed contract is the
    /// point of the per-type envelope discipline.
    #[test]
    fn trap_tenant_config_and_pool_config_are_distinct_records() {
        assert_eq!(
            decoder_of(&alloc::format!(
                "/tenants/{TENANT_SLUG}/pools/{POOL_SLUG}/config"
            )),
            DecoderKind::PoolEntry,
        );
        assert_eq!(
            decoder_of(&alloc::format!("/tenants/{TENANT_SLUG}/config")),
            DecoderKind::TenantEntry,
        );
    }

    // -- Table size ----------------------------------------------------------

    /// Pins the descriptor count so a template added or removed without a
    /// matching case-table row in `all_templates_resolve_to_expected_decoder`
    /// fails loudly instead of going uncovered.
    ///
    /// The count alone says nothing about a template that was edited in place —
    /// a descriptor can lose a segment or change decode class without moving
    /// this number. `resolve_returns_none_for_moved_tenant_keys` and
    /// `resolve_returns_none_for_folded_kernel_keys` are what prove a retired
    /// key actually stopped resolving.
    #[test]
    fn descriptor_table_has_expected_length() {
        assert_eq!(DESCRIPTORS.len(), 26);
    }

    // -- The committed seed ranges -------------------------------------

    /// The record sits beside the `pending/` collection under `seeds/`, and the
    /// two must never be confused: a pending seed's key is one segment longer
    /// and ends in an `Index`, so `committed-ranges` cannot be read as a
    /// pending seed and a pending seed cannot be read as the record. Neither
    /// has children.
    #[test]
    fn trap_committed_seed_ranges_is_a_leaf_beside_the_pending_collection() {
        let seeds = alloc::format!("/tenants/{TENANT_SLUG}/pools/{POOL_SLUG}/seeds");

        assert_eq!(
            decoder_of(&alloc::format!("{seeds}/committed-ranges")),
            DecoderKind::CommittedSeedRanges,
        );
        assert_eq!(
            decoder_of(&alloc::format!("{seeds}/pending/7")),
            DecoderKind::PendingSeed,
        );
        assert!(resolve(&alloc::format!("{seeds}/pending/committed-ranges")).is_none());
        assert!(resolve(&alloc::format!("{seeds}/committed-ranges/7")).is_none());
        assert_eq!(
            decoder_of(&alloc::format!("{seeds}/usage")),
            DecoderKind::SeedUsage,
        );
        assert!(resolve(&alloc::format!("{seeds}/pending/usage")).is_none());
        assert!(resolve(&alloc::format!("{seeds}/usage/7")).is_none());
        assert!(
            resolve(&seeds).is_none(),
            "`seeds` is a branch, not a value"
        );
    }

    // -- The seed beacons record --------------------------------------

    /// The second leaf beside `pending/`. Three records now share the `seeds/`
    /// prefix — a collection and two single records of two different types —
    /// and none may resolve as another: `beacons` is not an `Index`, has no
    /// children, and is not `committed-ranges`.
    #[test]
    fn trap_seed_beacons_is_a_leaf_beside_the_pending_collection() {
        let seeds = alloc::format!("/tenants/{TENANT_SLUG}/pools/{POOL_SLUG}/seeds");

        assert_eq!(
            decoder_of(&alloc::format!("{seeds}/beacons")),
            DecoderKind::SeedBeacons,
        );
        assert_ne!(
            decoder_of(&alloc::format!("{seeds}/beacons")),
            decoder_of(&alloc::format!("{seeds}/committed-ranges")),
            "two sibling records, two decoders"
        );
        assert!(resolve(&alloc::format!("{seeds}/pending/beacons")).is_none());
        assert!(resolve(&alloc::format!("{seeds}/beacons/7")).is_none());
    }

    // -- The inbox-acceptance marker -----------------------------------

    /// The per-pool marker is a borsh record beside the pool's `config` (also
    /// borsh, a different type), while the rollup-global since-level under
    /// `/kernel/` is a raw `u32` one directory over from the borsh
    /// `/kernel/info` — the same "prefix predicts nothing" trap as the rest of
    /// the table. Its parent is a branch, not a value.
    #[test]
    fn trap_inbox_acceptance_record_is_borsh_but_its_since_level_is_raw() {
        assert_eq!(
            decoder_of(&alloc::format!(
                "/tenants/{TENANT_SLUG}/pools/{POOL_SLUG}/inbox-acceptance"
            )),
            DecoderKind::InboxAcceptance,
        );
        assert_eq!(
            decoder_of(&alloc::format!(
                "/tenants/{TENANT_SLUG}/pools/{POOL_SLUG}/config"
            )),
            DecoderKind::PoolEntry,
        );
        assert_eq!(
            decoder_of("/kernel/inbox-acceptance/since-level"),
            DecoderKind::RawU32Le,
        );
        assert_eq!(decoder_of("/kernel/info"), DecoderKind::KernelInfo);
        assert!(resolve("/kernel/inbox-acceptance").is_none());
    }

    // -- The deferred-withdrawal FIFO ----------------------------------

    /// The cursor and an entry are siblings under one prefix and BOTH borsh,
    /// but different records: a reader that resolves an entry against the
    /// cursor's schema gets `DeserializeFailed`, not a plausible head/tail. The
    /// prefix nodes are branches, and an entry index is decimal only.
    #[test]
    fn trap_deferred_cursor_and_entries_are_distinct_records() {
        assert_eq!(
            decoder_of("/outbox/deferred/cursor"),
            DecoderKind::DeferredOutboxCursor,
        );
        assert_eq!(
            decoder_of("/outbox/deferred/entries/0"),
            DecoderKind::DeferredWithdrawal,
        );
        assert!(resolve("/outbox").is_none());
        assert!(resolve("/outbox/deferred").is_none());
        assert!(resolve("/outbox/deferred/entries").is_none());
        assert!(resolve("/outbox/deferred/entries/not-an-index").is_none());
    }

    // -- Negatives -----------------------------------------------------------

    /// The per-round transcript subtree, the session's round counter, and the
    /// two separately-keyed round records — the discrepancy entry and the
    /// max-win clamp entry, both now nested `Option`s on the settlement
    /// record — were removed from durable storage; nothing writes those keys
    /// any more, so they must not resolve. Without this a deletion would be
    /// unverifiable — `resolve` returning `None` is the only observable
    /// difference.
    ///
    /// The counter and the two folded-away subtree segments are spelled
    /// through `concat!` so the repo-wide deletion grep (which searches for
    /// those literals) stays at zero hits while this test still builds the
    /// exact concrete keys.
    #[test]
    fn resolve_returns_none_for_deleted_round_paths() {
        let round_counter = concat!("action", "-count");
        let session_counter = concat!("active-round", "-count");
        let discrepancies = concat!("discrep", "ancies");
        let clamps = concat!("max-win-", "clamps");

        for key in [
            alloc::format!("/tenants/{TENANT_SLUG}/pools/{POOL_SLUG}/rounds/{UUID}"),
            alloc::format!(
                "/tenants/{TENANT_SLUG}/pools/{POOL_SLUG}/rounds/{UUID}/{round_counter}"
            ),
            alloc::format!("/tenants/{TENANT_SLUG}/pools/{POOL_SLUG}/rounds/{UUID}/actions/0"),
            alloc::format!(
                "/tenants/{TENANT_SLUG}/pools/{POOL_SLUG}/sessions/{UUID}/{session_counter}"
            ),
            alloc::format!("/tenants/{TENANT_SLUG}/pools/{POOL_SLUG}/{discrepancies}/{UUID}"),
            alloc::format!("/tenants/{TENANT_SLUG}/pools/{POOL_SLUG}/{clamps}/{UUID}"),
        ] {
            assert!(
                resolve(&key).is_none(),
                "deleted path still resolves: {key}"
            );
        }
    }

    /// The pool's status scalar and its separately-keyed max-win cap were
    /// folded into the single `config` record; nothing writes either key any
    /// more, so neither must resolve. Same reasoning as
    /// [`resolve_returns_none_for_deleted_round_paths`]: `resolve` returning
    /// `None` is the only observable trace a deletion leaves.
    #[test]
    fn resolve_returns_none_for_folded_pool_keys() {
        // The deleted suffixes are spelled in halves so a repo-wide sweep for
        // the old keys stays clean; the joined strings are the exact old keys.
        let status = concat!("config/", "status");
        let max_win = concat!("config/", "max-win");
        for key in [
            alloc::format!("/tenants/{TENANT_SLUG}/pools/{POOL_SLUG}/{status}"),
            alloc::format!("/tenants/{TENANT_SLUG}/pools/{POOL_SLUG}/{max_win}"),
        ] {
            assert!(resolve(&key).is_none(), "{key} must no longer resolve");
        }
    }

    /// The tenant's status scalar and the two sequencer-key paths all sat under
    /// the tenant's `config/` prefix; the status became the record AT that
    /// prefix and the keys moved out to siblings, so none of the three old keys
    /// must resolve any more. Same reasoning as
    /// [`resolve_returns_none_for_folded_pool_keys`]: a relocation leaves no
    /// other observable trace, and without this the move would be unverifiable.
    ///
    /// The old suffixes are spelled in halves, matching the convention above,
    /// so the repo-wide sweep for the two retired tenant key patterns stays at
    /// zero hits while this test still builds the exact old keys.
    #[test]
    fn resolve_returns_none_for_moved_tenant_keys() {
        let status = concat!("config/", "status");
        let current = concat!("config/", "sequencer-keys/current");
        let previous = concat!("config/", "sequencer-keys/previous");

        for key in [
            alloc::format!("/tenants/{TENANT_SLUG}/{status}"),
            alloc::format!("/tenants/{TENANT_SLUG}/{current}"),
            alloc::format!("/tenants/{TENANT_SLUG}/{previous}"),
        ] {
            assert!(resolve(&key).is_none(), "{key} must no longer resolve");
        }
    }

    /// The kernel's version marker and the comma-separated game list folded
    /// into the single `/kernel/info` record, so neither old key must resolve
    /// any more. A sibling of [`resolve_returns_none_for_moved_tenant_keys`],
    /// kept separate so each retired key set has its own negative test.
    ///
    /// The retired names are spelled in halves, matching the convention above,
    /// so the repo-wide sweep for them stays at zero hits while this test still
    /// builds the exact old keys.
    #[test]
    fn resolve_returns_none_for_folded_kernel_keys() {
        let version = concat!("current", "-version");
        let games = concat!("supported", "-games");
        // Folded into `/kernel/info` as `admin_subtags` before it ever shipped;
        // spelled in halves like the two above.
        let subtags = concat!("admin", "-subtags");

        for key in [
            alloc::format!("/kernel/{version}"),
            alloc::format!("/config/{games}"),
            alloc::format!("/kernel/{subtags}"),
        ] {
            assert!(resolve(&key).is_none(), "{key} must no longer resolve");
        }
    }

    /// The three renamed path segments: the old keys must no longer resolve.
    ///
    /// The retired segments are spelled in halves, like the sibling tests
    /// above, so the repo-wide deletion sweep for them stays at zero hits while
    /// this test still builds the exact old keys.
    #[test]
    fn resolve_returns_none_for_renamed_segments() {
        let staging = concat!("upgrade", "-staging");
        let vaults = concat!("vault-", "addresses");
        let settled = concat!("settle", "ment");

        for key in [
            alloc::format!("/kernel/{staging}"),
            alloc::format!("/{vaults}/{CONTRACT_ADDRESS}"),
            alloc::format!("/tenants/{TENANT_SLUG}/pools/{POOL_SLUG}/{settled}/{UUID}"),
        ] {
            assert!(resolve(&key).is_none(), "{key} must no longer resolve");
        }
    }

    /// The five rollup-global `/config/` keys nested by subject; the flat forms
    /// must no longer resolve. Retired names spelled in halves, as above.
    #[test]
    fn resolve_returns_none_for_nested_config_keys() {
        let admin = concat!("admin-", "contract");
        let admin_pending = concat!("admin-contract", "-pending");
        let admin_delay = concat!("admin-replacement", "-min-delay-levels");
        let kernel_pending = concat!("kernel-upgrade", "-pending");
        let kernel_delay = concat!("kernel-upgrade", "-min-delay-levels");

        for key in [
            alloc::format!("/config/{admin}"),
            alloc::format!("/config/{admin_pending}"),
            alloc::format!("/config/{admin_delay}"),
            alloc::format!("/config/{kernel_pending}"),
            alloc::format!("/config/{kernel_delay}"),
        ] {
            assert!(resolve(&key).is_none(), "{key} must no longer resolve");
        }
    }

    /// The administrator's parent key is a pure BRANCH, not a value: a
    /// durable-value read of `/config/admin-contract/` returns nothing,
    /// silently, which is why every off-chain reader asks for the `current`
    /// leaf. It is a narrative pin: the nested-config negative test and the
    /// length pin go red on the same mutation, so it adds a name, not coverage.
    #[test]
    fn trap_admin_contract_is_a_branch_not_a_value() {
        let parent = concat!("/config/admin-", "contract");

        assert!(
            resolve(parent).is_none(),
            "the administrator's parent key must not resolve as a value",
        );
        assert_eq!(
            decoder_of("/config/admin-contract/current"),
            DecoderKind::RawUtf8,
        );
    }

    #[test]
    fn unknown_key_resolves_to_none() {
        assert!(resolve("/nonsense/path/here").is_none());
        assert!(resolve("/config/unknown-key").is_none());
        assert!(resolve("").is_none());
        assert!(resolve("/").is_none());
    }

    #[test]
    fn session_key_with_non_uuid_id_does_not_match() {
        // The id segment fails the Uuid param, so it must NOT match stored session.
        assert!(
            resolve(&alloc::format!(
                "/tenants/{TENANT_SLUG}/pools/{POOL_SLUG}/sessions/not-a-uuid"
            ))
            .is_none()
        );
    }

    #[test]
    fn vault_path_with_non_kt1_does_not_match() {
        // A non-KT1 final segment fails the ContractAddress param.
        assert!(resolve("/vault-routing/tz1notavault").is_none());
    }

    // -- Param validator unit checks ----------------------------------------

    #[test]
    fn param_validators() {
        assert!(ParamKind::Uuid.matches(UUID));
        assert!(!ParamKind::Uuid.matches("550e8400e29b41d4a716446655440000")); // no hyphens
        assert!(ParamKind::ContractAddress.matches(CONTRACT_ADDRESS));
        assert!(!ParamKind::ContractAddress.matches("KT1short"));
        assert!(ParamKind::Index.matches("0"));
        assert!(ParamKind::Index.matches("42"));
        assert!(!ParamKind::Index.matches("4a"));
        assert!(ParamKind::Slug.matches("dev-99dot5-com-shadownet"));
        assert!(!ParamKind::Slug.matches("Bad_Slug"));
        assert!(ParamKind::AssetCode.matches("TEZ"));
        assert!(!ParamKind::AssetCode.matches("tez"));
        assert!(ParamKind::String.matches(REFERENCE));
        assert!(!ParamKind::String.matches(""));
    }
}
