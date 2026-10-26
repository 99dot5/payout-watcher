//! Sync, dependency-light decode core: durable-storage key + raw bytes →
//! [`DecodedValue`] (a labeled field table).
//!
//! The key is resolved against the shared path grammar
//! ([`smart_rollup_storage::paths::resolve`]); the resulting
//! [`DecoderKind`](smart_rollup_storage::paths::DecoderKind) selects how the
//! bytes are interpreted — borsh-envelope-wrapped shared types, a raw scalar, or
//! (on any unresolved path or decode failure) an `unknown` fallback that still
//! carries the raw hex so no bytes are ever hidden.

use borsh::BorshDeserialize;
use smart_rollup_storage::v1::DeferredTarget;
use smart_rollup_storage::{
    CommittedSeedRangesEnvelope, DeferredOutboxCursorEnvelope, DeferredWithdrawalEnvelope,
    HouseEquityEnvelope, InboxAcceptanceEnvelope, KernelInfoEnvelope, PendingAdminContractEnvelope,
    PendingKernelUpgradeEnvelope, PendingSeedEnvelope, PoolEntryEnvelope,
    PreviousSequencerKeyEnvelope, SeedBeaconsEnvelope, SeedUsageEnvelope, SettlementEntryEnvelope,
    StoredSessionEnvelope, StoredTransactionEnvelope, TenantEntryEnvelope, VaultEntryEnvelope,
    VaultRoutingEnvelope,
    paths::{DecoderKind, resolve},
};
use tezos_crypto_rs::hash::{ChainId, PublicKeyEd25519};

/// One decoded field: a label and its rendered value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
    /// The field name (e.g. `"owner"`, `"balance"`, `"value"`).
    pub label: String,
    /// The rendered field value — its canonical human form (`edpk…` for a key,
    /// `NetX…` for a chain id, the decimal for a number, the text for a
    /// string).
    pub value: String,
    /// The field **as stored**, when that differs from [`Self::value`].
    ///
    /// Only byte-valued fields set it, and they set it to hex, because raw
    /// bytes have no other printable form. A number or a string is already its
    /// own stored form, so this stays `None` and a caller asking for the raw
    /// rendering gets `value` — which is why there is no "that field is not
    /// raw bytes" error to write.
    ///
    /// This is what replaced a synthetic `*_hex` sibling field: the second
    /// rendering belongs to the field, not to the record, and a `fields` table
    /// should mirror the stored struct rather than invent entries.
    pub raw: Option<String>,
    /// The entries of a list-valued field, when [`Self::value`] is their
    /// comma-join (`supported_games`, `admin_subtags`, seed `ranges`, beacon
    /// `entries`).
    ///
    /// `value` stays the bare `a,b,c` the shell readers select with `jq` and
    /// split on `,`; a renderer for people (the explorer's TUI) joins these
    /// with `", "` instead. One source for both forms, so the machine form
    /// cannot gain a space and the human form cannot lose an entry. `None`
    /// for every scalar field.
    pub items: Option<Vec<String>>,
}

/// A decoded durable-storage value: a type name, a labeled field table, and the
/// original raw hex (always present, even on `unknown`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedValue {
    /// The decoded type name (e.g. `"Session"`, `"u64"`, `"unknown"`).
    pub kind: String,
    /// One [`Field`] per struct field / scalar.
    pub fields: Vec<Field>,
    /// Hex of the raw bytes as fetched from the node.
    pub raw_hex: String,
}

/// Decode `bytes` fetched at durable-storage `key` into a [`DecodedValue`].
///
/// Resolves `key` against the shared path grammar to pick a decoder. Any borsh
/// or scalar decode failure — and any unresolved key — falls through to the
/// `unknown` branch (kind `"unknown"`, empty fields, `raw_hex` set) so a decode
/// failure never hides the bytes.
pub fn decode(key: &str, bytes: &[u8]) -> DecodedValue {
    let raw_hex = hex::encode(bytes);

    match resolve(key) {
        Some(resolved) => decode_kind(resolved.decoder, bytes, raw_hex),
        None => unknown(raw_hex),
    }
}

fn unknown(raw_hex: String) -> DecodedValue {
    DecodedValue {
        kind: "unknown".to_string(),
        fields: Vec::new(),
        raw_hex,
    }
}

/// One [`Field`], spelled out for readability at call sites.
fn field(label: &str, value: impl Into<String>) -> Field {
    Field {
        label: label.to_string(),
        value: value.into(),
        raw: None,
        items: None,
    }
}

/// A list-valued field: `value` is the entries comma-joined with no spaces
/// (what the shell readers split), `items` the entries themselves. Every list
/// in the field tables goes through here, so the join is spelled once.
fn list_field(label: &str, items: Vec<String>) -> Field {
    Field {
        label: label.to_string(),
        value: items.join(","),
        raw: None,
        items: Some(items),
    }
}

/// A byte-valued field: rendered in its canonical human form, carrying the hex
/// of the same bytes as its stored form. The only fields that differ between
/// the two renderings, and so the only ones a caller can ask for `--format raw`
/// of and get something new.
fn field_of_bytes(label: &str, value: impl Into<String>, bytes: &[u8]) -> Field {
    Field {
        label: label.to_string(),
        value: value.into(),
        raw: Some(hex::encode(bytes)),
        items: None,
    }
}

/// Render an amount — `u128` atomic units of the record's `asset` (mutez for
/// TEZ). The scale is a property of the asset, so it is not repeated here.
fn render_money(amount: u128) -> String {
    amount.to_string()
}

/// Render 16 raw UUID bytes in the hyphenated form the kernel uses for its
/// storage-path keys (`/sessions/{uuid}`), so a queued payout's session id
/// reads the same as the session record it belongs to.
fn render_uuid(bytes: &[u8; 16]) -> String {
    let hex = hex::encode(bytes);

    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

/// Render a sweep id — the 16 raw bytes `u64 BE level ‖ u64 BE id` an
/// `execute_sweep` carries — as the `sweep-{level}-{id}` reference of the
/// kernel record it names, so a queued sweep reads the same as the
/// `transactions/` row it belongs to (the hex stays as the field's raw form).
fn render_sweep_id(bytes: &[u8; 16]) -> String {
    let level = u64::from_be_bytes(bytes[..8].try_into().expect("8 bytes"));
    let id = u64::from_be_bytes(bytes[8..].try_into().expect("8 bytes"));

    format!("sweep-{level}-{id}")
}

/// Render an `Option<String>` as its value, or `"(none)"` when absent.
fn render_option(opt: &Option<String>) -> String {
    match opt {
        Some(s) => s.clone(),
        None => "(none)".to_string(),
    }
}

fn decode_kind(kind: DecoderKind, bytes: &[u8], raw_hex: String) -> DecodedValue {
    match kind {
        DecoderKind::StoredSession => match StoredSessionEnvelope::try_from_slice(bytes) {
            Ok(StoredSessionEnvelope::V1(session)) => DecodedValue {
                kind: "Session".to_string(),
                fields: vec![
                    field("owner", session.owner),
                    field("asset", session.asset),
                    field("balance", render_money(session.balance)),
                    field("funding_vault_address", session.funding_vault_address),
                    field("ended", session.ended.to_string()),
                    field("end_reason", render_option(&session.end_reason)),
                ],
                raw_hex,
            },
            Err(_) => unknown(raw_hex),
        },
        DecoderKind::SettlementEntry => match SettlementEntryEnvelope::try_from_slice(bytes) {
            Ok(SettlementEntryEnvelope::V1(entry)) => {
                let mut fields = vec![
                    field("session_id", entry.session_id),
                    field("player", entry.player),
                    field("game_type", entry.game_type),
                    field("asset", entry.asset),
                    field("stake", render_money(entry.stake)),
                    field("payout", render_money(entry.payout)),
                    field("outcome", entry.outcome),
                    field("validated", entry.validated.to_string()),
                    // Rendered whole: a truncated prefix would compare equal
                    // for two different commitments.
                    field("player_commitment", hex::encode(entry.player_commitment)),
                ];

                match entry.discrepancy {
                    Some(d) => fields.extend([
                        field("discrepancy.claimed_payout", render_money(d.claimed_payout)),
                        field(
                            "discrepancy.computed_payout",
                            render_money(d.computed_payout),
                        ),
                        field("discrepancy.computed_outcome", d.computed_outcome),
                        field("discrepancy.reason", d.reason),
                    ]),
                    None => fields.push(field("discrepancy", "(none)")),
                }

                match entry.clamp {
                    Some(c) => fields.extend([
                        field("clamp.cap", render_money(c.cap)),
                        field("clamp.stake", render_money(c.stake)),
                        field("clamp.banked", render_money(c.banked)),
                        field("clamp.original_live", render_money(c.original_live)),
                        field("clamp.clamped_live", render_money(c.clamped_live)),
                    ]),
                    None => fields.push(field("clamp", "(none)")),
                }

                DecodedValue {
                    kind: "SettlementEntry".to_string(),
                    fields,
                    raw_hex,
                }
            }
            Err(_) => unknown(raw_hex),
        },
        DecoderKind::StoredTransaction => match StoredTransactionEnvelope::try_from_slice(bytes) {
            Ok(StoredTransactionEnvelope::V1(transaction)) => DecodedValue {
                kind: "Transaction".to_string(),
                fields: vec![
                    field("account_address", transaction.account_address),
                    field("asset", transaction.asset),
                    field("kind", format!("{:?}", transaction.kind)),
                    field("amount", render_money(transaction.amount)),
                ],
                raw_hex,
            },
            Err(_) => unknown(raw_hex),
        },
        DecoderKind::PendingSeed => match PendingSeedEnvelope::try_from_slice(bytes) {
            Ok(PendingSeedEnvelope::V1(seed)) => DecodedValue {
                kind: "PendingSeed".to_string(),
                fields: vec![
                    field("hash", hex::encode(seed.hash)),
                    field("commitment_level", seed.commitment_level.to_string()),
                ],
                raw_hex,
            },
            Err(_) => unknown(raw_hex),
        },
        DecoderKind::VaultRouting => match VaultRoutingEnvelope::try_from_slice(bytes) {
            Ok(VaultRoutingEnvelope::V1 { tenant_id, pool_id }) => DecodedValue {
                kind: "VaultRouting".to_string(),
                fields: vec![field("tenant_id", tenant_id), field("pool_id", pool_id)],
                raw_hex,
            },
            Err(_) => unknown(raw_hex),
        },
        DecoderKind::PreviousSequencerKey => {
            match PreviousSequencerKeyEnvelope::try_from_slice(bytes) {
                Ok(PreviousSequencerKeyEnvelope::V1(k)) => DecodedValue {
                    kind: "PreviousSequencerKey".to_string(),
                    // `raw_hex` is the whole envelope, so it cannot isolate the
                    // key's bytes — which the fingerprint read needs. The
                    // field carries them itself, reachable as
                    // `--field public_key --format raw`.
                    //
                    // On a wrong width the hex is all there is: a decodable
                    // record whose key is not a key still renders, rather than
                    // panicking, and both renderings are then the same bytes.
                    fields: match <[u8; 32]>::try_from(k.public_key.as_slice()) {
                        Ok(arr) => vec![
                            field_of_bytes(
                                "public_key",
                                PublicKeyEd25519::from(arr).to_base58_check(),
                                &arr,
                            ),
                            field("valid_until_level", k.valid_until_level.to_string()),
                        ],
                        Err(_) => vec![
                            field_of_bytes("public_key", hex::encode(&k.public_key), &k.public_key),
                            field("valid_until_level", k.valid_until_level.to_string()),
                        ],
                    },
                    raw_hex,
                },
                Err(_) => unknown(raw_hex),
            }
        }
        DecoderKind::PendingAdminContract => {
            match PendingAdminContractEnvelope::try_from_slice(bytes) {
                Ok(PendingAdminContractEnvelope::V1(contract)) => DecodedValue {
                    kind: "PendingAdminContract".to_string(),
                    fields: vec![
                        field("new_admin", contract.new_admin),
                        field("activate_at_level", contract.activate_at_level.to_string()),
                    ],
                    raw_hex,
                },
                Err(_) => unknown(raw_hex),
            }
        }
        DecoderKind::PendingKernelUpgrade => {
            match PendingKernelUpgradeEnvelope::try_from_slice(bytes) {
                Ok(PendingKernelUpgradeEnvelope::V1(upgrade)) => DecodedValue {
                    kind: "PendingKernelUpgrade".to_string(),
                    fields: vec![
                        field("root_hash", hex::encode(upgrade.root_hash)),
                        field("activate_at_level", upgrade.activate_at_level.to_string()),
                    ],
                    raw_hex,
                },
                Err(_) => unknown(raw_hex),
            }
        }
        DecoderKind::PoolEntry => match PoolEntryEnvelope::try_from_slice(bytes) {
            Ok(PoolEntryEnvelope::V1(entry)) => DecodedValue {
                kind: "PoolEntry".to_string(),
                fields: vec![
                    field("status", entry.status),
                    field("asset", entry.asset),
                    field("max_win", render_money(entry.max_win)),
                ],
                raw_hex,
            },
            Err(_) => unknown(raw_hex),
        },
        DecoderKind::VaultEntry => match VaultEntryEnvelope::try_from_slice(bytes) {
            Ok(VaultEntryEnvelope::V1(entry)) => DecodedValue {
                kind: "VaultEntry".to_string(),
                fields: vec![field("status", entry.status)],
                raw_hex,
            },
            Err(_) => unknown(raw_hex),
        },
        DecoderKind::HouseEquity => match HouseEquityEnvelope::try_from_slice(bytes) {
            Ok(HouseEquityEnvelope::V1(equity)) => DecodedValue {
                kind: "HouseEquity".to_string(),
                fields: vec![
                    field("funded", render_money(equity.funded)),
                    field("stakes", render_money(equity.stakes)),
                    field("payouts", render_money(equity.payouts)),
                    field("swept", render_money(equity.swept)),
                    // Derived, not stored: the one number the record exists
                    // to bound (`docs/specs/house-equity-and-sweeps.md` H1),
                    // computed exactly as the kernel bounds a sweep —
                    // `(funded + stakes) − (payouts + swept)`, floored at
                    // zero — so `--field equity` answers the operator's
                    // question without a calculator.
                    field(
                        "equity",
                        render_money(
                            equity
                                .funded
                                .saturating_add(equity.stakes)
                                .saturating_sub(equity.payouts.saturating_add(equity.swept)),
                        ),
                    ),
                ],
                raw_hex,
            },
            Err(_) => unknown(raw_hex),
        },
        DecoderKind::TenantEntry => match TenantEntryEnvelope::try_from_slice(bytes) {
            Ok(TenantEntryEnvelope::V1(entry)) => DecodedValue {
                kind: "TenantEntry".to_string(),
                fields: vec![field("status", entry.status)],
                raw_hex,
            },
            Err(_) => unknown(raw_hex),
        },
        DecoderKind::KernelInfo => match KernelInfoEnvelope::try_from_slice(bytes) {
            Ok(KernelInfoEnvelope::V1(info)) => DecodedValue {
                kind: "KernelInfo".to_string(),
                fields: vec![
                    field("version", info.version),
                    // Comma-joined, deliberately: the shell readers select it
                    // with `jq -r .fields.supported_games`. Every `fields`
                    // value is a JSON string, so a list has to be rendered
                    // somehow; indexed labels would make the label set
                    // variable-length and the pin below unassertable.
                    list_field("supported_games", info.supported_games),
                    // Comma-joined for the same reason, as zero-padded
                    // two-digit hex (`0x00,0x01,…`) — the form the
                    // administrator subtags are written everywhere else.
                    list_field(
                        "admin_subtags",
                        info.admin_subtags
                            .iter()
                            .map(|subtag| format!("0x{subtag:02X}"))
                            .collect(),
                    ),
                ],
                raw_hex,
            },
            Err(_) => unknown(raw_hex),
        },
        DecoderKind::DeferredWithdrawal => {
            match DeferredWithdrawalEnvelope::try_from_slice(bytes) {
                Ok(DeferredWithdrawalEnvelope::V1(entry)) => DecodedValue {
                    kind: "DeferredWithdrawal".to_string(),
                    fields: {
                        // `target` names the vault entrypoint; the payee field
                        // that follows is the one that entrypoint takes — a
                        // bounce's `recipient`, a payout's `session_id`
                        // (hyphenated like the storage keys, hex as its raw),
                        // or a sweep's `sweep_id` (as the `sweep-{level}-{id}`
                        // record it names, hex as its raw).
                        let (target, payee) = match &entry.target {
                            DeferredTarget::Bounce { recipient } => {
                                ("bounce", field("recipient", recipient.clone()))
                            }
                            DeferredTarget::CementedPayout { session_id } => (
                                "cemented-payout",
                                field_of_bytes("session_id", render_uuid(session_id), session_id),
                            ),
                            DeferredTarget::Sweep { sweep_id } => (
                                "sweep",
                                field_of_bytes("sweep_id", render_sweep_id(sweep_id), sweep_id),
                            ),
                        };

                        vec![
                            field("tenant_id", entry.tenant_id),
                            field("pool_id", entry.pool_id),
                            field("reference", entry.reference),
                            field("vault", entry.vault),
                            field("target", target),
                            payee,
                            // The one stored amount that is `u64`: the
                            // post-narrowing L1 argument, always mutez. Widened
                            // only to share the renderer.
                            field("amount_mutez", render_money(u128::from(entry.amount_mutez))),
                        ]
                    },
                    raw_hex,
                },
                Err(_) => unknown(raw_hex),
            }
        }
        DecoderKind::DeferredOutboxCursor => {
            match DeferredOutboxCursorEnvelope::try_from_slice(bytes) {
                Ok(DeferredOutboxCursorEnvelope::V1(cursor)) => DecodedValue {
                    kind: "DeferredOutboxCursor".to_string(),
                    fields: vec![
                        field("head", cursor.head.to_string()),
                        field("tail", cursor.tail.to_string()),
                    ],
                    raw_hex,
                },
                Err(_) => unknown(raw_hex),
            }
        }
        DecoderKind::InboxAcceptance => match InboxAcceptanceEnvelope::try_from_slice(bytes) {
            Ok(InboxAcceptanceEnvelope::V1(marker)) => DecodedValue {
                kind: "InboxAcceptance".to_string(),
                fields: vec![
                    field("admitted_count", marker.admitted_count.to_string()),
                    field("since_level", marker.since_level.to_string()),
                    field(
                        "last_admitted_level",
                        marker.last_admitted_level.to_string(),
                    ),
                ],
                raw_hex,
            },
            Err(_) => unknown(raw_hex),
        },
        DecoderKind::CommittedSeedRanges => {
            match CommittedSeedRangesEnvelope::try_from_slice(bytes) {
                Ok(CommittedSeedRangesEnvelope::V1(committed)) => DecodedValue {
                    kind: "CommittedSeedRanges".to_string(),
                    // One field, mirroring the stored struct. Comma-joined
                    // `start-end` runs (both ends inclusive) for the same
                    // reason `supported_games` is joined: every `fields` value
                    // is a JSON string, and indexed labels would make the
                    // label set variable-length.
                    fields: vec![list_field(
                        "ranges",
                        committed
                            .ranges
                            .iter()
                            .map(|range| format!("{}-{}", range.start, range.end))
                            .collect(),
                    )],
                    raw_hex,
                },
                Err(_) => unknown(raw_hex),
            }
        }
        DecoderKind::SeedBeacons => match SeedBeaconsEnvelope::try_from_slice(bytes) {
            Ok(SeedBeaconsEnvelope::V1(beacons)) => DecodedValue {
                kind: "SeedBeacons".to_string(),
                // One field, mirroring the stored struct, for the reason
                // `ranges` is one field: every `fields` value is a JSON
                // string and indexed labels would make the label set
                // variable-length. Comma-joined entries, each
                // `{chain_hash}:{min_drand_round}-{max_drand_round}:{first_level}-{last_level}`
                // with the hash in the lowercase hex the wire carried.
                fields: vec![list_field(
                    "entries",
                    beacons
                        .entries
                        .iter()
                        .map(|entry| {
                            format!(
                                "{}:{}-{}:{}-{}",
                                hex::encode(entry.chain_hash),
                                entry.min_drand_round,
                                entry.max_drand_round,
                                entry.first_level,
                                entry.last_level,
                            )
                        })
                        .collect(),
                )],
                raw_hex,
            },
            Err(_) => unknown(raw_hex),
        },
        DecoderKind::SeedUsage => match SeedUsageEnvelope::try_from_slice(bytes) {
            Ok(SeedUsageEnvelope::V1(usage)) => DecodedValue {
                kind: "SeedUsage".to_string(),
                fields: vec![
                    field("consumed_count", usage.consumed_count.to_string()),
                    field("pending_count", usage.pending_count.to_string()),
                    // Empty when no seed has been consumed yet, the same way an
                    // absent optional renders elsewhere: the label is always
                    // present so `--field highest_consumed` resolves, and the
                    // empty string says "none" without inventing an index.
                    field(
                        "highest_consumed",
                        usage
                            .highest_consumed
                            .map(|index| index.to_string())
                            .unwrap_or_default(),
                    ),
                ],
                raw_hex,
            },
            Err(_) => unknown(raw_hex),
        },
        DecoderKind::RawU32Le => match <[u8; 4]>::try_from(bytes) {
            Ok(arr) => DecodedValue {
                kind: "u32".to_string(),
                fields: vec![field("value", u32::from_le_bytes(arr).to_string())],
                raw_hex,
            },
            Err(_) => unknown(raw_hex),
        },
        DecoderKind::RawUtf8 => DecodedValue {
            kind: "utf8".to_string(),
            fields: vec![field("value", String::from_utf8_lossy(bytes).into_owned())],
            raw_hex,
        },
        // The 32-byte base58check payload of an `edpk…`. The base58 IS the
        // value; the bytes stay reachable through `raw_hex` (and the CLI's
        // `--format raw`), which is what the key fingerprint is read from.
        DecoderKind::RawEd25519PublicKey => match <[u8; 32]>::try_from(bytes) {
            Ok(arr) => DecodedValue {
                kind: "ed25519-public-key".to_string(),
                fields: vec![field_of_bytes(
                    "value",
                    PublicKeyEd25519::from(arr).to_base58_check(),
                    &arr,
                )],
                raw_hex,
            },
            Err(_) => unknown(raw_hex),
        },
        // The 4-byte base58check payload of a `NetX…` chain id, rendered as the
        // `NetX…` so it compares directly against the tenant's declared
        // `chain_id`. The bytes remain in `raw_hex`.
        DecoderKind::RawChainId => match <[u8; 4]>::try_from(bytes) {
            Ok(arr) => DecodedValue {
                kind: "chain-id".to_string(),
                fields: vec![field_of_bytes(
                    "value",
                    ChainId::from(arr).to_base58_check(),
                    &arr,
                )],
                raw_hex,
            },
            Err(_) => unknown(raw_hex),
        },
        // Arbitrary-length raw bytes (no fixed width) — always renders, never
        // fails; the hex IS the value.
        DecoderKind::RawBytes => DecodedValue {
            kind: "bytes".to_string(),
            fields: vec![field("value", hex::encode(bytes))],
            raw_hex,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Distinct, non-repeating, and with a leading zero byte — so a renderer
    /// that dropped a leading `0` or rendered uppercase produces a string this
    /// file's assertions do not match.
    const PLAYER_COMMITMENT: [u8; 32] = [
        0x0a, 0xf3, 0x21, 0x9c, 0x47, 0xbe, 0x05, 0xd8, 0x63, 0x1f, 0xa4, 0x70, 0x8c, 0x2d, 0xe9,
        0x56, 0xb1, 0x38, 0xcf, 0x02, 0x7a, 0x95, 0x4e, 0xd3, 0x60, 0x8b, 0x17, 0xfa, 0x29, 0xc6,
        0x53, 0xee,
    ];
    const PLAYER_COMMITMENT_HEX: &str =
        "0af3219c47be05d8631fa4708c2de956b138cf027a954ed3608b17fa29c653ee";

    fn field_value<'a>(decoded: &'a DecodedValue, label: &str) -> &'a str {
        decoded
            .fields
            .iter()
            .find(|f| f.label == label)
            .map(|f| f.value.as_str())
            .unwrap_or_else(|| panic!("no field {label} in {decoded:?}"))
    }

    /// The operator's REAL captured session value — proves the whole
    /// resolve → borsh → field-table path end-to-end against known-good bytes.
    ///
    /// The SAME record, re-encoded once when `balance` widened from `u64` to
    /// `u128`: every field is byte-identical except that the zero balance is
    /// now sixteen zero bytes instead of eight. The capture is still the
    /// operator's, not a fixture — only the layout moved, pre-origination.
    #[test]
    fn decodes_operators_real_session() {
        let key = "/tenants/99dot5-shadownet/pools/standard/sessions/33a19445-c669-49f3-97d5-e4bd5d44ef6c";
        let hex = "0024000000747a3156384650535a37685552736732334839707045744b3359643656734c4a694377590300000054455a00000000000000000000000000000000240000004b543147436a5a774d476e5a684a7a47773336726d3867794b6568325a4a6539766a4e4501010700000045787069726564";
        let bytes = hex::decode(hex).expect("anchor hex decodes");
        let decoded = decode(key, &bytes);

        assert_eq!(decoded.kind, "Session");
        assert_eq!(
            field_value(&decoded, "owner"),
            "tz1V8FPSZ7hURsg23H9ppEtK3Yd6VsLJiCwY"
        );
        assert_eq!(field_value(&decoded, "asset"), "TEZ");
        assert_eq!(
            field_value(&decoded, "funding_vault_address"),
            "KT1GCjZwMGnZhJzGw36rm8gyKeh2ZJe9vjNE"
        );
        assert_eq!(field_value(&decoded, "ended"), "true");
        assert_eq!(field_value(&decoded, "end_reason"), "Expired");
        // Balance 0 per the captured record.
        assert_eq!(field_value(&decoded, "balance"), "0");
        assert_eq!(decoded.raw_hex, hex);
    }

    /// The same session shape with a balance ABOVE `u64::MAX`.
    ///
    /// A zero balance's sixteen zero bytes are also a valid eight-byte
    /// encoding followed by padding, so the capture above cannot by itself
    /// prove the decoder reads the full width. This one can: the high half
    /// carries a `0x01` and a decoder that stopped at eight bytes would
    /// render 123456789 instead.
    #[test]
    fn decodes_a_session_balance_above_u64_max() {
        const BALANCE: u128 = (1u128 << 64) + 123_456_789;

        const _: () = assert!(BALANCE > u64::MAX as u128);

        let key = "/tenants/99dot5-shadownet/pools/standard/sessions/33a19445-c669-49f3-97d5-e4bd5d44ef6c";
        let hex = "0024000000747a3156384650535a37685552736732334839707045744b3359643656734c4a694377590300000054455a15cd5b07000000000100000000000000240000004b543147436a5a774d476e5a684a7a47773336726d3867794b6568325a4a6539766a4e450000";
        let bytes = hex::decode(hex).expect("hex decodes");
        let decoded = decode(key, &bytes);

        assert_eq!(decoded.kind, "Session");
        assert_eq!(field_value(&decoded, "balance"), BALANCE.to_string());
        assert_ne!(
            field_value(&decoded, "balance"),
            "123456789",
            "a decoder that read only the low eight bytes would render this",
        );
        assert_eq!(decoded.raw_hex, hex);
    }

    /// Both nested records present. `clamp.clamped_live` is set above
    /// `u64::MAX` so a decoder that stopped at eight bytes would render a
    /// plausible-but-wrong smaller number instead of the full value.
    #[test]
    fn decodes_settlement_entry_with_nested_discrepancy_and_clamp() {
        const CLAMPED_LIVE: u128 = 20_000_000_000_000_000_000_000;
        const _: () = assert!(CLAMPED_LIVE > u64::MAX as u128);

        let key = "/tenants/acme/pools/standard/settlements/550e8400-e29b-41d4-a716-446655440000";
        let entry = smart_rollup_storage::v1::SettlementEntry {
            session_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            player: "tz1V8FPSZ7hURsg23H9ppEtK3Yd6VsLJiCwY".to_string(),
            game_type: "hilo:v1".to_string(),
            asset: "TEZ".to_string(),
            stake: 1_000_000,
            payout: 2_000_000,
            outcome: "win".to_string(),
            validated: false,
            player_commitment: PLAYER_COMMITMENT,
            discrepancy: Some(smart_rollup_storage::v1::Discrepancy {
                claimed_payout: 5_000_000,
                computed_payout: 2_000_000,
                computed_outcome: "lose".to_string(),
                reason: "payout-mismatch".to_string(),
            }),
            clamp: Some(smart_rollup_storage::v1::MaxWinClamp {
                cap: 10_000_000_000,
                stake: 1_000_000,
                banked: 0,
                original_live: 12_000_000_000,
                clamped_live: CLAMPED_LIVE,
            }),
        };
        let bytes = borsh::to_vec(&SettlementEntryEnvelope::V1(entry)).expect("encodes");
        let decoded = decode(key, &bytes);

        assert_eq!(decoded.kind, "SettlementEntry");
        assert_eq!(
            field_value(&decoded, "discrepancy.reason"),
            "payout-mismatch"
        );
        assert_eq!(
            field_value(&decoded, "clamp.clamped_live"),
            "20000000000000000000000",
        );
        assert_eq!(
            field_value(&decoded, "player_commitment"),
            PLAYER_COMMITMENT_HEX,
        );
    }

    /// An honest, unclamped settlement must not render as a decode failure.
    #[test]
    fn decodes_settlement_entry_without_discrepancy_or_clamp() {
        let key = "/tenants/acme/pools/standard/settlements/550e8400-e29b-41d4-a716-446655440000";
        let entry = smart_rollup_storage::v1::SettlementEntry {
            session_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            player: "tz1V8FPSZ7hURsg23H9ppEtK3Yd6VsLJiCwY".to_string(),
            game_type: "hilo:v1".to_string(),
            asset: "TEZ".to_string(),
            stake: 1_000_000,
            payout: 2_000_000,
            outcome: "win".to_string(),
            validated: true,
            player_commitment: PLAYER_COMMITMENT,
            discrepancy: None,
            clamp: None,
        };
        let bytes = borsh::to_vec(&SettlementEntryEnvelope::V1(entry)).expect("encodes");
        let decoded = decode(key, &bytes);

        assert_eq!(decoded.kind, "SettlementEntry");
        assert_eq!(field_value(&decoded, "discrepancy"), "(none)");
        assert_eq!(field_value(&decoded, "clamp"), "(none)");
        assert_eq!(
            field_value(&decoded, "player_commitment"),
            PLAYER_COMMITMENT_HEX,
        );
    }

    /// The cap above `u64::MAX` is deliberate: a decoder still reading 8 bytes
    /// would drop the high half and render a plausible-looking smaller number.
    #[test]
    fn decodes_pool_entry_with_max_win_above_u64_max() {
        const UNITS: u128 = 20_000_000_000_000_000_000;
        const _: () = assert!(UNITS > u64::MAX as u128);

        let key = "/tenants/acme/pools/standard/config";
        let entry = smart_rollup_storage::v1::PoolEntry {
            status: "active".to_string(),
            asset: "TEZ".to_string(),
            max_win: UNITS,
        };
        let bytes = borsh::to_vec(&PoolEntryEnvelope::V1(entry)).expect("encodes");
        let decoded = decode(key, &bytes);

        assert_eq!(decoded.kind, "PoolEntry");
        assert_eq!(field_value(&decoded, "status"), "active");
        assert_eq!(field_value(&decoded, "asset"), "TEZ");
        assert_eq!(field_value(&decoded, "max_win"), "20000000000000000000");
        assert_eq!(decoded.raw_hex, hex::encode(&bytes));
    }

    #[test]
    fn decodes_vault_entry() {
        let key = "/tenants/acme/pools/standard/vaults/KT1FNqdhr7P6FM9rx6P1CoPasUYE5JPSCqup";
        let entry = smart_rollup_storage::v1::VaultEntry {
            status: "draining".to_string(),
        };
        let bytes = borsh::to_vec(&VaultEntryEnvelope::V1(entry)).expect("encodes");
        let decoded = decode(key, &bytes);

        assert_eq!(decoded.kind, "VaultEntry");
        assert_eq!(field_value(&decoded, "status"), "draining");
        assert_eq!(decoded.raw_hex, hex::encode(&bytes));
    }

    #[test]
    fn decodes_tenant_entry() {
        let key = "/tenants/acme/config";
        let entry = smart_rollup_storage::v1::TenantEntry {
            status: "paused".to_string(),
        };
        let bytes = borsh::to_vec(&TenantEntryEnvelope::V1(entry)).expect("encodes");
        let decoded = decode(key, &bytes);

        assert_eq!(decoded.kind, "TenantEntry");
        assert_eq!(field_value(&decoded, "status"), "paused");
        assert_eq!(decoded.raw_hex, hex::encode(&bytes));
    }

    #[test]
    fn decodes_kernel_info() {
        let key = "/kernel/info";
        let info = smart_rollup_storage::v1::KernelInfo {
            version: "4.2.1".to_string(),
            supported_games: vec!["hilo:v1".to_string(), "plinko:v1".to_string()],
            admin_subtags: vec![0x00, 0x0D, 0x7F],
        };
        let bytes = borsh::to_vec(&KernelInfoEnvelope::V1(info)).expect("encodes");
        let decoded = decode(key, &bytes);

        assert_eq!(decoded.kind, "KernelInfo");
        assert_eq!(field_value(&decoded, "version"), "4.2.1");
        assert_eq!(
            field_value(&decoded, "supported_games"),
            "hilo:v1,plinko:v1"
        );
        assert_eq!(field_value(&decoded, "admin_subtags"), "0x00,0x0D,0x7F");
        assert_eq!(decoded.raw_hex, hex::encode(&bytes));
    }

    /// The record a live kernel 0.8.7 wrote, read off the shadownet rollup
    /// node on 2026-10-08. The explorer release before `admin_subtags` joined
    /// `KernelInfo` read these bytes as `unknown` (14 subtags left over), so
    /// this pins the decoder to what the chain actually holds, not only to a
    /// record this test encoded itself.
    #[test]
    fn decodes_a_live_kernel_info_record() {
        let bytes = hex::decode(
            "0005000000302e382e37050000000800000063726173683a76310700000068696c6f3a7631\
             0800000068796472613a7631080000006d696e65733a763109000000706c696e6b6f3a7631\
             0e000000000102030405060708090a0b0c0d",
        )
        .expect("hex decodes");
        let decoded = decode("/kernel/info", &bytes);

        assert_eq!(decoded.kind, "KernelInfo");
        assert_eq!(field_value(&decoded, "version"), "0.8.7");
        assert_eq!(
            field_value(&decoded, "supported_games"),
            "crash:v1,hilo:v1,hydra:v1,mines:v1,plinko:v1"
        );
        assert_eq!(
            field_value(&decoded, "admin_subtags"),
            "0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D"
        );
    }

    /// `supported_games` is a `Vec<String>` rendered into one `fields` string
    /// value; the join is what the shell readers depend on
    /// (`jq -r .fields.supported_games`), and the label pin alone does not
    /// assert it. Falsification: change `join(",")` to `join(", ")` in
    /// `list_field` and this test fails.
    #[test]
    fn kernel_info_supported_games_render_comma_joined_no_spaces() {
        let info = smart_rollup_storage::v1::KernelInfo {
            version: "1.0.0".to_string(),
            supported_games: vec!["a:v1".to_string(), "b:v1".to_string()],
            admin_subtags: vec![],
        };
        let bytes = borsh::to_vec(&KernelInfoEnvelope::V1(info)).expect("encodes");
        let decoded = decode("/kernel/info", &bytes);

        assert_eq!(field_value(&decoded, "supported_games"), "a:v1,b:v1");
    }

    /// A list field carries its entries beside the joined string, and only a
    /// list field does: the entries are what a human renderer spaces, the
    /// join is what the shell readers split, and they come from one `Vec`.
    #[test]
    fn list_fields_carry_their_items_and_scalars_do_not() {
        let info = smart_rollup_storage::v1::KernelInfo {
            version: "1.0.0".to_string(),
            supported_games: vec!["a:v1".to_string(), "b:v1".to_string()],
            admin_subtags: vec![0x00, 0x0D],
        };
        let bytes = borsh::to_vec(&KernelInfoEnvelope::V1(info)).expect("encodes");
        let decoded = decode("/kernel/info", &bytes);
        let items = |label: &str| {
            decoded
                .fields
                .iter()
                .find(|f| f.label == label)
                .unwrap_or_else(|| panic!("field {label}"))
                .items
                .clone()
        };

        assert_eq!(
            items("supported_games"),
            Some(vec!["a:v1".to_string(), "b:v1".to_string()])
        );
        assert_eq!(
            items("admin_subtags"),
            Some(vec!["0x00".to_string(), "0x0D".to_string()])
        );
        assert_eq!(items("version"), None);
    }

    /// The shell readers (`libs/smart-rollup/Taskfile.yml` verify-storage and
    /// the two local-env e2e scripts) select fields out of `--format json` by
    /// LABEL — `jq -er 'select(.kind=="PoolEntry") | .fields.status'`. A
    /// rename here silently breaks them, and no Rust test would notice, so the
    /// labels are pinned exactly.
    #[test]
    fn record_field_labels_are_stable() {
        let pool = decode(
            "/tenants/acme/pools/standard/config",
            &borsh::to_vec(&PoolEntryEnvelope::V1(
                smart_rollup_storage::v1::PoolEntry {
                    status: "active".to_string(),
                    asset: "TEZ".to_string(),
                    max_win: 10_000_000_000,
                },
            ))
            .expect("encodes"),
        );

        assert_eq!(pool.kind, "PoolEntry");
        assert_eq!(
            pool.fields
                .iter()
                .map(|f| f.label.as_str())
                .collect::<Vec<_>>(),
            ["status", "asset", "max_win"],
        );

        let vault = decode(
            "/tenants/acme/pools/standard/vaults/KT1FNqdhr7P6FM9rx6P1CoPasUYE5JPSCqup",
            &borsh::to_vec(&VaultEntryEnvelope::V1(
                smart_rollup_storage::v1::VaultEntry {
                    status: "active".to_string(),
                },
            ))
            .expect("encodes"),
        );

        assert_eq!(vault.kind, "VaultEntry");
        assert_eq!(
            vault
                .fields
                .iter()
                .map(|f| f.label.as_str())
                .collect::<Vec<_>>(),
            ["status"],
        );

        let tenant = decode(
            "/tenants/acme/config",
            &borsh::to_vec(&TenantEntryEnvelope::V1(
                smart_rollup_storage::v1::TenantEntry {
                    status: "active".to_string(),
                },
            ))
            .expect("encodes"),
        );

        assert_eq!(tenant.kind, "TenantEntry");
        assert_eq!(
            tenant
                .fields
                .iter()
                .map(|f| f.label.as_str())
                .collect::<Vec<_>>(),
            ["status"],
        );

        let kernel_info = decode(
            "/kernel/info",
            &borsh::to_vec(&KernelInfoEnvelope::V1(
                smart_rollup_storage::v1::KernelInfo {
                    version: "4.2.1".to_string(),
                    supported_games: vec!["hilo:v1".to_string(), "plinko:v1".to_string()],
                    admin_subtags: vec![0x00, 0x01],
                },
            ))
            .expect("encodes"),
        );

        assert_eq!(kernel_info.kind, "KernelInfo");
        assert_eq!(
            kernel_info
                .fields
                .iter()
                .map(|f| f.label.as_str())
                .collect::<Vec<_>>(),
            ["version", "supported_games", "admin_subtags"],
        );
    }

    /// A raw UTF-8 status is what the pool key used to hold one level down
    /// (`…/config` with a trailing `/status` segment); at the new record key
    /// it is not an envelope, and must surface as `unknown` carrying its hex
    /// rather than as a decoded record.
    #[test]
    fn legacy_raw_utf8_pool_status_is_unknown() {
        let key = "/tenants/acme/pools/standard/config";
        let decoded = decode(key, b"active");

        assert_eq!(decoded.kind, "unknown");
        assert_eq!(decoded.raw_hex, hex::encode(b"active"));
    }

    /// The tenant's status key moved from a raw scalar one level down
    /// (`…/config` with a trailing `/status` segment) to the borsh
    /// `TenantEntry` record at `…/config` itself (PR 3). A raw UTF-8 status
    /// left at the new key is not a valid envelope and must surface as
    /// `unknown` carrying its hex, not be silently accepted as a status.
    #[test]
    fn legacy_raw_utf8_tenant_status_is_unknown() {
        let key = "/tenants/acme/config";
        let decoded = decode(key, b"active");

        assert_eq!(decoded.kind, "unknown");
        assert_eq!(decoded.raw_hex, hex::encode(b"active"));
    }

    /// The running version and the supported-game list used to live as two
    /// separate raw UTF-8 scalars at their own legacy keys; at the new
    /// `/kernel/info` key a leftover raw string is not a valid
    /// `KernelInfoEnvelope` and must surface as `unknown` carrying its hex,
    /// not be silently accepted as a version.
    #[test]
    fn legacy_raw_utf8_kernel_version_is_unknown() {
        let key = "/kernel/info";
        let decoded = decode(key, b"0.4.0");

        assert_eq!(decoded.kind, "unknown");
        assert_eq!(decoded.raw_hex, hex::encode(b"0.4.0"));
    }

    #[test]
    fn unresolved_key_is_unknown_with_raw_hex() {
        let bytes = [0xde, 0xad, 0xbe, 0xef];
        let decoded = decode("/nonsense/path/here", &bytes);

        assert_eq!(decoded.kind, "unknown");
        assert!(decoded.fields.is_empty());
        assert_eq!(decoded.raw_hex, "deadbeef");
    }

    #[test]
    fn malformed_borsh_falls_through_to_unknown_not_hiding_bytes() {
        // A resolvable StoredSession path, but the bytes are not a valid
        // envelope — must not panic and must preserve the raw hex.
        let key = "/tenants/acme/pools/standard/sessions/550e8400-e29b-41d4-a716-446655440000";
        let bytes = [0x00, 0x01, 0x02];
        let decoded = decode(key, &bytes);

        assert_eq!(decoded.kind, "unknown");
        assert_eq!(decoded.raw_hex, "000102");
    }

    #[test]
    fn wrong_length_raw_scalar_falls_through_to_unknown() {
        // `/config/admin-contract/min-delay-levels` is a raw u32 LE; a
        // three-byte buffer is not one, and must not be rendered as a number.
        let key = "/config/admin-contract/min-delay-levels";
        let decoded = decode(key, &[1, 2, 3]);

        assert_eq!(decoded.kind, "unknown");
        assert_eq!(decoded.raw_hex, "010203");

        // The two base58-rendered scalars take the same route: the width guard
        // is what keeps a truncated buffer from being spelled as a plausible
        // `NetX…`/`edpk…`, so it must hold for them too.
        let chain = decode("/config/chain-id", &[0xd0, 0x52, 0x21]);
        assert_eq!(chain.kind, "unknown");
        assert_eq!(chain.raw_hex, "d05221");

        let key = decode("/tenants/acme/sequencer-keys/current", &SEQUENCER_KEY[..31]);
        assert_eq!(key.kind, "unknown");
        assert!(key.fields.is_empty());
    }

    // -- base58 rendering ---------------------------------------------------

    /// `config/tenants.example.yaml:46`'s declared key, and the 32 raw bytes
    /// the rollup stores for it.
    const SEQUENCER_KEY: [u8; 32] = [
        0xf5, 0xa9, 0xe5, 0x30, 0x33, 0xbf, 0x71, 0x06, 0x82, 0xfc, 0xaf, 0x85, 0x66, 0x45, 0x70,
        0xbc, 0xef, 0xfd, 0x9a, 0xe9, 0xf1, 0xeb, 0x73, 0x63, 0x91, 0x78, 0xfc, 0x79, 0xa6, 0xd8,
        0xd0, 0x75,
    ];
    const SEQUENCER_KEY_EDPK: &str = "edpkvWR5truf7AMF3PZVCXx7ieQLCW4MpNDzM3VwPfmFWVbBZwswBw";
    const SEQUENCER_KEY_HEX: &str =
        "f5a9e53033bf710682fcaf85664570bceffd9ae9f1eb73639178fc79a6d8d075";

    /// Two independently-derived vectors (pytezos, `b58encode_check` over
    /// `b'Net' ‖ payload`). One alone would pass against a hardcoded return.
    #[test]
    fn chain_id_matches_known_networks() {
        // Shadownet / the local sandbox chain baked at `/config/chain-id`.
        assert_eq!(
            ChainId::from([0xd0, 0x52, 0x21, 0x8e]).to_base58_check(),
            "NetXsqzbfFenSTS",
            "sandbox chain id"
        );
        // Tezos mainnet, `NetXdQprcVkpaWU`.
        assert_eq!(
            ChainId::from([0x7a, 0x06, 0xa7, 0x70]).to_base58_check(),
            "NetXdQprcVkpaWU",
            "mainnet chain id"
        );
    }

    /// The `sequencer_public_key` of `config/tenants.example.yaml:46` — an
    /// `edpk…` the repo already declares — against the 32 raw bytes the rollup
    /// stores for it at `/tenants/{t}/sequencer-keys/current`.
    #[test]
    fn ed25519_key_matches_the_config_fixture() {
        assert_eq!(
            PublicKeyEd25519::from(SEQUENCER_KEY).to_base58_check(),
            SEQUENCER_KEY_EDPK
        );
    }

    /// The goldens alone cannot separate "right prefix, wrong checksum" from a
    /// correct encoding — a checked decoder (`bs58`, independent of the crypto
    /// crate that encodes) can. Round-tripping also proves the prefix is
    /// INSIDE the checksummed payload rather than prepended after.
    #[test]
    fn encoded_values_round_trip_through_a_checked_decoder() {
        let key = [0x11u8; 32];
        let decoded: Vec<u8> = bs58::decode(PublicKeyEd25519::from(key).to_base58_check())
            .with_check(None)
            .into_vec()
            .expect("edpk must carry a valid base58check checksum");
        assert_eq!(&decoded[..4], &[13, 15, 37, 217]);
        assert_eq!(&decoded[4..], &key);

        let chain = [0xd0, 0x52, 0x21, 0x8e];
        let decoded: Vec<u8> = bs58::decode(ChainId::from(chain).to_base58_check())
            .with_check(None)
            .into_vec()
            .expect("NetX must carry a valid base58check checksum");
        assert_eq!(&decoded[..3], &[87, 82, 0]);
        assert_eq!(&decoded[3..], &chain);
    }

    /// The encoding is payload-sensitive: no byte of the key is dropped on the
    /// way in. Checksum coverage is proven by the round trip above, not here:
    /// base58 encodes the whole buffer as one integer, so moving the last
    /// payload byte moves the tail even under a checksum over the prefix alone.
    #[test]
    fn a_one_byte_payload_change_changes_the_encoding() {
        let a = PublicKeyEd25519::from([0x11u8; 32]).to_base58_check();
        let mut other = [0x11u8; 32];
        other[31] = 0x12;
        let b = PublicKeyEd25519::from(other).to_base58_check();

        assert_ne!(a, b, "a changed payload byte must change the encoding");
    }

    /// The value a reader compares against the tenant's declared `chain_id`,
    /// which is itself a `NetX…`. The bytes stay reachable in `raw_hex`.
    #[test]
    fn chain_id_renders_the_netx_form() {
        let decoded = decode("/config/chain-id", &[0xd0, 0x52, 0x21, 0x8e]);

        assert_eq!(decoded.kind, "chain-id");
        assert_eq!(field_value(&decoded, "value"), "NetXsqzbfFenSTS");
        assert_eq!(decoded.raw_hex, "d052218e");
    }

    #[test]
    fn sequencer_key_renders_the_edpk_form() {
        let decoded = decode("/tenants/acme/sequencer-keys/current", &SEQUENCER_KEY);

        assert_eq!(decoded.kind, "ed25519-public-key");
        assert_eq!(field_value(&decoded, "value"), SEQUENCER_KEY_EDPK);
        assert_eq!(decoded.raw_hex, SEQUENCER_KEY_HEX);
    }

    /// The field table mirrors the stored struct — two fields, no invented
    /// third. The key's bytes are reachable as the field's own `raw` form,
    /// which is what `--field public_key --format raw` serves.
    #[test]
    fn previous_sequencer_key_renders_edpk_with_its_bytes_alongside() {
        let record = smart_rollup_storage::v1::PreviousSequencerKey {
            public_key: SEQUENCER_KEY.to_vec(),
            valid_until_level: 5_050_472,
        };
        let bytes = borsh::to_vec(&PreviousSequencerKeyEnvelope::V1(record)).expect("encodes");
        let decoded = decode("/tenants/acme/sequencer-keys/previous", &bytes);

        assert_eq!(decoded.kind, "PreviousSequencerKey");
        assert_eq!(
            decoded
                .fields
                .iter()
                .map(|f| f.label.as_str())
                .collect::<Vec<_>>(),
            ["public_key", "valid_until_level"],
        );
        assert_eq!(field_value(&decoded, "public_key"), SEQUENCER_KEY_EDPK);
        assert_eq!(
            decoded.fields[0].raw.as_deref(),
            Some(SEQUENCER_KEY_HEX),
            "the key carries its stored bytes",
        );
        assert_eq!(
            decoded.fields[1].raw, None,
            "a number is already its own stored form",
        );
    }

    /// A stored key of the wrong width is a decodable record with an
    /// undecodable key: the hex must still render and the base58 must simply
    /// be absent. An `.unwrap()` on the width here would be a panic on a
    /// record the borsh layer accepted.
    #[test]
    fn previous_sequencer_key_with_a_wrong_width_key_renders_hex_not_base58() {
        let record = smart_rollup_storage::v1::PreviousSequencerKey {
            public_key: vec![0xab; 31],
            valid_until_level: 7,
        };
        let bytes = borsh::to_vec(&PreviousSequencerKeyEnvelope::V1(record)).expect("encodes");
        let decoded = decode("/tenants/acme/sequencer-keys/previous", &bytes);

        assert_eq!(decoded.kind, "PreviousSequencerKey");
        assert_eq!(
            decoded
                .fields
                .iter()
                .map(|f| f.label.as_str())
                .collect::<Vec<_>>(),
            ["public_key", "valid_until_level"],
            "the labels do not change with the width",
        );
        assert_eq!(field_value(&decoded, "public_key"), "ab".repeat(31));
        assert_eq!(
            decoded.fields[0].raw.as_deref(),
            Some("ab".repeat(31).as_str())
        );
    }

    /// §4.2's audit as a gate: the binary values whose canonical human form IS
    /// hex must not follow the key and the chain id into base58.
    ///
    /// Note what is NOT asserted here: `/kernel/boot.wasm` is absent from the
    /// descriptor table and resolves to `unknown` with no fields, so an arm
    /// for it would pass no matter what the `RawBytes` renderer did. The
    /// staging sibling is the path that actually exercises it.
    #[test]
    fn binary_fields_that_must_stay_hex_stay_hex() {
        let settlement = smart_rollup_storage::v1::SettlementEntry {
            session_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            player: "tz1V8FPSZ7hURsg23H9ppEtK3Yd6VsLJiCwY".to_string(),
            game_type: "hilo:v1".to_string(),
            asset: "TEZ".to_string(),
            stake: 1_000_000,
            payout: 2_000_000,
            outcome: "win".to_string(),
            validated: true,
            player_commitment: PLAYER_COMMITMENT,
            discrepancy: None,
            clamp: None,
        };
        let decoded = decode(
            "/tenants/acme/pools/standard/settlements/550e8400-e29b-41d4-a716-446655440000",
            &borsh::to_vec(&SettlementEntryEnvelope::V1(settlement)).expect("encodes"),
        );
        assert_eq!(
            field_value(&decoded, "player_commitment"),
            PLAYER_COMMITMENT_HEX,
        );

        let seed = smart_rollup_storage::v1::PendingSeed {
            hash: PLAYER_COMMITMENT,
            commitment_level: 42,
        };
        let decoded = decode(
            "/tenants/acme/pools/standard/seeds/pending/7",
            &borsh::to_vec(&PendingSeedEnvelope::V1(seed)).expect("encodes"),
        );
        assert_eq!(field_value(&decoded, "hash"), PLAYER_COMMITMENT_HEX);

        let upgrade = smart_rollup_storage::v1::PendingKernelUpgrade {
            root_hash: [0x5c; 33],
            activate_at_level: 99,
        };
        let decoded = decode(
            "/config/kernel-upgrade/pending",
            &borsh::to_vec(&PendingKernelUpgradeEnvelope::V1(upgrade)).expect("encodes"),
        );
        assert_eq!(field_value(&decoded, "root_hash"), "5c".repeat(33));

        let decoded = decode("/kernel/boot.wasm.staging", &[0x00, 0x61, 0x73, 0x6d]);
        assert_eq!(decoded.kind, "bytes");
        assert_eq!(field_value(&decoded, "value"), "0061736d");
    }

    /// No record invents a field: the `fields` table is the stored struct, and
    /// a second rendering of a value belongs to its field's `raw`, not to a
    /// synthetic sibling entry. A `*_hex` label reappearing means someone
    /// reached for the shape this replaced.
    #[test]
    fn no_record_carries_a_synthetic_hex_sibling() {
        let source = include_str!("decode.rs");
        let mut siblings: Vec<&str> = source
            .match_indices("field(\"")
            .map(|(at, _)| {
                let rest = &source[at + "field(\"".len()..];
                &rest[..rest.find('"').expect("a field label is a closed literal")]
            })
            .filter(|label| label.ends_with("_hex"))
            .collect();
        siblings.sort_unstable();
        siblings.dedup();

        assert!(
            siblings.is_empty(),
            "a second rendering belongs in Field::raw, not a sibling field: {siblings:?}",
        );
    }

    /// A vault's house-equity counters, each above `u64::MAX` so a decoder
    /// reading eight bytes cannot pass, plus the derived `equity` the record
    /// exists to bound.
    #[test]
    fn decodes_house_equity() {
        const FUNDED: u128 = (1u128 << 70) + 1_000;
        const STAKES: u128 = (1u128 << 70) + 500;
        const PAYOUTS: u128 = (1u128 << 70) + 300;
        const SWEPT: u128 = (1u128 << 70) + 200;
        const _: () = assert!(SWEPT > u64::MAX as u128);

        let key = "/tenants/acme/pools/standard/equity/KT1BuEZtb68c1Q4yjtckcNjGELqWt56Xyesc";
        let equity = smart_rollup_storage::v1::HouseEquity {
            funded: FUNDED,
            stakes: STAKES,
            payouts: PAYOUTS,
            swept: SWEPT,
        };
        let bytes = borsh::to_vec(&HouseEquityEnvelope::V1(equity)).expect("encodes");
        let decoded = decode(key, &bytes);

        assert_eq!(decoded.kind, "HouseEquity");
        assert_eq!(field_value(&decoded, "funded"), FUNDED.to_string());
        assert_eq!(field_value(&decoded, "stakes"), STAKES.to_string());
        assert_eq!(field_value(&decoded, "payouts"), PAYOUTS.to_string());
        assert_eq!(field_value(&decoded, "swept"), SWEPT.to_string());
        assert_eq!(
            field_value(&decoded, "equity"),
            ((FUNDED + STAKES) - (PAYOUTS + SWEPT)).to_string(),
            "equity = (funded + stakes) − (payouts + swept)"
        );
        assert_eq!(decoded.raw_hex, hex::encode(&bytes));
    }

    /// The derived `equity` floors at zero: a vault the house has lost more
    /// on than it holds renders `0`, never wraps.
    #[test]
    fn house_equity_floors_at_zero() {
        let key = "/tenants/acme/pools/standard/equity/KT1BuEZtb68c1Q4yjtckcNjGELqWt56Xyesc";
        let equity = smart_rollup_storage::v1::HouseEquity {
            funded: 10,
            stakes: 5,
            payouts: 40,
            swept: 0,
        };
        let bytes = borsh::to_vec(&HouseEquityEnvelope::V1(equity)).expect("encodes");

        assert_eq!(field_value(&decode(key, &bytes), "equity"), "0");
    }

    /// A vault's status bytes at its equity key are `unknown`, and the other
    /// way round: the two records share a KT1 and nothing else.
    #[test]
    fn vault_entry_bytes_at_the_equity_key_are_unknown() {
        let status = borsh::to_vec(&VaultEntryEnvelope::V1(
            smart_rollup_storage::v1::VaultEntry {
                status: "active".to_string(),
            },
        ))
        .expect("encodes");
        let decoded = decode(
            "/tenants/acme/pools/standard/equity/KT1BuEZtb68c1Q4yjtckcNjGELqWt56Xyesc",
            &status,
        );

        assert_eq!(decoded.kind, "unknown");
        assert_eq!(decoded.raw_hex, hex::encode(&status));
    }

    /// The transaction ledger's two newer kinds render by name like the
    /// four before them.
    #[test]
    fn decodes_fund_and_sweep_transaction_kinds() {
        use smart_rollup_storage::v1::StoredTransactionKind;

        for (kind, reference, name) in [
            (StoredTransactionKind::Fund, "fund-7-3", "Fund"),
            (StoredTransactionKind::Sweep, "sweep-9-1", "Sweep"),
        ] {
            let key = format!("/tenants/acme/pools/standard/transactions/TEZ/{reference}");
            let bytes = borsh::to_vec(&StoredTransactionEnvelope::V1(
                smart_rollup_storage::v1::StoredTransaction {
                    account_address: "KT1BuEZtb68c1Q4yjtckcNjGELqWt56Xyesc".to_string(),
                    asset: "TEZ".to_string(),
                    kind,
                    amount: 1,
                },
            ))
            .expect("encodes");
            let decoded = decode(&key, &bytes);

            assert_eq!(decoded.kind, "Transaction");
            assert_eq!(field_value(&decoded, "kind"), name);
        }
    }

    /// One queued `execute_sweep`: the target names the entrypoint, the sweep
    /// id renders as the `sweep-{level}-{id}` record it names and keeps its
    /// hex as the raw form, and no `recipient` exists — the vault pays the
    /// treasury baked into it.
    #[test]
    fn decodes_deferred_sweep() {
        // level 4_294_967_300 (above u32::MAX, so the u64 width shows), id 3.
        const SWEEP_ID: [u8; 16] = [
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x03,
        ];

        let key = "/outbox/deferred/entries/44";
        let entry = smart_rollup_storage::v1::DeferredWithdrawal {
            tenant_id: "acme".to_string(),
            pool_id: "standard".to_string(),
            reference: "sweep-4294967300-3".to_string(),
            vault: "KT1BuEZtb68c1Q4yjtckcNjGELqWt56Xyesc".to_string(),
            target: DeferredTarget::Sweep { sweep_id: SWEEP_ID },
            amount_mutez: 7,
        };
        let bytes = borsh::to_vec(&DeferredWithdrawalEnvelope::V1(entry)).expect("encodes");
        let decoded = decode(key, &bytes);

        assert_eq!(decoded.kind, "DeferredWithdrawal");
        assert_eq!(field_value(&decoded, "target"), "sweep");
        assert_eq!(field_value(&decoded, "sweep_id"), "sweep-4294967300-3");

        let sweep_field = decoded
            .fields
            .iter()
            .find(|f| f.label == "sweep_id")
            .expect("sweep_id field");

        assert_eq!(
            sweep_field.raw.as_deref(),
            Some(hex::encode(SWEEP_ID).as_str())
        );
        assert!(
            !decoded
                .fields
                .iter()
                .any(|f| f.label == "recipient" || f.label == "session_id"),
            "a sweep carries neither a recipient nor a session id"
        );
        assert_eq!(field_value(&decoded, "amount_mutez"), "7");
    }

    /// One queued `execute_bounce`. `amount_mutez` sits above
    /// `u32::MAX` so a decoder reading four bytes cannot pass.
    #[test]
    fn decodes_deferred_withdrawal() {
        const AMOUNT: u64 = (1u64 << 40) + 5;
        const _: () = assert!(AMOUNT > u32::MAX as u64);

        let key = "/outbox/deferred/entries/42";
        let entry = smart_rollup_storage::v1::DeferredWithdrawal {
            tenant_id: "acme".to_string(),
            pool_id: "standard".to_string(),
            reference: "deposit-7-3".to_string(),
            vault: "KT1BuEZtb68c1Q4yjtckcNjGELqWt56Xyesc".to_string(),
            target: DeferredTarget::Bounce {
                recipient: "tz1VSUr8wwNhLAzempoch5d6hLRiTh8Cjcjb".to_string(),
            },
            amount_mutez: AMOUNT,
        };
        let bytes = borsh::to_vec(&DeferredWithdrawalEnvelope::V1(entry)).expect("encodes");
        let decoded = decode(key, &bytes);

        assert_eq!(decoded.kind, "DeferredWithdrawal");
        assert_eq!(field_value(&decoded, "tenant_id"), "acme");
        assert_eq!(field_value(&decoded, "pool_id"), "standard");
        assert_eq!(field_value(&decoded, "reference"), "deposit-7-3");
        assert_eq!(
            field_value(&decoded, "vault"),
            "KT1BuEZtb68c1Q4yjtckcNjGELqWt56Xyesc"
        );
        assert_eq!(field_value(&decoded, "target"), "bounce");
        assert_eq!(
            field_value(&decoded, "recipient"),
            "tz1VSUr8wwNhLAzempoch5d6hLRiTh8Cjcjb"
        );
        assert!(
            !decoded.fields.iter().any(|f| f.label == "session_id"),
            "a bounce carries no session id"
        );
        assert_eq!(field_value(&decoded, "amount_mutez"), AMOUNT.to_string());
        assert_eq!(decoded.raw_hex, hex::encode(&bytes));
    }

    /// One queued `execute_cemented_payout`: the target names the entrypoint,
    /// the session id renders hyphenated like the session's own storage key and
    /// keeps its hex as the raw form, and no `recipient` field exists — the
    /// vault pays the owner it bound, so the record never held one.
    #[test]
    fn decodes_deferred_cemented_payout() {
        const SESSION_ID: [u8; 16] = [
            0x55, 0x0e, 0x84, 0x00, 0xe2, 0x9b, 0x41, 0xd4, 0xa7, 0x16, 0x44, 0x66, 0x55, 0x44,
            0x00, 0x00,
        ];

        let key = "/outbox/deferred/entries/43";
        let entry = smart_rollup_storage::v1::DeferredWithdrawal {
            tenant_id: "acme".to_string(),
            pool_id: "standard".to_string(),
            reference: "session-550e8400-e29b-41d4-a716-446655440000-end-payout".to_string(),
            vault: "KT1BuEZtb68c1Q4yjtckcNjGELqWt56Xyesc".to_string(),
            target: DeferredTarget::CementedPayout {
                session_id: SESSION_ID,
            },
            amount_mutez: 7,
        };
        let bytes = borsh::to_vec(&DeferredWithdrawalEnvelope::V1(entry)).expect("encodes");
        let decoded = decode(key, &bytes);

        assert_eq!(decoded.kind, "DeferredWithdrawal");
        assert_eq!(field_value(&decoded, "target"), "cemented-payout");
        assert_eq!(
            field_value(&decoded, "session_id"),
            "550e8400-e29b-41d4-a716-446655440000"
        );
        let session_field = decoded
            .fields
            .iter()
            .find(|f| f.label == "session_id")
            .expect("session_id field");

        assert_eq!(
            session_field.raw.as_deref(),
            Some(hex::encode(SESSION_ID).as_str())
        );
        assert!(
            !decoded.fields.iter().any(|f| f.label == "recipient"),
            "a cemented payout carries no recipient"
        );
        assert_eq!(field_value(&decoded, "amount_mutez"), "7");
    }

    /// The FIFO's head/tail pair. `head < tail` is a non-empty queue; the two
    /// values differ so a swap is caught.
    #[test]
    fn decodes_deferred_outbox_cursor() {
        let key = "/outbox/deferred/cursor";
        let cursor = smart_rollup_storage::v1::DeferredOutboxCursor { head: 7, tail: 12 };
        let bytes = borsh::to_vec(&DeferredOutboxCursorEnvelope::V1(cursor)).expect("encodes");
        let decoded = decode(key, &bytes);

        assert_eq!(decoded.kind, "DeferredOutboxCursor");
        assert_eq!(field_value(&decoded, "head"), "7");
        assert_eq!(field_value(&decoded, "tail"), "12");
    }

    /// The committed seed runs render as one comma-joined field, both ends of
    /// each run inclusive, in stored order.
    #[test]
    fn decodes_committed_seed_ranges() {
        let key = "/tenants/acme/pools/standard/seeds/committed-ranges";
        let committed = smart_rollup_storage::v1::CommittedSeedRanges {
            ranges: vec![
                smart_rollup_storage::v1::SeedIndexRange { start: 0, end: 149 },
                smart_rollup_storage::v1::SeedIndexRange {
                    start: 200,
                    end: u64::MAX,
                },
            ],
        };
        let bytes = borsh::to_vec(&CommittedSeedRangesEnvelope::V1(committed)).expect("encodes");
        let decoded = decode(key, &bytes);

        assert_eq!(decoded.kind, "CommittedSeedRanges");
        assert_eq!(decoded.fields.len(), 1);
        assert_eq!(
            field_value(&decoded, "ranges"),
            "0-149,200-18446744073709551615"
        );
        assert_eq!(decoded.raw_hex, hex::encode(&bytes));
    }

    /// A pool that has the record but no runs renders an empty field, not a
    /// missing one — `--field ranges` must still find the label.
    #[test]
    fn decodes_empty_committed_seed_ranges() {
        let key = "/tenants/acme/pools/standard/seeds/committed-ranges";
        let bytes = borsh::to_vec(&CommittedSeedRangesEnvelope::V1(
            smart_rollup_storage::v1::CommittedSeedRanges { ranges: vec![] },
        ))
        .expect("encodes");
        let decoded = decode(key, &bytes);

        assert_eq!(decoded.kind, "CommittedSeedRanges");
        assert_eq!(field_value(&decoded, "ranges"), "");
    }

    /// The usage tally renders its three counters by name; a pool that has
    /// consumed nothing renders an empty `highest_consumed`, not a zero.
    #[test]
    fn decodes_seed_usage() {
        let key = "/tenants/acme/pools/standard/seeds/usage";
        let bytes = borsh::to_vec(&SeedUsageEnvelope::V1(
            smart_rollup_storage::v1::SeedUsage {
                consumed_count: 12,
                pending_count: 488,
                highest_consumed: Some(11),
            },
        ))
        .expect("encodes");
        let decoded = decode(key, &bytes);

        assert_eq!(decoded.kind, "SeedUsage");
        assert_eq!(field_value(&decoded, "consumed_count"), "12");
        assert_eq!(field_value(&decoded, "pending_count"), "488");
        assert_eq!(field_value(&decoded, "highest_consumed"), "11");
        assert_eq!(decoded.raw_hex, hex::encode(&bytes));

        let fresh = borsh::to_vec(&SeedUsageEnvelope::V1(
            smart_rollup_storage::v1::SeedUsage {
                consumed_count: 0,
                pending_count: 50,
                highest_consumed: None,
            },
        ))
        .expect("encodes");
        let decoded = decode(key, &fresh);

        assert_eq!(field_value(&decoded, "highest_consumed"), "");
    }

    /// A pending seed's bytes at the record's key are `unknown`, never a
    /// plausible run list — the per-type envelope, again.
    #[test]
    fn pending_seed_bytes_at_the_committed_ranges_key_are_unknown() {
        let seed = smart_rollup_storage::v1::PendingSeed {
            hash: [0xab; 32],
            commitment_level: 7,
        };
        let bytes = borsh::to_vec(&PendingSeedEnvelope::V1(seed)).expect("encodes");
        let decoded = decode(
            "/tenants/acme/pools/standard/seeds/committed-ranges",
            &bytes,
        );

        assert_eq!(decoded.kind, "unknown");
        assert_eq!(decoded.raw_hex, hex::encode(&bytes));
    }

    /// The beacons record renders every entry in one field, the chain hash
    /// in the lowercase hex the wire carried.
    #[test]
    fn decodes_seed_beacons() {
        let key = "/tenants/acme/pools/standard/seeds/beacons";
        let mut chain_hash = [0u8; 32];
        hex::decode_to_slice(
            "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971",
            &mut chain_hash,
        )
        .expect("valid hex");
        let beacons = smart_rollup_storage::v1::SeedBeacons {
            entries: vec![
                smart_rollup_storage::v1::SeedBeaconEntry {
                    chain_hash,
                    min_drand_round: 12_345,
                    max_drand_round: u64::MAX,
                    first_level: 5_050_970,
                    last_level: 5_051_014,
                },
                smart_rollup_storage::v1::SeedBeaconEntry {
                    chain_hash: [0xab; 32],
                    min_drand_round: 1,
                    max_drand_round: 2,
                    first_level: 3,
                    last_level: 4,
                },
            ],
        };
        let bytes = borsh::to_vec(&SeedBeaconsEnvelope::V1(beacons)).expect("encodes");
        let decoded = decode(key, &bytes);

        assert_eq!(decoded.kind, "SeedBeacons");
        assert_eq!(decoded.fields.len(), 1);
        assert_eq!(
            field_value(&decoded, "entries"),
            "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971\
             :12345-18446744073709551615:5050970-5051014,\
             abababababababababababababababababababababababababababababababab:1-2:3-4"
        );
        assert_eq!(decoded.raw_hex, hex::encode(&bytes));
    }

    /// The sibling record's bytes at the beacons key are `unknown`, never a
    /// plausible beacon list — two leaves under `seeds/`, two envelopes.
    #[test]
    fn committed_ranges_bytes_at_the_beacons_key_are_unknown() {
        let bytes = borsh::to_vec(&CommittedSeedRangesEnvelope::V1(
            smart_rollup_storage::v1::CommittedSeedRanges {
                ranges: vec![smart_rollup_storage::v1::SeedIndexRange { start: 0, end: 9 }],
            },
        ))
        .expect("encodes");
        let decoded = decode("/tenants/acme/pools/standard/seeds/beacons", &bytes);

        assert_eq!(decoded.kind, "unknown");
        assert_eq!(decoded.raw_hex, hex::encode(&bytes));
    }

    /// An entry's bytes resolved at the cursor's key must NOT decode as a
    /// cursor: the per-type envelope makes the wrong record `unknown`, never a
    /// plausible head/tail.
    #[test]
    fn deferred_entry_bytes_at_the_cursor_key_are_unknown() {
        let entry = smart_rollup_storage::v1::DeferredWithdrawal {
            tenant_id: "acme".to_string(),
            pool_id: "standard".to_string(),
            reference: "deposit-1-2".to_string(),
            vault: "KT1BuEZtb68c1Q4yjtckcNjGELqWt56Xyesc".to_string(),
            target: DeferredTarget::Bounce {
                recipient: "tz1VSUr8wwNhLAzempoch5d6hLRiTh8Cjcjb".to_string(),
            },
            amount_mutez: 1,
        };
        let bytes = borsh::to_vec(&DeferredWithdrawalEnvelope::V1(entry)).expect("encodes");
        let decoded = decode("/outbox/deferred/cursor", &bytes);

        assert_eq!(decoded.kind, "unknown");
        assert_eq!(decoded.raw_hex, hex::encode(&bytes));
    }
}
