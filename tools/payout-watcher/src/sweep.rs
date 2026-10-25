//! Comparing a `sweep` event with what the kernel recorded, read from the
//! watcher's OWN rollup node (`docs/specs/house-equity-and-sweeps.md` H4,
//! H5; ADR 0027 §4.7).
//!
//! A sweep is house profit leaving a vault for its treasury. The kernel
//! authorises it: an administrator's `Sweep` operation is refused unless its
//! amount fits the vault's house equity, and an accepted one writes the
//! `sweep-{level}-{id}` record (`payout_protocol::kernel_records::sweep_key`),
//! reserves the amount on the vault's equity record and emits the
//! `execute_sweep((sweep_id, amount))` outbox message, which the vault pays
//! to the treasury baked into its storage once the commitment cements. So a
//! sweep on L1 is sound only when:
//!
//! - the kernel holds a sweep record under the `sweep_id` the event names,
//!   for the vault that paid, of the amount paid;
//! - the equity record at the request level — the level in the `sweep_id`,
//!   read back from the node's history — covers the reservation: the kernel
//!   bounded the sweep by `(funded + stakes) − (payouts + swept)` before
//!   reserving it, so after the reservation `payouts + swept ≤ funded +
//!   stakes` must hold at that level;
//! - the address paid is the vault's `treasury`.
//!
//! Anything else is a finding: tez left a vault that the kernel's own books
//! do not back, which is exactly what the sweep design promises cannot
//! happen (a stolen multisig can at most sweep house profit, into our own
//! treasury, never a player's balance).

use borsh::BorshDeserialize;
use payout_protocol::kernel_records::{TEZ, house_equity_key, parse_sweep_id, sweep_key};
use smart_rollup_storage::v1::{HouseEquity, StoredTransactionKind};
use smart_rollup_storage::{HouseEquityEnvelope, StoredTransactionEnvelope};

use crate::events::SweepEvent;
use crate::source::{NodeError, RollupNode};

/// What the kernel's records say about one sweep.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SweepFinding {
    /// Recorded for this vault and amount, bounded by the equity at the
    /// request level, paid to the treasury: the sweep is backed.
    Backed { equity_before: u128 },
    /// No record under the event's `sweep_id`.
    NotRecorded,
    /// The record at the sweep key is not a sweep.
    RecordNotASweep { kind: String },
    /// The kernel authorised another amount.
    AmountMismatch { kernel_amount: u128 },
    /// The kernel authorised a sweep of another vault.
    VaultMismatch { recorded: String },
    /// The vault paid an address other than its baked treasury.
    TreasuryMismatch { expected: String },
    /// The equity record at the request level is short of the reservation:
    /// `payouts + swept` exceeds `funded + stakes`.
    AboveEquity { shortfall: u128 },
    /// No equity record at the request level, or one whose `swept` does not
    /// hold this sweep's amount: the kernel cannot have bounded the sweep
    /// by it.
    EquityNotRecorded { reason: String },
    /// A record that does not decode as its envelope.
    CorruptRecord { key: String, reason: String },
}

enum Read<T> {
    Absent,
    Value(T),
    Corrupt(String),
}

fn decode<T: BorshDeserialize>(bytes: Option<Vec<u8>>) -> Read<T> {
    match bytes {
        None => Read::Absent,
        Some(bytes) => match T::try_from_slice(&bytes) {
            Ok(value) => Read::Value(value),
            Err(e) => Read::Corrupt(e.to_string()),
        },
    }
}

/// Compare the sweep `event` from `vault` under `(tenant, pool)` with the
/// kernel's records, given the `treasury` the vault's storage names.
///
/// The checks run in the order the kernel's own refusals run, and the first
/// finding is the verdict: a record that exists but names another vault is
/// reported as that, not as an amount or an equity problem too.
pub async fn check_sweep<R: RollupNode>(
    rollup: &R,
    tenant: &str,
    pool: &str,
    vault: &str,
    treasury: &str,
    event: &SweepEvent,
) -> Result<SweepFinding, NodeError> {
    let id = parse_sweep_id(&event.sweep_id);
    let key = sweep_key(tenant, pool, TEZ, id.level, id.id);
    let record = match decode::<StoredTransactionEnvelope>(rollup.value(&key).await?) {
        Read::Absent => return Ok(SweepFinding::NotRecorded),
        Read::Corrupt(reason) => return Ok(SweepFinding::CorruptRecord { key, reason }),
        Read::Value(StoredTransactionEnvelope::V1(record)) => record,
    };
    if record.kind != StoredTransactionKind::Sweep {
        return Ok(SweepFinding::RecordNotASweep {
            kind: format!("{:?}", record.kind),
        });
    }
    if record.account_address != vault {
        return Ok(SweepFinding::VaultMismatch {
            recorded: record.account_address,
        });
    }
    if record.amount != event.amount {
        return Ok(SweepFinding::AmountMismatch {
            kernel_amount: record.amount,
        });
    }
    if event.treasury != treasury {
        return Ok(SweepFinding::TreasuryMismatch {
            expected: treasury.to_string(),
        });
    }

    // The equity as the kernel left it in the level it accepted the sweep:
    // `swept` already holds this amount, so the bound it checked is
    // `payouts + swept ≤ funded + stakes`.
    let Ok(level) = i64::try_from(id.level) else {
        return Ok(SweepFinding::EquityNotRecorded {
            reason: format!(
                "the sweep id names level {}, which is not an L1 level",
                id.level
            ),
        });
    };
    let key = house_equity_key(tenant, pool, vault);
    let equity: HouseEquity =
        match decode::<HouseEquityEnvelope>(rollup.value_at_level(level, &key).await?) {
            Read::Absent => {
                return Ok(SweepFinding::EquityNotRecorded {
                    reason: format!("no equity record at {key} at level {level}"),
                });
            }
            Read::Corrupt(reason) => return Ok(SweepFinding::CorruptRecord { key, reason }),
            Read::Value(HouseEquityEnvelope::V1(equity)) => equity,
        };
    if equity.swept < event.amount {
        return Ok(SweepFinding::EquityNotRecorded {
            reason: format!(
                "the equity record at level {level} has swept {} mutez, less than this sweep's {}",
                equity.swept, event.amount
            ),
        });
    }

    let inflows = equity.funded.saturating_add(equity.stakes);
    let outflows = equity.payouts.saturating_add(equity.swept);

    if outflows > inflows {
        return Ok(SweepFinding::AboveEquity {
            shortfall: outflows - inflows,
        });
    }

    Ok(SweepFinding::Backed {
        equity_before: inflows - outflows.saturating_sub(event.amount),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::RollupNodeSnapshot;
    use payout_protocol::kernel_records::sweep_id_bytes;
    use smart_rollup_storage::v1::StoredTransaction;
    use std::collections::BTreeMap;

    const TENANT: &str = "t";
    const POOL: &str = "p";
    const VAULT: &str = "KT1BuEZtb68c1Q4yjtckcNjGELqWt56Xyesc";
    const OTHER_VAULT: &str = "KT1EfTusMLoeCAAGd9MZJn5yKzFr6kJU5U91";
    const TREASURY: &str = "KT1FNqdhr7P6FM9rx6P1CoPasUYE5JPSCqup";
    const LEVEL: u64 = 1_000;
    const ID: u64 = 2;
    const AMOUNT: u128 = 4_000_000;

    fn event(amount: u128, treasury: &str) -> SweepEvent {
        SweepEvent {
            vault: VAULT.to_string(),
            sweep_id: sweep_id_bytes(LEVEL, ID),
            amount,
            treasury: treasury.to_string(),
            operation_hash: "oo1".to_string(),
        }
    }

    fn hex_of<T: borsh::BorshSerialize>(value: &T) -> String {
        hex::encode(borsh::to_vec(value).unwrap())
    }

    fn sweep_record(vault: &str, amount: u128, kind: StoredTransactionKind) -> String {
        hex_of(&StoredTransactionEnvelope::V1(StoredTransaction {
            account_address: vault.to_string(),
            asset: TEZ.to_string(),
            kind,
            amount,
        }))
    }

    fn equity(funded: u128, stakes: u128, payouts: u128, swept: u128) -> String {
        hex_of(&HouseEquityEnvelope::V1(HouseEquity {
            funded,
            stakes,
            payouts,
            swept,
        }))
    }

    /// A node holding `record` at the sweep key (finalised) and `equity`
    /// at the equity key as of the request level.
    fn node(record: Option<String>, equity_at_level: Option<String>) -> RollupNodeSnapshot {
        let mut durable = BTreeMap::new();
        if let Some(record) = record {
            durable.insert(sweep_key(TENANT, POOL, TEZ, LEVEL, ID), record);
        }
        let mut at_level = BTreeMap::new();
        if let Some(equity) = equity_at_level {
            at_level.insert(house_equity_key(TENANT, POOL, VAULT), equity);
        }
        RollupNodeSnapshot {
            finalized_level: 2_000,
            durable,
            durable_at_level: BTreeMap::from([(LEVEL as i64, at_level)]),
        }
    }

    async fn check(node: &RollupNodeSnapshot, event: &SweepEvent) -> SweepFinding {
        check_sweep(node, TENANT, POOL, VAULT, TREASURY, event)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn a_recorded_bounded_sweep_to_the_treasury_is_backed() {
        let node = node(
            Some(sweep_record(VAULT, AMOUNT, StoredTransactionKind::Sweep)),
            // funded 10, stakes 5, payouts 3, swept 4 (this sweep): equity
            // before the reservation was 12 − 4 + 4 = 8.
            Some(equity(10_000_000, 5_000_000, 3_000_000, AMOUNT)),
        );

        assert_eq!(
            check(&node, &event(AMOUNT, TREASURY)).await,
            SweepFinding::Backed {
                equity_before: 12_000_000
            }
        );
    }

    #[tokio::test]
    async fn every_way_the_kernel_does_not_back_a_sweep_is_its_own_finding() {
        let good_equity = equity(10_000_000, 5_000_000, 3_000_000, AMOUNT);
        let backed = sweep_record(VAULT, AMOUNT, StoredTransactionKind::Sweep);

        assert_eq!(
            check(
                &node(None, Some(good_equity.clone())),
                &event(AMOUNT, TREASURY)
            )
            .await,
            SweepFinding::NotRecorded
        );
        assert_eq!(
            check(
                &node(
                    Some(sweep_record(
                        VAULT,
                        AMOUNT,
                        StoredTransactionKind::RoundEndPayout
                    )),
                    Some(good_equity.clone())
                ),
                &event(AMOUNT, TREASURY)
            )
            .await,
            SweepFinding::RecordNotASweep {
                kind: "RoundEndPayout".to_string()
            }
        );
        assert_eq!(
            check(
                &node(
                    Some(sweep_record(
                        OTHER_VAULT,
                        AMOUNT,
                        StoredTransactionKind::Sweep
                    )),
                    Some(good_equity.clone())
                ),
                &event(AMOUNT, TREASURY)
            )
            .await,
            SweepFinding::VaultMismatch {
                recorded: OTHER_VAULT.to_string()
            }
        );
        assert_eq!(
            check(
                &node(
                    Some(sweep_record(
                        VAULT,
                        AMOUNT - 1,
                        StoredTransactionKind::Sweep
                    )),
                    Some(good_equity.clone())
                ),
                &event(AMOUNT, TREASURY)
            )
            .await,
            SweepFinding::AmountMismatch {
                kernel_amount: AMOUNT - 1
            }
        );
        assert_eq!(
            check(
                &node(Some(backed.clone()), Some(good_equity.clone())),
                &event(AMOUNT, OTHER_VAULT)
            )
            .await,
            SweepFinding::TreasuryMismatch {
                expected: TREASURY.to_string()
            }
        );
        // payouts 9 + swept 4 = 13 > funded 10 + stakes 2 = 12.
        assert_eq!(
            check(
                &node(
                    Some(backed.clone()),
                    Some(equity(10_000_000, 2_000_000, 9_000_000, AMOUNT))
                ),
                &event(AMOUNT, TREASURY)
            )
            .await,
            SweepFinding::AboveEquity {
                shortfall: 1_000_000
            }
        );
        assert!(matches!(
            check(&node(Some(backed.clone()), None), &event(AMOUNT, TREASURY)).await,
            SweepFinding::EquityNotRecorded { .. }
        ));
        assert!(matches!(
            check(
                &node(
                    Some(backed.clone()),
                    Some(equity(10_000_000, 0, 0, AMOUNT - 1))
                ),
                &event(AMOUNT, TREASURY)
            )
            .await,
            SweepFinding::EquityNotRecorded { .. }
        ));
        assert!(matches!(
            check(
                &node(Some("ff".to_string()), Some(good_equity)),
                &event(AMOUNT, TREASURY)
            )
            .await,
            SweepFinding::CorruptRecord { .. }
        ));
    }
}
