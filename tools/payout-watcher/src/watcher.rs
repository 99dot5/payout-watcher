//! One pass of the watcher: from each vault's cursor up to the final L1
//! level, every payout event checked against the kernel, the paid ledger and
//! the vault's own signer set, and every sweep event against the kernel's
//! sweep record, its equity and the vault's treasury.
//!
//! A level is evaluated whole, then committed: its alarms are reported, the
//! ledger moves applied and the cursor advanced, and the state written. A
//! level the rollup node has not finalised yet is DEFERRED — nothing from it
//! is reported or applied, the vault's cursor stays on it, and the next pass
//! evaluates it again — so an alarm is never raised twice and a lagging node
//! never reads as a missing record.

use crate::alarm::{Alarm, AlarmKind, Notice};
use crate::events::{BlockItem, PayoutEvent, PayoutPath, SweepEvent, scan_block};
use crate::kernel::{KernelFinding, KernelPin, check_fast_payout, check_kernel_pin};
use crate::ledger::{LedgerMove, check_cemented, check_fast};
use crate::signatures::verify_call;
use crate::source::{L1Node, NodeError, RollupNode};
use crate::state::{State, VaultState};
use crate::sweep::{SweepFinding, check_sweep};
use crate::vault_storage::{VaultStorage, decode_script};
use payout_protocol::kernel_records::parse_sweep_id;
use payout_protocol::{ChainId, VaultAddress};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

/// One watched vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchedVault {
    pub address: String,
    /// The first level to read: the vault's origination level, so the
    /// replayed paid ledger starts from empty.
    pub start_level: i64,
    /// The signer set the runner expects; any other set is an alarm.
    pub expected_payout_signers: Option<BTreeSet<String>>,
}

/// What a pass checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchConfig {
    pub vaults: Vec<WatchedVault>,
    pub kernel: KernelPin,
    /// How far the rollup node's finalised level may trail L1's before a pass
    /// that had to defer reports itself blind.
    pub max_rollup_lag_levels: i64,
}

/// Where a pass's findings go, as they are made.
pub trait Sink {
    fn alarm(&mut self, alarm: &Alarm);
    fn notice(&mut self, notice: &Notice);
    /// Called after every committed level, to persist `state`.
    fn commit(&mut self, state: &State) -> std::io::Result<()>;
}

/// How a pass ended.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PassReport {
    pub alarm_count: usize,
    pub l1_finalized_level: i64,
    pub rollup_finalized_level: i64,
    /// Vaults stopped at a level the rollup node had not finalised.
    pub deferred: Vec<(String, i64)>,
    /// A vault deferred while the rollup node trailed L1 by more than the
    /// configured lag: the pass could not check what it was asked to.
    pub blind: bool,
}

/// Why a pass stopped early.
#[derive(Debug, thiserror::Error)]
pub enum PassError {
    #[error(transparent)]
    Node(#[from] NodeError),
    #[error("state file: {0}")]
    State(#[from] std::io::Error),
}

/// Run one pass.
pub async fn run_pass<L: L1Node, R: RollupNode, S: Sink>(
    l1: &L,
    rollup: &R,
    config: &WatchConfig,
    state: &mut State,
    sink: &mut S,
) -> Result<PassReport, PassError> {
    let mut report = PassReport {
        l1_finalized_level: l1.finalized_level().await?,
        rollup_finalized_level: rollup.finalized_level().await?,
        ..PassReport::default()
    };

    if let Some(mismatch) = check_kernel_pin(rollup, &config.kernel)
        .await
        .map_err(NodeError::from)?
    {
        let alarm = Alarm::new(AlarmKind::KernelIdentityMismatch, mismatch.detail);
        sink.alarm(&alarm);
        report.alarm_count += 1;
    }

    for vault in &config.vaults {
        let entry = state
            .vaults
            .entry(vault.address.clone())
            .or_insert_with(|| VaultState::new(vault.start_level));
        entry.next_level = entry.next_level.max(vault.start_level);
    }

    let mut active: BTreeSet<String> = config.vaults.iter().map(|v| v.address.clone()).collect();
    let vaults: BTreeMap<&str, &WatchedVault> = config
        .vaults
        .iter()
        .map(|v| (v.address.as_str(), v))
        .collect();
    let Some(mut level) = config
        .vaults
        .iter()
        .map(|v| state.vaults[&v.address].next_level)
        .min()
    else {
        return Ok(report);
    };

    while level <= report.l1_finalized_level && !active.is_empty() {
        let due: BTreeSet<String> = active
            .iter()
            .filter(|a| state.vaults[*a].next_level == level)
            .cloned()
            .collect();
        if due.is_empty() {
            level += 1;
            continue;
        }
        let operations = l1.manager_operations(level).await?;
        let items = scan_block(&operations, &due);

        for address in &due {
            let vault_items: Vec<&BlockItem> = items
                .iter()
                .filter(|item| item.vault() == address)
                .collect();
            let watched = vaults[address.as_str()];
            let outcome = evaluate_level(
                l1,
                rollup,
                watched,
                &state.vaults[address],
                level,
                report.rollup_finalized_level,
                &vault_items,
            )
            .await?;

            match outcome {
                LevelOutcome::Deferred => {
                    sink.notice(&Notice::Deferred {
                        vault_address: address.clone(),
                        l1_level: level,
                        rollup_finalized_level: report.rollup_finalized_level,
                    });
                    report.deferred.push((address.clone(), level));
                    active.remove(address);
                }
                LevelOutcome::Done {
                    alarms,
                    notices,
                    next,
                } => {
                    for notice in &notices {
                        sink.notice(notice);
                    }
                    for alarm in &alarms {
                        sink.alarm(alarm);
                    }
                    report.alarm_count += alarms.len();
                    let mut next = next;
                    next.next_level = level + 1;
                    state.vaults.insert(address.clone(), next);
                }
            }
        }
        sink.commit(state)?;
        level += 1;
    }

    report.blind = !report.deferred.is_empty()
        && report.l1_finalized_level - report.rollup_finalized_level > config.max_rollup_lag_levels;

    Ok(report)
}

enum LevelOutcome {
    Deferred,
    Done {
        alarms: Vec<Alarm>,
        notices: Vec<Notice>,
        next: VaultState,
    },
}

/// The scope a fast payout's alarms carry, read from the vault before the
/// payout's block.
struct Scope {
    storage: Option<VaultStorage>,
}

fn base_alarm(kind: AlarmKind, event: &PayoutEvent, level: i64, detail: String) -> Alarm {
    let mut alarm = Alarm::new(kind, detail);
    alarm.vault_address = Some(event.vault.clone());
    alarm.session_id = Some(Uuid::from_bytes(event.session_id));
    alarm.l1_level = Some(level);
    alarm.reference = Some(event.operation_hash.clone());
    alarm.amount_mutez = Some(event.amount);
    alarm.paid_now_mutez = Some(event.paid_now);
    alarm.paid_total_mutez = Some(event.paid_total);
    alarm
}

async fn evaluate_level<L: L1Node, R: RollupNode>(
    l1: &L,
    rollup: &R,
    vault: &WatchedVault,
    current: &VaultState,
    level: i64,
    rollup_finalized_level: i64,
    items: &[&BlockItem],
) -> Result<LevelOutcome, NodeError> {
    let has_fast = items
        .iter()
        .any(|i| matches!(i, BlockItem::Event(e) if e.path == PayoutPath::Fast));
    // A fast payout and a sweep are both judged by the kernel's records, so
    // neither is judged before the node has finalised their level.
    let needs_rollup = has_fast || items.iter().any(|i| matches!(i, BlockItem::Sweep(_)));
    if needs_rollup && rollup_finalized_level < level {
        return Ok(LevelOutcome::Deferred);
    }

    let mut next = current.clone();
    let mut alarms = Vec::new();
    let mut notices = Vec::new();

    // The vault as it was before this block, once: every alarm carries its
    // scope, and a fast payout's signatures are checked against its signers.
    let scope = if !items.is_empty() {
        let script = l1.contract_script(&vault.address, level - 1).await?;
        match decode_script(&script) {
            Ok(storage) => Scope {
                storage: Some(storage),
            },
            Err(e) => {
                let mut alarm = Alarm::new(
                    AlarmKind::Undecodable,
                    format!("the vault's storage before level {level}: {e}"),
                );
                alarm.vault_address = Some(vault.address.clone());
                alarm.l1_level = Some(level);
                alarms.push(alarm);
                Scope { storage: None }
            }
        }
    } else {
        Scope { storage: None }
    };

    if has_fast
        && let Some(storage) = &scope.storage
        && let Some(signers) = &storage.payout_signers
    {
        signer_set_findings(
            vault,
            storage,
            signers,
            &mut next,
            level,
            &mut alarms,
            &mut notices,
        );
    }

    for item in items {
        let event = match item {
            BlockItem::Undecodable {
                vault: address,
                tag,
                operation_hash,
                reason,
            } => {
                let mut alarm = Alarm::new(
                    AlarmKind::Undecodable,
                    format!("a {tag} event that does not decode: {reason}"),
                );
                alarm.vault_address = Some(address.clone());
                alarm.l1_level = Some(level);
                alarm.reference = Some(operation_hash.clone());
                alarms.push(alarm);
                continue;
            }
            BlockItem::Sweep(sweep) => {
                let sweep_alarms =
                    check_sweep_event(rollup, sweep, scope.storage.as_ref(), level, &mut notices)
                        .await?;
                for mut alarm in sweep_alarms {
                    if let Some(storage) = &scope.storage {
                        alarm.tenant_id = Some(storage.tenant_id.clone());
                        alarm.pool_id = Some(storage.pool_id.clone());
                    }
                    alarms.push(alarm);
                }
                continue;
            }
            BlockItem::Event(event) => event,
        };
        let previous = next
            .paid(&event.session_id)
            .map_err(|e| NodeError::L1(format!("state for {}: {e}", vault.address)))?;
        let reported = LedgerMove {
            paid_now: event.paid_now,
            paid_total: event.paid_total,
        };
        let mismatch = match event.path {
            PayoutPath::Fast => check_fast(previous, event.amount, reported),
            PayoutPath::Cemented => check_cemented(previous, event.amount, reported),
        };
        let mut scoped = |mut alarm: Alarm| {
            if let Some(storage) = &scope.storage {
                alarm.tenant_id = Some(storage.tenant_id.clone());
                alarm.pool_id = Some(storage.pool_id.clone());
            }
            alarms.push(alarm);
        };
        if let Some(m) = mismatch {
            let mut alarm = base_alarm(
                AlarmKind::LedgerMismatch,
                event,
                level,
                format!(
                    "the {} event's ledger move does not follow the paid-ledger rule over a previous total of {} mutez",
                    event.path.tag(),
                    m.previous
                ),
            );
            alarm.expected_paid_now_mutez = m.expected.map(|e| e.paid_now);
            alarm.expected_paid_total_mutez = m.expected.map(|e| e.paid_total);
            scoped(alarm);
        } else if event.path == PayoutPath::Cemented {
            notices.push(Notice::CementedPayoutChecked {
                vault_address: event.vault.clone(),
                session_id: Uuid::from_bytes(event.session_id),
                l1_level: level,
                amount_mutez: event.amount,
                paid_now_mutez: event.paid_now,
            });
        }
        // The ledger follows what the vault reported, so one bad move is one
        // alarm, not a cascade over every later event of the session.
        next.set_paid(&event.session_id, event.paid_total);

        if event.path == PayoutPath::Fast {
            let fast_alarms =
                check_fast_event(rollup, event, scope.storage.as_ref(), level, &mut notices)
                    .await?;
            for alarm in fast_alarms {
                scoped(alarm);
            }
        }
    }

    Ok(LevelOutcome::Done {
        alarms,
        notices,
        next,
    })
}

fn signer_set_findings(
    vault: &WatchedVault,
    storage: &VaultStorage,
    found: &BTreeSet<String>,
    next: &mut VaultState,
    level: i64,
    alarms: &mut Vec<Alarm>,
    notices: &mut Vec<Notice>,
) {
    let joined = |set: &BTreeSet<String>| set.iter().cloned().collect::<Vec<_>>().join(",");
    let scoped = |kind, detail: String| {
        let mut alarm = Alarm::new(kind, detail);
        alarm.vault_address = Some(vault.address.clone());
        alarm.tenant_id = Some(storage.tenant_id.clone());
        alarm.pool_id = Some(storage.pool_id.clone());
        alarm.l1_level = Some(level);
        alarm
    };

    match &next.payout_signers {
        None => notices.push(Notice::PayoutSignersObserved {
            vault_address: vault.address.clone(),
            l1_level: level,
            payout_signers: found.iter().cloned().collect(),
        }),
        Some(previous) if previous != found => alarms.push(scoped(
            AlarmKind::PayoutSignersChanged,
            format!(
                "payout_signers changed from [{}] to [{}]",
                joined(previous),
                joined(found)
            ),
        )),
        Some(_) => {}
    }
    if let Some(expected) = &vault.expected_payout_signers
        && expected != found
    {
        alarms.push(scoped(
            AlarmKind::UnexpectedPayoutSigners,
            format!(
                "payout_signers are [{}], the configured set is [{}]",
                joined(found),
                joined(expected)
            ),
        ));
    }
    next.payout_signers = Some(found.clone());
}

async fn check_fast_event<R: RollupNode>(
    rollup: &R,
    event: &PayoutEvent,
    storage: Option<&VaultStorage>,
    level: i64,
    notices: &mut Vec<Notice>,
) -> Result<Vec<Alarm>, NodeError> {
    let mut alarms = Vec::new();
    let alarm = |kind, detail: String| base_alarm(kind, event, level, detail);
    let session_id = Uuid::from_bytes(event.session_id);

    // The signatures, against the set the vault checked them against.
    match &event.call {
        None => alarms.push(alarm(
            AlarmKind::FastPayoutCallMissing,
            "no fast_payout call naming this session in the operation".to_string(),
        )),
        Some(Err(reason)) => alarms.push(alarm(
            AlarmKind::FastPayoutCallMissing,
            format!("the fast_payout call does not decode: {reason}"),
        )),
        Some(Ok(call)) => {
            if call.amount != event.amount {
                alarms.push(alarm(
                    AlarmKind::LedgerMismatch,
                    format!(
                        "the call asked for {} mutez, the event reports {}",
                        call.amount, event.amount
                    ),
                ));
            }
            let chain_id = event.chain_id.as_deref().map(ChainId::parse);
            let vault = VaultAddress::parse(&event.vault);
            let signers = storage.map(|s| s.payout_signers.as_ref());
            match (chain_id, vault, u64::try_from(call.amount), signers) {
                (Some(Ok(chain_id)), Ok(vault), Ok(amount), Some(Some(signers))) => {
                    let verdict = verify_call(
                        &chain_id,
                        &vault,
                        &call.session_id,
                        amount,
                        &call.signatures,
                        signers,
                    );
                    for (key, verified) in &verdict.foreign {
                        let mut a = alarm(
                            AlarmKind::SignerOutsideSet,
                            format!(
                                "a signature from a key outside payout_signers ({})",
                                if *verified {
                                    "it verifies"
                                } else {
                                    "it does not verify"
                                }
                            ),
                        );
                        a.public_key = Some(key.clone());
                        alarms.push(a);
                    }
                    for (key, reason) in &verdict.invalid {
                        let mut a = alarm(
                            AlarmKind::SignatureInvalid,
                            format!("a payout signer's signature does not verify: {reason}"),
                        );
                        a.public_key = Some(key.clone());
                        alarms.push(a);
                    }
                    if verdict.under_threshold() {
                        alarms.push(alarm(
                            AlarmKind::UnderThreshold,
                            format!(
                                "{} valid signature(s) from payout_signers on a payout the vault applied",
                                verdict.valid.len()
                            ),
                        ));
                    }
                }
                (None, ..) | (Some(Err(_)), ..) => alarms.push(alarm(
                    AlarmKind::Undecodable,
                    "the operation names no readable chain id; the signatures cannot be checked"
                        .to_string(),
                )),
                (_, Err(e), ..) => alarms.push(alarm(AlarmKind::Undecodable, e.to_string())),
                (_, _, Err(_), _) => alarms.push(alarm(
                    AlarmKind::Undecodable,
                    "the amount does not fit mutez".to_string(),
                )),
                (_, _, _, Some(None)) => alarms.push(alarm(
                    AlarmKind::Undecodable,
                    "a fast payout on a vault whose storage holds no payout_signers".to_string(),
                )),
                (_, _, _, None) => {} // the storage alarm is already raised
            }
        }
    }

    // The kernel's records, under the vault's own scope.
    let Some(storage) = storage else {
        return Ok(alarms);
    };
    let finding = check_fast_payout(
        rollup,
        &storage.tenant_id,
        &storage.pool_id,
        &event.vault,
        &session_id,
        event.amount,
    )
    .await?;
    let kernel_alarm = |kind, detail: String, kernel_amount: Option<u128>| {
        let mut a = alarm(kind, detail);
        a.kernel_amount_mutez = kernel_amount;
        a
    };
    match finding {
        KernelFinding::Backed { kernel_amount } => notices.push(Notice::FastPayoutChecked {
            vault_address: event.vault.clone(),
            session_id,
            l1_level: level,
            amount_mutez: event.amount,
            kernel_amount_mutez: kernel_amount,
        }),
        KernelFinding::Short { kernel_amount } => notices.push(Notice::FastPayoutShort {
            vault_address: event.vault.clone(),
            session_id,
            l1_level: level,
            amount_mutez: event.amount,
            kernel_amount_mutez: kernel_amount,
        }),
        KernelFinding::AboveKernel { kernel_amount } => alarms.push(kernel_alarm(
            AlarmKind::FastPayoutAboveKernel,
            format!(
                "paid {} mutez fast; the kernel recorded a payout of {kernel_amount}",
                event.amount
            ),
            Some(kernel_amount),
        )),
        KernelFinding::SessionNotRecorded => alarms.push(kernel_alarm(
            AlarmKind::SessionNotRecorded,
            "the kernel has no record of this session at its finalised block".to_string(),
            None,
        )),
        KernelFinding::SessionNotEnded => alarms.push(kernel_alarm(
            AlarmKind::SessionNotEnded,
            "the kernel has not ended this session at its finalised block".to_string(),
            None,
        )),
        KernelFinding::FundingVaultMismatch { recorded } => alarms.push(kernel_alarm(
            AlarmKind::FundingVaultMismatch,
            format!("the kernel recorded the session against vault {recorded}"),
            None,
        )),
        KernelFinding::SessionAssetNotTez { asset } => alarms.push(kernel_alarm(
            AlarmKind::SessionAssetNotTez,
            format!("the session's asset is {asset}; a fast payout pays TEZ only"),
            None,
        )),
        KernelFinding::PayoutNotRecorded => alarms.push(kernel_alarm(
            AlarmKind::PayoutNotRecorded,
            "the session ended with no payout record: the kernel owes it nothing".to_string(),
            Some(0),
        )),
        KernelFinding::PayoutRecordNotASessionEndPayout { kind } => alarms.push(kernel_alarm(
            AlarmKind::PayoutRecordNotASessionEndPayout,
            format!("the record at the payout key is a {kind}"),
            None,
        )),
        KernelFinding::CorruptRecord { key, reason } => alarms.push(kernel_alarm(
            AlarmKind::CorruptRecord,
            format!("the record at {key} does not decode: {reason}"),
            None,
        )),
    }

    Ok(alarms)
}

/// Check one sweep against the kernel's records under the vault's own
/// scope and treasury. Without the vault's storage (its alarm is already
/// raised) nothing can be compared; without a treasury in it, the vault is
/// of a generation that cannot sweep, and a `sweep` event from it is a
/// shape this watcher cannot read.
async fn check_sweep_event<R: RollupNode>(
    rollup: &R,
    event: &SweepEvent,
    storage: Option<&VaultStorage>,
    level: i64,
    notices: &mut Vec<Notice>,
) -> Result<Vec<Alarm>, NodeError> {
    let reference = parse_sweep_id(&event.sweep_id).reference();
    let alarm = |kind, detail: String| {
        let mut alarm = Alarm::new(kind, detail);
        alarm.vault_address = Some(event.vault.clone());
        alarm.l1_level = Some(level);
        alarm.reference = Some(event.operation_hash.clone());
        alarm.amount_mutez = Some(event.amount);
        alarm.sweep_id = Some(reference.clone());
        alarm.treasury = Some(event.treasury.clone());
        alarm
    };
    let Some(storage) = storage else {
        return Ok(Vec::new());
    };
    let Some(treasury) = storage.treasury.as_deref() else {
        return Ok(vec![alarm(
            AlarmKind::Undecodable,
            "a sweep on a vault whose storage holds no treasury".to_string(),
        )]);
    };
    let finding = check_sweep(
        rollup,
        &storage.tenant_id,
        &storage.pool_id,
        &event.vault,
        treasury,
        event,
    )
    .await?;
    let kernel_alarm = |kind, detail: String, kernel_amount: Option<u128>| {
        let mut a = alarm(kind, detail);
        a.kernel_amount_mutez = kernel_amount;
        a
    };

    Ok(match finding {
        SweepFinding::Backed { equity_before } => {
            notices.push(Notice::SweepChecked {
                vault_address: event.vault.clone(),
                sweep_id: reference,
                l1_level: level,
                amount_mutez: event.amount,
                equity_before_mutez: equity_before,
                treasury: event.treasury.clone(),
            });
            Vec::new()
        }
        SweepFinding::NotRecorded => vec![kernel_alarm(
            AlarmKind::SweepNotRecorded,
            "the kernel has no record of this sweep at its finalised block".to_string(),
            None,
        )],
        SweepFinding::RecordNotASweep { kind } => vec![kernel_alarm(
            AlarmKind::SweepRecordNotASweep,
            format!("the record at the sweep key is a {kind}"),
            None,
        )],
        SweepFinding::AmountMismatch { kernel_amount } => vec![kernel_alarm(
            AlarmKind::SweepAmountMismatch,
            format!(
                "paid {} mutez; the kernel authorised a sweep of {kernel_amount}",
                event.amount
            ),
            Some(kernel_amount),
        )],
        SweepFinding::VaultMismatch { recorded } => vec![kernel_alarm(
            AlarmKind::SweepVaultMismatch,
            format!("the kernel authorised this sweep from vault {recorded}"),
            Some(event.amount),
        )],
        SweepFinding::TreasuryMismatch { expected } => vec![kernel_alarm(
            AlarmKind::SweepTreasuryMismatch,
            format!(
                "paid {}; the vault's treasury is {expected}",
                event.treasury
            ),
            Some(event.amount),
        )],
        SweepFinding::AboveEquity { shortfall } => vec![kernel_alarm(
            AlarmKind::SweepAboveEquity,
            format!(
                "the kernel's equity record at the request level is {shortfall} mutez short of \
                 the sweep it reserved"
            ),
            Some(event.amount),
        )],
        SweepFinding::EquityNotRecorded { reason } => vec![kernel_alarm(
            AlarmKind::SweepEquityNotRecorded,
            reason,
            Some(event.amount),
        )],
        SweepFinding::CorruptRecord { key, reason } => vec![kernel_alarm(
            AlarmKind::CorruptRecord,
            format!("the record at {key} does not decode: {reason}"),
            None,
        )],
    })
}
