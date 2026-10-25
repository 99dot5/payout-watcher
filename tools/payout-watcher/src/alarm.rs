//! What the watcher reports: alarms (something paid that should not have
//! been, a sweep the kernel does not back, or a change of who can pay) and
//! notices (what it saw and skipped).
//!
//! Every alarm is one JSON line at `ERROR` with the canonical field names
//! (`tenant_id`, `pool_id`, `session_id`, `l1_level`, `reference` = the
//! operation hash), `alarm` naming the kind, `vault_address`, `sweep_id` (the
//! kernel's `sweep-{level}-{id}` reference) and `treasury` for a sweep, and
//! amounts in mutez as decimal strings (`*_mutez`: a `u128` does not fit a
//! JSON number).

use uuid::Uuid;

/// The kinds of alarm, as the `alarm` field spells them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum AlarmKind {
    /// A fast payout above the kernel's recorded payout.
    FastPayoutAboveKernel,
    /// A session paid fast that the kernel has no record of.
    SessionNotRecorded,
    /// A session paid fast that the kernel has not ended.
    SessionNotEnded,
    /// A session paid fast that ended with no payout record.
    PayoutNotRecorded,
    /// The record at the payout key is not the session payout (the kernel's
    /// `SessionEndPayout` row; `RoundEndPayout` is the per-round credit).
    PayoutRecordNotASessionEndPayout,
    /// A session paid fast that is not a TEZ session.
    SessionAssetNotTez,
    /// A session paid fast on a vault other than its funding vault.
    FundingVaultMismatch,
    /// A kernel record that does not decode.
    CorruptRecord,
    /// A payout event whose ledger move breaks the paid-ledger rule.
    LedgerMismatch,
    /// A `fast_payout` signature from a key outside `payout_signers`.
    SignerOutsideSet,
    /// A signature from a set member that does not verify.
    SignatureInvalid,
    /// Fewer than two valid in-set signatures on a payout the vault applied.
    UnderThreshold,
    /// The vault's `payout_signers` differ from the set last seen.
    PayoutSignersChanged,
    /// The vault's `payout_signers` differ from the configured set.
    UnexpectedPayoutSigners,
    /// A fast payout event with no decodable `fast_payout` call beside it.
    FastPayoutCallMissing,
    /// A payout event, or the vault's storage, that does not decode.
    Undecodable,
    /// The rollup node runs a kernel other than the pinned one.
    KernelIdentityMismatch,
    /// A `sweep` event naming a `sweep-{level}-{id}` the kernel has no
    /// record of.
    SweepNotRecorded,
    /// The record at the sweep key is not a sweep.
    SweepRecordNotASweep,
    /// A sweep paying an amount other than the kernel's record.
    SweepAmountMismatch,
    /// A sweep from a vault other than the one the kernel's record names.
    SweepVaultMismatch,
    /// A sweep paying an address other than the vault's baked treasury.
    SweepTreasuryMismatch,
    /// The kernel's equity record at the sweep's request level does not
    /// cover the sweep: the counters it bounded the sweep by were short.
    SweepAboveEquity,
    /// No equity record, or one that does not hold the sweep, at the
    /// sweep's request level — the record the kernel must have bounded the
    /// sweep by.
    SweepEquityNotRecorded,
}

impl AlarmKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FastPayoutAboveKernel => "fast_payout_above_kernel",
            Self::SessionNotRecorded => "session_not_recorded",
            Self::SessionNotEnded => "session_not_ended",
            Self::PayoutNotRecorded => "payout_not_recorded",
            Self::PayoutRecordNotASessionEndPayout => "payout_record_not_a_session_end_payout",
            Self::SessionAssetNotTez => "session_asset_not_tez",
            Self::FundingVaultMismatch => "funding_vault_mismatch",
            Self::CorruptRecord => "corrupt_record",
            Self::LedgerMismatch => "ledger_mismatch",
            Self::SignerOutsideSet => "signer_outside_set",
            Self::SignatureInvalid => "signature_invalid",
            Self::UnderThreshold => "under_threshold",
            Self::PayoutSignersChanged => "payout_signers_changed",
            Self::UnexpectedPayoutSigners => "unexpected_payout_signers",
            Self::FastPayoutCallMissing => "fast_payout_call_missing",
            Self::Undecodable => "undecodable",
            Self::KernelIdentityMismatch => "kernel_identity_mismatch",
            Self::SweepNotRecorded => "sweep_not_recorded",
            Self::SweepRecordNotASweep => "sweep_record_not_a_sweep",
            Self::SweepAmountMismatch => "sweep_amount_mismatch",
            Self::SweepVaultMismatch => "sweep_vault_mismatch",
            Self::SweepTreasuryMismatch => "sweep_treasury_mismatch",
            Self::SweepAboveEquity => "sweep_above_equity",
            Self::SweepEquityNotRecorded => "sweep_equity_not_recorded",
        }
    }
}

/// One alarm and everything known about where it happened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Alarm {
    pub kind: AlarmKind,
    pub vault_address: Option<String>,
    pub tenant_id: Option<String>,
    pub pool_id: Option<String>,
    pub session_id: Option<Uuid>,
    pub l1_level: Option<i64>,
    /// The operation group hash.
    pub reference: Option<String>,
    /// The amount the path asked to pay (`fast` / `cemented`).
    pub amount_mutez: Option<u128>,
    pub kernel_amount_mutez: Option<u128>,
    pub paid_now_mutez: Option<u128>,
    pub paid_total_mutez: Option<u128>,
    pub expected_paid_now_mutez: Option<u128>,
    pub expected_paid_total_mutez: Option<u128>,
    /// The signer the alarm is about, when it is about one.
    pub public_key: Option<String>,
    /// The kernel's `sweep-{level}-{id}` reference, for a sweep.
    pub sweep_id: Option<String>,
    /// The address a sweep paid.
    pub treasury: Option<String>,
    pub detail: String,
}

impl Alarm {
    pub fn new(kind: AlarmKind, detail: impl Into<String>) -> Self {
        Self {
            kind,
            vault_address: None,
            tenant_id: None,
            pool_id: None,
            session_id: None,
            l1_level: None,
            reference: None,
            amount_mutez: None,
            kernel_amount_mutez: None,
            paid_now_mutez: None,
            paid_total_mutez: None,
            expected_paid_now_mutez: None,
            expected_paid_total_mutez: None,
            public_key: None,
            sweep_id: None,
            treasury: None,
            detail: detail.into(),
        }
    }
}

/// Write `alarm` as one `ERROR` line.
pub fn emit(alarm: &Alarm) {
    let text = |v: Option<u128>| v.map(|v| v.to_string());
    tracing::error!(
        alarm = alarm.kind.as_str(),
        vault_address = alarm.vault_address.as_deref(),
        tenant_id = alarm.tenant_id.as_deref(),
        pool_id = alarm.pool_id.as_deref(),
        session_id = alarm.session_id.map(|s| s.to_string()).as_deref(),
        l1_level = alarm.l1_level,
        reference = alarm.reference.as_deref(),
        amount_mutez = text(alarm.amount_mutez).as_deref(),
        kernel_amount_mutez = text(alarm.kernel_amount_mutez).as_deref(),
        paid_now_mutez = text(alarm.paid_now_mutez).as_deref(),
        paid_total_mutez = text(alarm.paid_total_mutez).as_deref(),
        expected_paid_now_mutez = text(alarm.expected_paid_now_mutez).as_deref(),
        expected_paid_total_mutez = text(alarm.expected_paid_total_mutez).as_deref(),
        public_key = alarm.public_key.as_deref(),
        sweep_id = alarm.sweep_id.as_deref(),
        treasury = alarm.treasury.as_deref(),
        detail = %alarm.detail,
        "payout watcher alarm"
    );
}

/// Something the watcher saw that is not an alarm.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Notice {
    /// A fast payout, checked and backed by the kernel.
    FastPayoutChecked {
        vault_address: String,
        session_id: Uuid,
        l1_level: i64,
        amount_mutez: u128,
        kernel_amount_mutez: u128,
    },
    /// A fast payout below the kernel's number: the cemented payout tops up.
    FastPayoutShort {
        vault_address: String,
        session_id: Uuid,
        l1_level: i64,
        amount_mutez: u128,
        kernel_amount_mutez: u128,
    },
    /// A cemented payout whose ledger move is the expected one.
    CementedPayoutChecked {
        vault_address: String,
        session_id: Uuid,
        l1_level: i64,
        amount_mutez: u128,
        paid_now_mutez: u128,
    },
    /// A sweep matched to the kernel's record, bounded by its equity and
    /// paid to the vault's treasury.
    SweepChecked {
        vault_address: String,
        sweep_id: String,
        l1_level: i64,
        amount_mutez: u128,
        /// The vault's equity before the kernel reserved this sweep.
        equity_before_mutez: u128,
        treasury: String,
    },
    /// The vault's signer set, the first time this state file sees it.
    PayoutSignersObserved {
        vault_address: String,
        l1_level: i64,
        payout_signers: Vec<String>,
    },
    /// A level not checked yet: the rollup node has not finalised it.
    Deferred {
        vault_address: String,
        l1_level: i64,
        rollup_finalized_level: i64,
    },
}

/// Write `notice` as one `INFO` (or, for a deferral, `WARN`) line.
pub fn note(notice: &Notice) {
    match notice {
        Notice::FastPayoutChecked {
            vault_address,
            session_id,
            l1_level,
            amount_mutez,
            kernel_amount_mutez,
        } => tracing::info!(
            vault_address = %vault_address,
            session_id = %session_id,
            l1_level,
            amount_mutez = %amount_mutez,
            kernel_amount_mutez = %kernel_amount_mutez,
            "fast payout backed by the kernel's record"
        ),
        Notice::FastPayoutShort {
            vault_address,
            session_id,
            l1_level,
            amount_mutez,
            kernel_amount_mutez,
        } => tracing::warn!(
            vault_address = %vault_address,
            session_id = %session_id,
            l1_level,
            amount_mutez = %amount_mutez,
            kernel_amount_mutez = %kernel_amount_mutez,
            "fast payout below the kernel's record; the cemented payout pays the rest"
        ),
        Notice::CementedPayoutChecked {
            vault_address,
            session_id,
            l1_level,
            amount_mutez,
            paid_now_mutez,
        } => tracing::info!(
            vault_address = %vault_address,
            session_id = %session_id,
            l1_level,
            amount_mutez = %amount_mutez,
            paid_now_mutez = %paid_now_mutez,
            "cemented payout follows the paid-ledger rule"
        ),
        Notice::SweepChecked {
            vault_address,
            sweep_id,
            l1_level,
            amount_mutez,
            equity_before_mutez,
            treasury,
        } => tracing::info!(
            vault_address = %vault_address,
            sweep_id = %sweep_id,
            l1_level,
            amount_mutez = %amount_mutez,
            equity_before_mutez = %equity_before_mutez,
            treasury = %treasury,
            "sweep backed by the kernel's record and bounded by its equity"
        ),
        Notice::PayoutSignersObserved {
            vault_address,
            l1_level,
            payout_signers,
        } => tracing::info!(
            vault_address = %vault_address,
            l1_level,
            payout_signers = %payout_signers.join(","),
            "vault payout signers observed"
        ),
        Notice::Deferred {
            vault_address,
            l1_level,
            rollup_finalized_level,
        } => tracing::warn!(
            vault_address = %vault_address,
            l1_level,
            rollup_finalized_level,
            "deferred: the rollup node has not finalised this level yet"
        ),
    }
}
