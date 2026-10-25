//! Every fixture case: a recorded snapshot of both nodes, the config to run
//! it under, and what a `--once` run must report.
//!
//! The fast payouts are the shared vectors' (`fast-payout-vectors.json`):
//! chain, vault, session, amount and the pytezos signatures. A second
//! session, used where a case needs two, is signed here with the shared
//! deterministic signer from the vectors' secret exponents.

use super::chain::{
    Durable, OTHER_VAULT, TREASURY, block, cemented_payout_group, fast_payout_group, kernel_bytes,
    sweep_group, sweep_vault_script, vault_script,
};
use payout_protocol::kernel_identity::{format_root_hash, root_hash_of};
use payout_protocol::{ChainId, LocalSecp256k1Signer, VaultAddress, sign_fast_payout};
use serde::Deserialize;
use serde_json::{Value, json};
use smart_rollup_storage::v1::{HouseEquity, StoredTransactionKind};
use std::collections::BTreeMap;

#[derive(Deserialize)]
struct Vectors {
    chain_id: String,
    vault: String,
    payout_signers: Vec<String>,
    payloads: BTreeMap<String, Payload>,
    signers: BTreeMap<String, Signer>,
}

#[derive(Deserialize)]
struct Payload {
    #[serde(default)]
    session_id: Option<String>,
    #[serde(default)]
    amount_mutez: Option<u64>,
}

#[derive(Deserialize)]
struct Signer {
    secret_exponent: String,
    public_key: String,
    signatures: BTreeMap<String, String>,
}

fn vectors() -> Vectors {
    serde_json::from_str(include_str!(
        "../../../operator-cli/tests/fast-payout-vectors.json"
    ))
    .expect("fixture parses")
}

/// What a case's run must produce.
pub struct Case {
    pub name: &'static str,
    pub config: String,
    pub snapshot: Value,
    pub exit_code: i32,
    /// The `alarm` kinds, sorted, with repeats.
    pub alarms: Vec<&'static str>,
}

const START: i64 = 100;
const FAST_LEVEL: i64 = 105;
const ROTATION_LEVEL: i64 = 110;
const SECOND_FAST_LEVEL: i64 = 115;
const CEMENTED_LEVEL: i64 = 120;
/// The level the `Sweep` admin op landed at (the kernel's record) and the
/// level its `execute_sweep` was executed at, a cementation later.
const SWEEP_REQUEST_LEVEL: u64 = 102;
const SWEEP_ID: u64 = 3;
const SWEEP_LEVEL: i64 = 125;
const SWEEP_AMOUNT: u128 = 4_000_000;
const HEAD: i64 = 130;
/// The second session's id and payout.
const SESSION_B: [u8; 16] = [0xb0; 16];
const AMOUNT_B: u64 = 700_000;

struct Base {
    v: Vectors,
    session: [u8; 16],
    amount: u128,
}

impl Base {
    fn new() -> Self {
        let v = vectors();
        let fast = &v.payloads["fast_payout"];
        let session = hex::decode(fast.session_id.as_deref().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let amount = u128::from(fast.amount_mutez.unwrap());
        Self { v, session, amount }
    }

    fn key(&self, label: &str) -> String {
        self.v.signers[label].public_key.clone()
    }

    fn entry(&self, key: &str, signed_by: &str, payload: &str) -> (String, String) {
        (
            self.key(key),
            self.v.signers[signed_by].signatures[payload].clone(),
        )
    }

    /// The vectors' two-secp256k1 accepted call.
    fn good_entries(&self) -> Vec<(String, String)> {
        vec![
            self.entry("sp_a", "sp_a", "fast_payout"),
            self.entry("sp_b", "sp_b", "fast_payout"),
        ]
    }

    fn fast(&self, entries: &[(String, String)]) -> Value {
        fast_payout_group(
            &self.v.chain_id,
            1,
            &self.v.vault,
            &self.session,
            self.amount,
            entries,
        )
    }

    /// A kernel that ended the session on the vault with `kernel_amount`.
    fn durable(&self, kernel_amount: u128) -> Durable {
        let mut d = Durable::default();
        d.kernel()
            .session(&self.session, &self.v.vault, true)
            .payout(&self.session, kernel_amount);
        d
    }

    fn config(&self, extra: &str) -> String {
        format!(
            "max_rollup_lag_levels = 60\n{extra}\n[[vaults]]\naddress = \"{}\"\nstart_level = {START}\n",
            self.v.vault
        )
    }

    fn snapshot(
        &self,
        blocks: Vec<(i64, Vec<Value>)>,
        scripts: Vec<(i64, Value)>,
        durable: &Durable,
        rollup_level: i64,
    ) -> Value {
        let blocks: BTreeMap<String, Value> = blocks
            .into_iter()
            .map(|(level, groups)| (level.to_string(), block(groups)))
            .collect();
        let scripts: Vec<Value> = scripts
            .into_iter()
            .map(|(from_level, script)| {
                json!({ "contract": self.v.vault, "from_level": from_level, "script": script })
            })
            .collect();

        json!({
            "l1": { "finalized_level": HEAD, "blocks": blocks, "scripts": scripts },
            "rollup": {
                "finalized_level": rollup_level,
                "durable": durable.0,
                "durable_at_level": durable.1
            }
        })
    }

    fn origin_script(&self) -> Vec<(i64, Value)> {
        vec![(START, vault_script(&self.v.payout_signers, 0))]
    }

    /// The sweep generation's script: the same signers, plus the treasury.
    fn sweep_origin_script(&self) -> Vec<(i64, Value)> {
        vec![(
            START,
            sweep_vault_script(&self.v.payout_signers, 0, TREASURY),
        )]
    }

    /// The executed sweep of [`SWEEP_AMOUNT`] from the vault to `treasury`,
    /// naming the kernel record `sweep-{SWEEP_REQUEST_LEVEL}-{SWEEP_ID}`.
    fn sweep(&self, treasury: &str) -> Value {
        sweep_group(
            &self.v.chain_id,
            5,
            &self.v.vault,
            SWEEP_REQUEST_LEVEL,
            SWEEP_ID,
            SWEEP_AMOUNT,
            treasury,
        )
    }

    /// A kernel that recorded the sweep: the record under the vault, and the
    /// equity it reserved the amount on at the request level (funded 10,
    /// stakes 5, payouts 3, swept 4: the bound held with 8 to spare).
    fn sweep_durable(&self) -> Durable {
        let mut d = Durable::default();
        d.kernel()
            .sweep(
                SWEEP_REQUEST_LEVEL,
                SWEEP_ID,
                &self.v.vault,
                SWEEP_AMOUNT,
                StoredTransactionKind::Sweep,
            )
            .equity_at(
                SWEEP_REQUEST_LEVEL as i64,
                &self.v.vault,
                HouseEquity {
                    funded: 10_000_000,
                    stakes: 5_000_000,
                    payouts: 3_000_000,
                    swept: SWEEP_AMOUNT,
                },
            );
        d
    }

    /// One executed sweep at `SWEEP_LEVEL` on a sweep-generation vault,
    /// nothing else, over `durable`.
    fn single_sweep(&self, treasury: &str, durable: &Durable) -> Value {
        self.snapshot(
            vec![(SWEEP_LEVEL, vec![self.sweep(treasury)])],
            self.sweep_origin_script(),
            durable,
            HEAD,
        )
    }

    /// One fast payout at `FAST_LEVEL` with `entries`, nothing else.
    fn single_fast(&self, entries: &[(String, String)], durable: &Durable) -> Value {
        self.snapshot(
            vec![(FAST_LEVEL, vec![self.fast(entries)])],
            self.origin_script(),
            durable,
            HEAD,
        )
    }

    /// `sp_a` and `sp_b` signing the second session's fast payout.
    async fn second_session_entries(&self) -> Vec<(String, String)> {
        let chain = ChainId::parse(&self.v.chain_id).unwrap();
        let vault = VaultAddress::parse(&self.v.vault).unwrap();
        let mut out = Vec::new();
        for label in ["sp_a", "sp_b"] {
            let exponent: [u8; 32] = hex::decode(&self.v.signers[label].secret_exponent)
                .unwrap()
                .try_into()
                .unwrap();
            let signer = LocalSecp256k1Signer::from_secret_exponent(&exponent).unwrap();
            let signed = sign_fast_payout(&signer, &chain, &vault, &SESSION_B, AMOUNT_B)
                .await
                .unwrap();
            assert_eq!(signed.public_key, self.key(label));
            out.push((signed.public_key, signed.signature));
        }
        out
    }
}

/// Every case, in a stable order.
pub async fn all() -> Vec<Case> {
    let b = Base::new();
    let a = b.amount;
    let mut cases = Vec::new();

    // ── clean ───────────────────────────────────────────────────────────
    // A fast payout backed by the kernel, its later cemented payout paying
    // nothing more, a second session paid by the cemented path only, and a
    // sweep the kernel recorded, bounded and the vault paid to its
    // treasury; the kernel pinned by version and root hash.
    {
        let mut durable = b.durable(a);
        durable
            .session(&SESSION_B, &b.v.vault, true)
            .payout(&SESSION_B, u128::from(AMOUNT_B));
        let sweep = b.sweep_durable();
        durable.0.extend(sweep.0);
        durable.1.extend(sweep.1);
        let root = format_root_hash(&root_hash_of(&kernel_bytes()).unwrap());
        let chain = &b.v.chain_id;
        let vault = &b.v.vault;
        cases.push(Case {
            name: "clean",
            config: b.config(&format!(
                "[kernel]\nexpected_version = \"{}\"\nexpected_root_hash = \"{root}\"\n",
                super::chain::KERNEL_VERSION
            )),
            snapshot: b.snapshot(
                vec![
                    (FAST_LEVEL, vec![b.fast(&b.good_entries())]),
                    (
                        CEMENTED_LEVEL,
                        vec![
                            cemented_payout_group(chain, 2, vault, &b.session, a, 0, a),
                            cemented_payout_group(
                                chain,
                                3,
                                vault,
                                &SESSION_B,
                                u128::from(AMOUNT_B),
                                u128::from(AMOUNT_B),
                                u128::from(AMOUNT_B),
                            ),
                        ],
                    ),
                    (SWEEP_LEVEL, vec![b.sweep(TREASURY)]),
                ],
                b.sweep_origin_script(),
                &durable,
                HEAD,
            ),
            exit_code: 0,
            alarms: vec![],
        });
    }

    // ── a sweep the kernel has no record of ─────────────────────────────
    {
        let mut durable = Durable::default();
        durable.kernel();
        cases.push(Case {
            name: "sweep_not_recorded",
            config: b.config(""),
            snapshot: b.single_sweep(TREASURY, &durable),
            exit_code: 1,
            alarms: vec!["sweep_not_recorded"],
        });
    }

    // ── a sweep whose record is a payout ────────────────────────────────
    {
        let mut durable = b.sweep_durable();
        durable.sweep(
            SWEEP_REQUEST_LEVEL,
            SWEEP_ID,
            &b.v.vault,
            SWEEP_AMOUNT,
            StoredTransactionKind::RoundEndPayout,
        );
        cases.push(Case {
            name: "sweep_record_not_a_sweep",
            config: b.config(""),
            snapshot: b.single_sweep(TREASURY, &durable),
            exit_code: 1,
            alarms: vec!["sweep_record_not_a_sweep"],
        });
    }

    // ── a sweep paying more than the kernel authorised ──────────────────
    {
        let mut durable = b.sweep_durable();
        durable.sweep(
            SWEEP_REQUEST_LEVEL,
            SWEEP_ID,
            &b.v.vault,
            SWEEP_AMOUNT - 1_000_000,
            StoredTransactionKind::Sweep,
        );
        cases.push(Case {
            name: "sweep_amount_mismatch",
            config: b.config(""),
            snapshot: b.single_sweep(TREASURY, &durable),
            exit_code: 1,
            alarms: vec!["sweep_amount_mismatch"],
        });
    }

    // ── a sweep the kernel authorised from another vault ────────────────
    {
        let mut durable = b.sweep_durable();
        durable.sweep(
            SWEEP_REQUEST_LEVEL,
            SWEEP_ID,
            OTHER_VAULT,
            SWEEP_AMOUNT,
            StoredTransactionKind::Sweep,
        );
        cases.push(Case {
            name: "sweep_vault_mismatch",
            config: b.config(""),
            snapshot: b.single_sweep(TREASURY, &durable),
            exit_code: 1,
            alarms: vec!["sweep_vault_mismatch"],
        });
    }

    // ── a sweep paid to an address other than the vault's treasury ──────
    cases.push(Case {
        name: "sweep_treasury_mismatch",
        config: b.config(""),
        snapshot: b.single_sweep(OTHER_VAULT, &b.sweep_durable()),
        exit_code: 1,
        alarms: vec!["sweep_treasury_mismatch"],
    });

    // ── a sweep the equity at its request level does not cover ──────────
    // payouts 9 + swept 4 > funded 10 + stakes 2: the kernel's own bound
    // did not hold at the level it reserved the sweep.
    {
        let mut durable = b.sweep_durable();
        durable.equity_at(
            SWEEP_REQUEST_LEVEL as i64,
            &b.v.vault,
            HouseEquity {
                funded: 10_000_000,
                stakes: 2_000_000,
                payouts: 9_000_000,
                swept: SWEEP_AMOUNT,
            },
        );
        cases.push(Case {
            name: "sweep_above_equity",
            config: b.config(""),
            snapshot: b.single_sweep(TREASURY, &durable),
            exit_code: 1,
            alarms: vec!["sweep_above_equity"],
        });
    }

    // ── a sweep with no equity record at its request level ──────────────
    {
        let mut durable = b.sweep_durable();
        durable.1.clear();
        cases.push(Case {
            name: "sweep_equity_not_recorded",
            config: b.config(""),
            snapshot: b.single_sweep(TREASURY, &durable),
            exit_code: 1,
            alarms: vec!["sweep_equity_not_recorded"],
        });
    }

    // ── a fast payout above the kernel's number ────────────────────────
    cases.push(Case {
        name: "overpayment",
        config: b.config(""),
        snapshot: b.single_fast(&b.good_entries(), &b.durable(a - 500_000)),
        exit_code: 1,
        alarms: vec!["fast_payout_above_kernel"],
    });

    // ── a session paid fast the kernel has no record of ─────────────────
    {
        let mut durable = Durable::default();
        durable.kernel();
        cases.push(Case {
            name: "session_not_recorded",
            config: b.config(""),
            snapshot: b.single_fast(&b.good_entries(), &durable),
            exit_code: 1,
            alarms: vec!["session_not_recorded"],
        });
    }

    // ── a session paid fast the kernel has not ended ────────────────────
    {
        let mut durable = Durable::default();
        durable.kernel().session(&b.session, &b.v.vault, false);
        cases.push(Case {
            name: "session_not_ended",
            config: b.config(""),
            snapshot: b.single_fast(&b.good_entries(), &durable),
            exit_code: 1,
            alarms: vec!["session_not_ended"],
        });
    }

    // ── a payout key holding a round's credit, not a SessionEndPayout ──
    {
        let mut durable = Durable::default();
        durable
            .kernel()
            .session(&b.session, &b.v.vault, true)
            .payout_of_kind(&b.session, b.amount, StoredTransactionKind::RoundEndPayout);
        cases.push(Case {
            name: "payout_record_not_a_session_end_payout",
            config: b.config(""),
            snapshot: b.single_fast(&b.good_entries(), &durable),
            exit_code: 1,
            alarms: vec!["payout_record_not_a_session_end_payout"],
        });
    }

    // ── a session paid fast that ended owing nothing ────────────────────
    {
        let mut durable = Durable::default();
        durable.kernel().session(&b.session, &b.v.vault, true);
        cases.push(Case {
            name: "payout_not_recorded",
            config: b.config(""),
            snapshot: b.single_fast(&b.good_entries(), &durable),
            exit_code: 1,
            alarms: vec!["payout_not_recorded"],
        });
    }

    // ── a session paid fast on a vault other than its funding vault ─────
    {
        let mut durable = Durable::default();
        durable
            .kernel()
            .session(&b.session, OTHER_VAULT, true)
            .payout(&b.session, a);
        cases.push(Case {
            name: "funding_vault_mismatch",
            config: b.config(""),
            snapshot: b.single_fast(&b.good_entries(), &durable),
            exit_code: 1,
            alarms: vec!["funding_vault_mismatch"],
        });
    }

    // ── a cemented payout that pays in full over a fast payout ──────────
    {
        let cemented = a + 500_000;
        cases.push(Case {
            name: "cemented_ledger_mismatch",
            config: b.config(""),
            snapshot: b.snapshot(
                vec![
                    (FAST_LEVEL, vec![b.fast(&b.good_entries())]),
                    (
                        CEMENTED_LEVEL,
                        vec![cemented_payout_group(
                            &b.v.chain_id,
                            2,
                            &b.v.vault,
                            &b.session,
                            cemented,
                            cemented,
                            a + cemented,
                        )],
                    ),
                ],
                b.origin_script(),
                &b.durable(a),
                HEAD,
            ),
            exit_code: 1,
            alarms: vec!["ledger_mismatch"],
        });
    }

    // ── a signature from a key outside the set ──────────────────────────
    {
        let mut entries = b.good_entries();
        entries.push(b.entry("mallory", "mallory", "fast_payout"));
        cases.push(Case {
            name: "signer_outside_set",
            config: b.config(""),
            snapshot: b.single_fast(&entries, &b.durable(a)),
            exit_code: 1,
            alarms: vec!["signer_outside_set"],
        });
    }

    // ── fewer than two valid signatures on an applied payout ────────────
    {
        let entries = vec![
            b.entry("sp_a", "sp_a", "fast_payout"),
            b.entry("sp_b", "sp_b", "fast_payout_other_amount"),
        ];
        cases.push(Case {
            name: "under_threshold",
            config: b.config(""),
            snapshot: b.single_fast(&entries, &b.durable(a)),
            exit_code: 1,
            alarms: vec!["signature_invalid", "under_threshold"],
        });
    }

    // ── a rotation of the signer set between two fast payouts ───────────
    {
        let mut durable = b.durable(a);
        durable
            .session(&SESSION_B, &b.v.vault, true)
            .payout(&SESSION_B, u128::from(AMOUNT_B));
        let rotated = vec![b.key("ed_c"), b.key("ed_b"), b.key("sp_a"), b.key("sp_b")];
        let second = fast_payout_group(
            &b.v.chain_id,
            4,
            &b.v.vault,
            &SESSION_B,
            u128::from(AMOUNT_B),
            &b.second_session_entries().await,
        );
        cases.push(Case {
            name: "payout_signers_changed",
            config: b.config(""),
            snapshot: b.snapshot(
                vec![
                    (FAST_LEVEL, vec![b.fast(&b.good_entries())]),
                    (SECOND_FAST_LEVEL, vec![second]),
                ],
                vec![
                    (START, vault_script(&b.v.payout_signers, 0)),
                    (ROTATION_LEVEL, vault_script(&rotated, 1)),
                ],
                &durable,
                HEAD,
            ),
            exit_code: 1,
            alarms: vec!["payout_signers_changed"],
        });
    }

    // ── a configured signer set the vault does not hold ─────────────────
    cases.push(Case {
        name: "unexpected_payout_signers",
        config: format!(
            "max_rollup_lag_levels = 60\n[[vaults]]\naddress = \"{}\"\nstart_level = {START}\nexpected_payout_signers = [\"{}\", \"{}\", \"{}\", \"{}\"]\n",
            b.v.vault,
            b.key("ed_c"),
            b.key("ed_b"),
            b.key("sp_a"),
            b.key("sp_b")
        ),
        snapshot: b.single_fast(&b.good_entries(), &b.durable(a)),
        exit_code: 1,
        alarms: vec!["unexpected_payout_signers"],
    });

    // ── a kernel other than the pinned one ──────────────────────────────
    cases.push(Case {
        name: "kernel_identity_mismatch",
        config: b.config("[kernel]\nexpected_version = \"9.9.9\"\n"),
        snapshot: b.single_fast(&b.good_entries(), &b.durable(a)),
        exit_code: 1,
        alarms: vec!["kernel_identity_mismatch"],
    });

    // ── the rollup node has not finalised the payout's level ────────────
    // Nothing is judged yet: no alarm, a deferral, exit 0, cursor kept.
    cases.push(Case {
        name: "deferred",
        config: b.config(""),
        snapshot: b.snapshot(
            vec![(FAST_LEVEL, vec![b.fast(&b.good_entries())])],
            b.origin_script(),
            &Durable::default(),
            FAST_LEVEL - 1,
        ),
        exit_code: 0,
        alarms: vec![],
    });

    // ── …and trails L1 by more than the allowed lag: exit 3, retry ──────
    cases.push(Case {
        name: "rollup_node_behind",
        config: b
            .config("")
            .replace("max_rollup_lag_levels = 60", "max_rollup_lag_levels = 10"),
        snapshot: b.snapshot(
            vec![(FAST_LEVEL, vec![b.fast(&b.good_entries())])],
            b.origin_script(),
            &Durable::default(),
            FAST_LEVEL - 1,
        ),
        exit_code: 3,
        alarms: vec![],
    });

    cases
}
