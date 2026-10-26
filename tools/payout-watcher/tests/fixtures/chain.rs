//! Builders for synthetic node answers, in the shapes an octez L1 node and
//! rollup node return: operation groups with their internal results and
//! events, a vault script with its compiled storage type, and borsh-encoded
//! kernel records. The event, parameter and storage types are the compiled
//! vault's, verbatim.

use payout_protocol::kernel_records::{
    KERNEL_BOOT_KEY, KERNEL_INFO_KEY, TEZ, house_equity_key, session_end_payout_key, session_key,
    sweep_id_bytes, sweep_key,
};
use serde_json::{Value, json};
use smart_rollup_storage::v1::{
    HouseEquity, KernelInfo, StoredSession, StoredTransaction, StoredTransactionKind,
};
use smart_rollup_storage::{
    HouseEquityEnvelope, KernelInfoEnvelope, StoredSessionEnvelope, StoredTransactionEnvelope,
};
use std::collections::BTreeMap;
use uuid::Uuid;

pub const TENANT: &str = "golden-tenant";
pub const POOL: &str = "golden-pool";
pub const OWNER: &str = "tz1UyQDepgtUBnWjyzzonqeDwaiWoQzRKSP5";
pub const SUBMITTER: &str = "tz1KzFd43P88CfLbvDC1arQTXhLYuxfRraHd";
pub const ROLLUP: &str = "sr1TMxAUtDA4sDL7C4r39L18iQjhRcBRzd8a";
pub const OTHER_VAULT: &str = "KT1EfTusMLoeCAAGd9MZJn5yKzFr6kJU5U91";
/// The treasury baked into the sweep-generation vault's storage.
pub const TREASURY: &str = "KT1FNqdhr7P6FM9rx6P1CoPasUYE5JPSCqup";
pub const KERNEL_VERSION: &str = "0.8.10";

fn ty(prim: &str, annot: &str) -> Value {
    json!({ "prim": prim, "annots": [format!("%{annot}")] })
}

fn pair(a: Value, b: Value) -> Value {
    json!({ "prim": "pair", "args": [a, b] })
}

fn pair_value(a: Value, b: Value) -> Value {
    json!({ "prim": "Pair", "args": [a, b] })
}

fn int(n: u128) -> Value {
    json!({ "int": n.to_string() })
}

/// `EMIT %fast_payout` / `EMIT %cemented_payout`: `pair (mutez %<amount>)
/// (pair (mutez %paid_now) (pair (mutez %paid_total) (bytes %session_id)))`.
fn event_type(amount_field: &str) -> Value {
    pair(
        ty("mutez", amount_field),
        pair(
            ty("mutez", "paid_now"),
            pair(ty("mutez", "paid_total"), ty("bytes", "session_id")),
        ),
    )
}

fn event_payload(session: &[u8; 16], amount: u128, paid_now: u128, paid_total: u128) -> Value {
    pair_value(
        int(amount),
        pair_value(
            int(paid_now),
            pair_value(int(paid_total), json!({ "bytes": hex::encode(session) })),
        ),
    )
}

/// A fake operation hash: base58check under the `o` prefix of `seed`.
pub fn operation_hash(seed: u8) -> String {
    let mut bytes = vec![5u8, 116];
    bytes.extend_from_slice(&[seed; 32]);
    bs58::encode(bytes).with_check().into_string()
}

fn group(chain_id: &str, seed: u8, content: Value) -> Value {
    json!({
        "protocol": "PsUshuai9QapM5TGj1JpuVGkdxz5GykdnEvS6Rh8SUVrARvZLCY",
        "chain_id": chain_id,
        "hash": operation_hash(seed),
        "branch": "BL35qU9cLuKmamjHhebWLKe4ySiiWFxwXhmcUZ8Vo4kXzwAhRdQ",
        "contents": [content],
        "signature": "sigNXGj9T2fhd3v6H1hxpRUDpdhcBeghKQVt5nCKghm4ECeMHC6EkAxbXPaA2DLFZkvM6NMh7gXi7J9JjYNp4ymhrN8H8Y2s"
    })
}

/// One signature entry of a call: `(public key, signature)`, as strings.
pub type Entry = (String, String);

/// An applied `fast_payout` operation group: the submitter's call, the
/// vault's transfer to the owner and its `fast_payout` event.
pub fn fast_payout_group(
    chain_id: &str,
    seed: u8,
    vault: &str,
    session: &[u8; 16],
    amount: u128,
    entries: &[Entry],
) -> Value {
    let mut sorted = entries.to_vec();
    sorted.sort();
    let elts: Vec<Value> = sorted
        .iter()
        .map(|(k, s)| json!({ "prim": "Elt", "args": [{ "string": k }, { "string": s }] }))
        .collect();
    let parameter = pair_value(
        int(amount),
        pair_value(json!({ "bytes": hex::encode(session) }), Value::Array(elts)),
    );

    group(
        chain_id,
        seed,
        json!({
            "kind": "transaction",
            "source": SUBMITTER,
            "fee": "2000",
            "counter": "1000",
            "gas_limit": "6000",
            "storage_limit": "100",
            "amount": "0",
            "destination": vault,
            "parameters": { "entrypoint": "fast_payout", "value": parameter },
            "metadata": {
                "balance_updates": [],
                "operation_result": { "status": "applied", "consumed_milligas": "4000000" },
                "internal_operation_results": [
                    {
                        "kind": "transaction",
                        "source": vault,
                        "nonce": 0,
                        "amount": amount.to_string(),
                        "destination": OWNER,
                        "result": { "status": "applied", "consumed_milligas": "2100000" }
                    },
                    {
                        "kind": "event",
                        "source": vault,
                        "nonce": 1,
                        "type": event_type("fast"),
                        "tag": "fast_payout",
                        "payload": event_payload(session, amount, amount, amount),
                        "result": { "status": "applied", "consumed_milligas": "100000" }
                    }
                ]
            }
        }),
    )
}

/// An applied outbox execution of `execute_cemented_payout((session,
/// cemented))`, with the vault's transfer (when `paid_now > 0`) and its
/// `cemented_payout` event reporting `paid_now` / `paid_total`.
pub fn cemented_payout_group(
    chain_id: &str,
    seed: u8,
    vault: &str,
    session: &[u8; 16],
    cemented: u128,
    paid_now: u128,
    paid_total: u128,
) -> Value {
    let mut internal = vec![json!({
        "kind": "transaction",
        "source": ROLLUP,
        "nonce": 0,
        "amount": "0",
        "destination": vault,
        "parameters": {
            "entrypoint": "execute_cemented_payout",
            "value": pair_value(json!({ "bytes": hex::encode(session) }), int(cemented))
        },
        "result": { "status": "applied", "consumed_milligas": "3000000" }
    })];
    if paid_now > 0 {
        internal.push(json!({
            "kind": "transaction",
            "source": vault,
            "nonce": 1,
            "amount": paid_now.to_string(),
            "destination": OWNER,
            "result": { "status": "applied", "consumed_milligas": "2100000" }
        }));
    }
    internal.push(json!({
        "kind": "event",
        "source": vault,
        "nonce": 2,
        "type": event_type("cemented"),
        "tag": "cemented_payout",
        "payload": event_payload(session, cemented, paid_now, paid_total),
        "result": { "status": "applied", "consumed_milligas": "100000" }
    }));

    group(
        chain_id,
        seed,
        json!({
            "kind": "smart_rollup_execute_outbox_message",
            "source": SUBMITTER,
            "fee": "3000",
            "counter": "1001",
            "gas_limit": "12000",
            "storage_limit": "100",
            "rollup": ROLLUP,
            "cemented_commitment": "src12UJzB8mg7yU6nWPzicH7ofJbFjyJEbHvwtZpNhSMFqEB9hxsPF",
            "output_proof": "00",
            "metadata": {
                "balance_updates": [],
                "operation_result": { "status": "applied", "consumed_milligas": "9000000" },
                "internal_operation_results": internal
            }
        }),
    )
}

/// `EMIT %sweep`: `pair (mutez %amount) (pair (bytes %sweep_id) (address
/// %treasury))`, the sweep generation's event type, verbatim.
fn sweep_event_type() -> Value {
    pair(
        ty("mutez", "amount"),
        pair(ty("bytes", "sweep_id"), ty("address", "treasury")),
    )
}

/// An applied outbox execution of `execute_sweep((sweep_id, amount))` for
/// the kernel record `sweep-{level}-{id}`: the vault's transfer to
/// `treasury` and its `sweep` event naming the same three values.
pub fn sweep_group(
    chain_id: &str,
    seed: u8,
    vault: &str,
    level: u64,
    id: u64,
    amount: u128,
    treasury: &str,
) -> Value {
    let sweep_id = hex::encode(sweep_id_bytes(level, id));
    let internal = vec![
        json!({
            "kind": "transaction",
            "source": ROLLUP,
            "nonce": 0,
            "amount": "0",
            "destination": vault,
            "parameters": {
                "entrypoint": "execute_sweep",
                "value": pair_value(json!({ "bytes": sweep_id }), int(amount))
            },
            "result": { "status": "applied", "consumed_milligas": "3000000" }
        }),
        json!({
            "kind": "transaction",
            "source": vault,
            "nonce": 1,
            "amount": amount.to_string(),
            "destination": treasury,
            "parameters": { "entrypoint": "default", "value": { "prim": "Unit" } },
            "result": { "status": "applied", "consumed_milligas": "2100000" }
        }),
        json!({
            "kind": "event",
            "source": vault,
            "nonce": 2,
            "type": sweep_event_type(),
            "tag": "sweep",
            "payload": pair_value(
                int(amount),
                pair_value(json!({ "bytes": sweep_id }), json!({ "string": treasury }))
            ),
            "result": { "status": "applied", "consumed_milligas": "100000" }
        }),
    ];

    group(
        chain_id,
        seed,
        json!({
            "kind": "smart_rollup_execute_outbox_message",
            "source": SUBMITTER,
            "fee": "3000",
            "counter": "1002",
            "gas_limit": "12000",
            "storage_limit": "100",
            "rollup": ROLLUP,
            "cemented_commitment": "src12UJzB8mg7yU6nWPzicH7ofJbFjyJEbHvwtZpNhSMFqEB9hxsPF",
            "output_proof": "00",
            "metadata": {
                "balance_updates": [],
                "operation_result": { "status": "applied", "consumed_milligas": "9000000" },
                "internal_operation_results": internal
            }
        }),
    )
}

/// A block's `/operations` answer: the manager pass holds `groups`.
pub fn block(groups: Vec<Value>) -> Value {
    json!([[], [], [], groups])
}

/// The compiled vault's storage type, with the sweep generation's
/// `treasury` leaf — the last one, since the compiler sorts the fields —
/// when `treasury` is set.
fn storage_type(treasury: bool) -> Value {
    let tail = if treasury {
        pair(ty("mutez", "total_deposits"), ty("address", "treasury"))
    } else {
        ty("mutez", "total_deposits")
    };

    pair(
        ty("address", "admin_address"),
        pair(
            json!({ "prim": "big_map", "args": [{ "prim": "bytes" }, { "prim": "mutez" }], "annots": ["%paid"] }),
            pair(
                ty("bool", "paused"),
                pair(
                    ty("nat", "payout_signer_nonce"),
                    pair(
                        json!({ "prim": "set", "args": [{ "prim": "key" }], "annots": ["%payout_signers"] }),
                        pair(
                            json!({ "prim": "option", "args": [{ "prim": "address" }], "annots": ["%pending_admin_address"] }),
                            pair(
                                ty("string", "pool_id"),
                                pair(
                                    json!({ "prim": "big_map", "args": [{ "prim": "bytes" }, { "prim": "pair", "args": [
                                        { "prim": "address", "annots": ["%owner"] },
                                        { "prim": "key", "annots": ["%session_public_key"] }
                                    ] }], "annots": ["%sessions"] }),
                                    pair(
                                        ty("address", "smart_rollup_address"),
                                        pair(ty("string", "tenant_id"), tail),
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        ),
    )
}

/// The vault's `/script` answer with `signers` in its `payout_signers`:
/// the fast-payout generation, without a treasury.
pub fn vault_script(signers: &[String], nonce: u128) -> Value {
    script(signers, nonce, None)
}

/// The sweep generation's `/script` answer: the same storage with
/// `treasury` as its last leaf.
pub fn sweep_vault_script(signers: &[String], nonce: u128, treasury: &str) -> Value {
    script(signers, nonce, Some(treasury))
}

fn script(signers: &[String], nonce: u128, treasury: Option<&str>) -> Value {
    let mut keys = signers.to_vec();
    keys.sort();
    let keys: Vec<Value> = keys.iter().map(|k| json!({ "string": k })).collect();
    let mut leaves = vec![
        json!({ "string": OWNER }),
        json!({ "int": "41" }),
        json!({ "prim": "False" }),
        int(nonce),
        Value::Array(keys),
        json!({ "prim": "None" }),
        json!({ "string": POOL }),
        json!({ "int": "42" }),
        json!({ "string": ROLLUP }),
        json!({ "string": TENANT }),
        json!({ "int": "25000000" }),
    ];
    if let Some(treasury) = treasury {
        leaves.push(json!({ "string": treasury }));
    }
    let storage = json!({ "prim": "Pair", "args": leaves });

    json!({
        "code": [
            { "prim": "parameter", "args": [{ "prim": "unit" }] },
            { "prim": "storage", "args": [storage_type(treasury.is_some())] },
            { "prim": "code", "args": [[]] }
        ],
        "storage": storage
    })
}

/// Durable values, hex by key, as a rollup node snapshot holds them: at the
/// finalised block (`.0`), and as of the end of earlier levels
/// (`at_level`), where a sweep's request-time equity is read back.
#[derive(Default)]
pub struct Durable(
    pub BTreeMap<String, String>,
    pub BTreeMap<i64, BTreeMap<String, String>>,
);

impl Durable {
    fn put<T: borsh::BorshSerialize>(&mut self, key: String, value: &T) -> &mut Self {
        self.0
            .insert(key, hex::encode(borsh::to_vec(value).expect("borsh")));
        self
    }

    /// The kernel's `sweep-{level}-{id}` record: a sweep of `amount` from
    /// `vault`, of `kind` (a sweep, unless a case plants another kind).
    pub fn sweep(
        &mut self,
        level: u64,
        id: u64,
        vault: &str,
        amount: u128,
        kind: StoredTransactionKind,
    ) -> &mut Self {
        self.put(
            sweep_key(TENANT, POOL, TEZ, level, id),
            &StoredTransactionEnvelope::V1(StoredTransaction {
                account_address: vault.to_string(),
                asset: TEZ.to_string(),
                kind,
                amount,
            }),
        )
    }

    /// The vault's equity record as of the end of `level`, the state the
    /// kernel left after accepting a sweep in that level.
    pub fn equity_at(&mut self, level: i64, vault: &str, equity: HouseEquity) -> &mut Self {
        self.1.entry(level).or_default().insert(
            house_equity_key(TENANT, POOL, vault),
            hex::encode(borsh::to_vec(&HouseEquityEnvelope::V1(equity)).expect("borsh")),
        );
        self
    }

    /// The kernel's identity: `/kernel/info` and a stand-in `/kernel/boot.wasm`.
    pub fn kernel(&mut self) -> &mut Self {
        self.put(
            KERNEL_INFO_KEY.to_string(),
            &KernelInfoEnvelope::V1(KernelInfo {
                version: KERNEL_VERSION.to_string(),
                supported_games: vec!["crash".to_string()],
                admin_subtags: vec![0x00],
            }),
        );
        self.0
            .insert(KERNEL_BOOT_KEY.to_string(), hex::encode(kernel_bytes()));
        self
    }

    pub fn session(&mut self, session: &[u8; 16], vault: &str, ended: bool) -> &mut Self {
        let id = Uuid::from_bytes(*session);
        self.put(
            session_key(TENANT, POOL, &id),
            &StoredSessionEnvelope::V1(StoredSession {
                owner: OWNER.to_string(),
                asset: TEZ.to_string(),
                balance: 0,
                funding_vault_address: vault.to_string(),
                ended,
                end_reason: ended.then(|| "player".to_string()),
            }),
        )
    }

    /// The session's `session-{session_id}-end-payout` row as the kernel's `EndSession`
    /// writes it: a `SessionEndPayout`, the balance leaving the rollup.
    pub fn payout(&mut self, session: &[u8; 16], amount: u128) -> &mut Self {
        self.payout_of_kind(session, amount, StoredTransactionKind::SessionEndPayout)
    }

    /// A row of another kind at the session's payout key: what the watcher
    /// must refuse to price a fast payout against.
    pub fn payout_of_kind(
        &mut self,
        session: &[u8; 16],
        amount: u128,
        kind: StoredTransactionKind,
    ) -> &mut Self {
        let id = Uuid::from_bytes(*session);
        self.put(
            session_end_payout_key(TENANT, POOL, TEZ, &id),
            &StoredTransactionEnvelope::V1(StoredTransaction {
                account_address: OWNER.to_string(),
                asset: TEZ.to_string(),
                kind,
                amount,
            }),
        )
    }
}

/// Stand-in kernel bytes: what the fixture's node has installed.
pub fn kernel_bytes() -> Vec<u8> {
    (0..5_000u32)
        .map(|i| (i.wrapping_mul(31) % 251) as u8)
        .collect()
}
