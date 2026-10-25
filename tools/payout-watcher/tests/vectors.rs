//! The watcher's two reads of a `fast_payout` call — the parameter decoding
//! and the signature verdict — pinned to the shared fast-payout vectors
//! (`tools/operator-cli/tests/fast-payout-vectors.json`, generated with
//! pytezos; the vault's own `sp.pack` agrees with the same file).
//!
//! Every `fast_payout_cases` row is rendered as the parameter value a node
//! would show for that call, in the readable form (keys and signatures as
//! base58 strings) and in the optimised form (forged bytes), decoded by the
//! watcher, verified against the fixture's `payout_signers`, and the verdict
//! compared with the one pytezos wrote.

use payout_protocol::{ChainId, VaultAddress, fast_payout_payload};
use payout_watcher::events::decode_fast_payout_call;
use payout_watcher::signatures::verify_call;
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use tezos_wallet_signature::{KeyCurve, decode_public_key, decode_signature};

#[derive(Deserialize)]
struct Vectors {
    chain_id: String,
    vault: String,
    payout_signers: Vec<String>,
    payloads: BTreeMap<String, Payload>,
    signers: BTreeMap<String, Signer>,
    fast_payout_cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Payload {
    #[serde(default)]
    session_id: Option<String>,
    #[serde(default)]
    amount_mutez: Option<u64>,
    bytes: String,
}

#[derive(Deserialize)]
struct Signer {
    public_key: String,
    signatures: BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct Entry {
    key: String,
    payload: String,
    signed_by: String,
}

#[derive(Deserialize)]
struct Case {
    name: String,
    signatures: Vec<Entry>,
    verdict: String,
}

fn vectors() -> Vectors {
    serde_json::from_str(include_str!(
        "../../operator-cli/tests/fast-payout-vectors.json"
    ))
    .expect("fixture parses")
}

#[derive(Clone, Copy)]
enum Form {
    Readable,
    Optimised,
}

fn key_node(key: &str, form: Form) -> Value {
    match form {
        Form::Readable => json!({ "string": key }),
        Form::Optimised => {
            let decoded = decode_public_key(key).expect("key");
            let tag = match decoded.curve {
                KeyCurve::Ed25519 => 0u8,
                KeyCurve::Secp256k1 => 1,
                KeyCurve::P256 => 2,
            };
            let mut bytes = vec![tag];
            bytes.extend_from_slice(&decoded.raw);
            json!({ "bytes": hex::encode(bytes) })
        }
    }
}

fn signature_node(signature: &str, form: Form) -> Value {
    match form {
        Form::Readable => json!({ "string": signature }),
        Form::Optimised => {
            json!({ "bytes": hex::encode(decode_signature(signature).expect("sig").raw) })
        }
    }
}

/// The parameter value of the case's call: `Pair amount (Pair session_id
/// {Elt key signature; …})`, for the fixture's `fast_payout` payload.
fn call_value(v: &Vectors, case: &Case, form: Form) -> Value {
    let fast = &v.payloads["fast_payout"];
    let elts: Vec<Value> = case
        .signatures
        .iter()
        .map(|e| {
            json!({"prim": "Elt", "args": [
                key_node(&v.signers[&e.key].public_key, form),
                signature_node(&v.signers[&e.signed_by].signatures[&e.payload], form),
            ]})
        })
        .collect();

    json!({"prim": "Pair", "args": [
        {"int": fast.amount_mutez.expect("amount").to_string()},
        {"prim": "Pair", "args": [
            {"bytes": fast.session_id.as_deref().expect("session")},
            elts,
        ]},
    ]})
}

#[test]
fn the_shared_encoder_reproduces_the_fixture_payload() {
    let v = vectors();
    let fast = &v.payloads["fast_payout"];
    let session: [u8; 16] = hex::decode(fast.session_id.as_deref().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let payload = fast_payout_payload(
        &ChainId::parse(&v.chain_id).unwrap(),
        &VaultAddress::parse(&v.vault).unwrap(),
        &session,
        fast.amount_mutez.unwrap(),
    );

    assert_eq!(hex::encode(payload), fast.bytes);
}

#[test]
fn every_fast_payout_case_decodes_and_gets_the_vaults_verdict_in_both_forms() {
    let v = vectors();
    let chain_id = ChainId::parse(&v.chain_id).expect("chain id");
    let vault = VaultAddress::parse(&v.vault).expect("vault");
    let signers: BTreeSet<String> = v.payout_signers.iter().cloned().collect();
    let fast = &v.payloads["fast_payout"];
    let mut checked = 0;

    for case in &v.fast_payout_cases {
        for form in [Form::Readable, Form::Optimised] {
            let call = decode_fast_payout_call(&call_value(&v, case, form))
                .unwrap_or_else(|e| panic!("{}: {e}", case.name));

            assert_eq!(
                hex::encode(call.session_id),
                fast.session_id.as_deref().unwrap()
            );
            assert_eq!(call.amount, u128::from(fast.amount_mutez.unwrap()));
            assert_eq!(call.signatures.len(), case.signatures.len());

            let verdict = verify_call(
                &chain_id,
                &vault,
                &call.session_id,
                fast.amount_mutez.unwrap(),
                &call.signatures,
                &signers,
            );
            let watcher_verdict = if verdict.under_threshold() {
                "Under threshold"
            } else {
                "accepted"
            };
            assert_eq!(watcher_verdict, case.verdict, "{}", case.name);

            // Keys outside the set are reported, never counted.
            let mallory = &v.signers["mallory"].public_key;
            let has_mallory = case
                .signatures
                .iter()
                .any(|e| &v.signers[&e.key].public_key == mallory);
            assert_eq!(
                verdict.foreign.iter().any(|(k, _)| k == mallory),
                has_mallory,
                "{}",
                case.name
            );
            assert!(verdict.valid.iter().all(|k| signers.contains(k)));
            checked += 1;
        }
    }

    assert_eq!(checked, 2 * v.fast_payout_cases.len());
    assert!(checked >= 26, "the fixture's cases are all exercised");
}

#[test]
fn a_signature_over_another_amount_is_invalid_not_foreign() {
    let v = vectors();
    let case = v
        .fast_payout_cases
        .iter()
        .find(|c| c.name == "one_right_one_over_other_amount")
        .expect("case");
    let call = decode_fast_payout_call(&call_value(&v, case, Form::Readable)).unwrap();
    let verdict = verify_call(
        &ChainId::parse(&v.chain_id).unwrap(),
        &VaultAddress::parse(&v.vault).unwrap(),
        &call.session_id,
        v.payloads["fast_payout"].amount_mutez.unwrap(),
        &call.signatures,
        &v.payout_signers.iter().cloned().collect(),
    );

    assert_eq!(verdict.valid, vec![v.signers["sp_a"].public_key.clone()]);
    assert_eq!(verdict.invalid.len(), 1);
    assert_eq!(verdict.invalid[0].0, v.signers["sp_b"].public_key);
    assert!(verdict.foreign.is_empty());
}
