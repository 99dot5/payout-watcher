//! The session binding: the session key's signature a first `deposit`
//! carries, in the form the vault's `deposit` verifies (ADR 0008; `docs/
//! architecture.md` §4.7).
//!
//! The vault binds `(owner, session_public_key)` to a session on its first
//! deposit only under a signature by that session key over
//!
//! ```text
//! PACK(("session-binding:v1", chain_id, vault, session_id, sender, session_public_key))
//! ```
//!
//! a 6-tuple right comb. The leaf encodings follow
//! [`deposit_authorisation_payload`](crate::deposit_authorisation_payload):
//! the vault and the sender are optimised `address` leaves, the session id a
//! `bytes` leaf, and the session key the optimised `key` leaf `PACK` emits,
//! `curve tag ‖ raw key` (`0x00 ‖ 32 bytes` for Ed25519, the only curve the
//! vault binds). Byte-pinned to the client's golden
//! (`libs/casino-client/src/wallet/signature.test.ts`), which the vault's own
//! `sp.pack` produced.
//!
//! The browser-held session key is the one thing a session's player has that
//! nobody else does, so the signature doubles as the player's consent to
//! whatever asks for it off chain: the sequencer issues the deposit
//! authorisation of a session (ADR 0027 §4.4) only to a request that carries
//! it, verified against the key the session was created under. A party who
//! learns a session id — from the mempool, say — cannot sign for the key and
//! so cannot be authorised to bind the session to another wallet.

use crate::SenderAddress;
use crate::payload::{ChainId, PACK_MAGIC, VaultAddress};
use tezos_data_encoding::enc::BinWriter;
use tezos_smart_rollup_encoding::michelson::{MichelsonBytes, MichelsonPair, MichelsonString};
use tezos_wallet_signature::{
    DecodedPublicKey, WalletSignatureError, decode_public_key, verify_over,
};

/// Domain-separation tag the vault verifies a session binding under — must
/// match `crypto/vault-contract/src/vault_contract/main.py` and
/// `SESSION_BINDING_DOMAIN` in `libs/casino-client/src/wallet/signature.ts`.
pub const SESSION_BINDING_DOMAIN: &str = "session-binding:v1";

/// The bytes the session key signs to bind the session `session_id` (its 16
/// raw bytes) to the wallet `sender` and the key `session_public_key` on
/// `vault` on chain `chain_id`.
pub fn session_binding_payload(
    chain_id: &ChainId,
    vault: &VaultAddress,
    session_id: &[u8; 16],
    sender: &SenderAddress,
    session_public_key: &DecodedPublicKey,
) -> Vec<u8> {
    let payload = MichelsonPair(
        MichelsonString(SESSION_BINDING_DOMAIN.to_string()),
        MichelsonPair(
            MichelsonBytes(chain_id.raw().to_vec()),
            MichelsonPair(
                MichelsonBytes(vault.forged()),
                MichelsonPair(
                    MichelsonBytes(session_id.to_vec()),
                    MichelsonPair(
                        MichelsonBytes(sender.forged()),
                        MichelsonBytes(session_public_key.forged()),
                    ),
                ),
            ),
        ),
    );
    let mut out = vec![PACK_MAGIC];

    payload
        .bin_write(&mut out)
        .expect("Michelson bin_write into a Vec is infallible");

    out
}

/// Check that `signature` is `session_public_key`'s signature over the
/// binding of `session_id` to `sender` on `vault` on `chain_id` — the exact
/// check the vault's `deposit` makes, over the same bytes.
///
/// `session_public_key` is the key text the session was created under
/// (`edpk…`); a key that does not decode, a signature of another curve, or a
/// signature over any other binding (another wallet, session, vault or
/// chain) is an error.
pub fn verify_session_binding(
    chain_id: &ChainId,
    vault: &VaultAddress,
    session_id: &[u8; 16],
    sender: &SenderAddress,
    session_public_key: &str,
    signature: &str,
) -> Result<(), WalletSignatureError> {
    let key = decode_public_key(session_public_key)?;
    let payload = session_binding_payload(chain_id, vault, session_id, sender, &key);

    verify_over(session_public_key, signature, &payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    // The client's golden gate (`signature.test.ts`): the inputs of the
    // vault's own `test_deposit_success` scenario, the bytes its `sp.pack`
    // produced, and the `edsig…` the scenario's session key put over them.
    const CHAIN: &str = "NetXdQprcVkpaWU";
    const CHAIN_RAW: [u8; 4] = [0x7a, 0x06, 0xa7, 0x70];
    const VAULT: &str = "KT1TezoooozzSmartPyzzSTATiCzzzwwBFA1";
    const SENDER: &str = "tz1h4EsGunH2Ue1T2uNs8mfKZ8XZoQji3HcK";
    const SESSION_KEY: &str = "edpkuEJbQZpSunwAsVub3WXq4wYQpJCQpbJyGgyVNhoarnjSLmzmXu";
    const SESSION_ID: [u8; 16] = [0xaa; 16];
    const GOLDEN_EDSIG: &str = "edsigtt9Lv1NfP3BsV7Urjq24X32p6oDsemG9k3YKRxm7pR1hzYtC8wtDj2XtowkUkphYqodHtQghNK6Va36VTfAFmCwXEeQKsj";
    /// The scenario's chain id is the literal `0x9caecab9`, which has no
    /// `Net…` text; the golden bytes are pinned with it spliced in.
    const SCENARIO_CHAIN_RAW: [u8; 4] = [0x9c, 0xae, 0xca, 0xb9];
    const GOLDEN_PACKED_HEX: &str = concat!(
        "050707010000001273657373696f6e2d62696e64696e673a763107070a000000049caecab9",
        "07070a0000001601d1371b91fdbd07c8855659c84652230be0eaecd50007070a00000010",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa07070a000000160000eaeec9ada5305ad61fc452a5",
        "ee9f7d4f55f804670a00000021004d622bc12c0df1a49baff6beab548b7765b021e29b53e8",
        "ff0f0c41d972be4d0d",
    );

    fn golden_payload() -> Vec<u8> {
        let payload = session_binding_payload(
            &ChainId::parse(CHAIN).unwrap(),
            &VaultAddress::parse(VAULT).unwrap(),
            &SESSION_ID,
            &SenderAddress::parse(SENDER).unwrap(),
            &decode_public_key(SESSION_KEY).unwrap(),
        );
        // Swap the real chain id's bytes for the scenario literal's.
        let at = payload
            .windows(4)
            .position(|window| window == CHAIN_RAW)
            .expect("the chain id leaf is in the payload");
        let mut payload = payload;

        payload[at..at + 4].copy_from_slice(&SCENARIO_CHAIN_RAW);
        payload
    }

    #[test]
    fn packs_the_binding_to_the_vaults_own_bytes() {
        assert_eq!(hex::encode(golden_payload()), GOLDEN_PACKED_HEX);
    }

    #[test]
    fn the_golden_signature_verifies_over_the_packed_bytes() {
        verify_over(SESSION_KEY, GOLDEN_EDSIG, &golden_payload())
            .expect("the scenario's session key signed exactly these bytes");
    }

    #[test]
    fn another_wallet_session_or_vault_does_not_verify() {
        // The real chain id packs differently from the scenario literal, so
        // every full-path verify below fails for that reason alone unless
        // the chain is also right; pin the reason by checking the leaves.
        let chain = ChainId::parse(CHAIN).unwrap();
        let vault = VaultAddress::parse(VAULT).unwrap();
        let sender = SenderAddress::parse(SENDER).unwrap();
        let key = decode_public_key(SESSION_KEY).unwrap();
        let reference = session_binding_payload(&chain, &vault, &SESSION_ID, &sender, &key);
        let other_sender = SenderAddress::parse("tz2BFTyPeYRzxd5aiBchbXN3WCZhx7BqbMBq").unwrap();
        let other_session = [0xbb; 16];
        let other_vault = VaultAddress::parse("KT1BuEZtb68c1Q4yjtckcNjGELqWt56Xyesc").unwrap();

        assert_ne!(
            session_binding_payload(&chain, &vault, &SESSION_ID, &other_sender, &key),
            reference
        );
        assert_ne!(
            session_binding_payload(&chain, &vault, &other_session, &sender, &key),
            reference
        );
        assert_ne!(
            session_binding_payload(&chain, &other_vault, &SESSION_ID, &sender, &key),
            reference
        );
        // And the golden signature is over the scenario's binding, not this
        // chain's: the full check refuses it.
        assert_eq!(
            verify_session_binding(
                &chain,
                &vault,
                &SESSION_ID,
                &sender,
                SESSION_KEY,
                GOLDEN_EDSIG
            ),
            Err(WalletSignatureError::DoesNotVerify)
        );
    }

    #[test]
    fn a_key_that_does_not_decode_is_refused_before_any_arithmetic() {
        let chain = ChainId::parse(CHAIN).unwrap();
        let vault = VaultAddress::parse(VAULT).unwrap();
        let sender = SenderAddress::parse(SENDER).unwrap();

        assert!(
            verify_session_binding(
                &chain,
                &vault,
                &SESSION_ID,
                &sender,
                "edpknope",
                GOLDEN_EDSIG
            )
            .is_err()
        );
        // A secp256k1 signature offered against the Ed25519 session key.
        assert_eq!(
            verify_session_binding(
                &chain,
                &vault,
                &SESSION_ID,
                &sender,
                SESSION_KEY,
                "spsig161NWr7VBk1Knu8hkuYhwszYh8kpSF2nb9gWp3R5jit9m1UmqFV7ExKefmxf8EFYSSVptot5CNVYSHoqBfzUWrr11zJDVF",
            ),
            Err(WalletSignatureError::SignatureCurveMismatch {
                key: tezos_wallet_signature::KeyCurve::Ed25519,
                signature: tezos_wallet_signature::KeyCurve::Secp256k1,
            })
        );
    }
}
