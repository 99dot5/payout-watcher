//! The deposit authorisation: the backend's signature that admits a wallet's
//! deposit (ADR 0027 §4.4), in the form the vault's `deposit` verifies.
//!
//! The vault accepts a deposit only with a signature by its stored
//! `deposit_authoriser` over
//!
//! ```text
//! PACK(("deposit-authorisation:v1", chain_id, vault, sender, session_id, authorisation_expiry))
//! ```
//!
//! a 6-tuple right comb, and only while `sp.now < authorisation_expiry`. The
//! leaf encodings follow [`fast_payout_payload`](crate::fast_payout_payload):
//! the sender is the optimised `address` of an implicit account (`0x00 ‖
//! curve tag ‖ hash20`, no entrypoint suffix), the expiry a Micheline `Int`
//! of Unix seconds, which is how `PACK` serialises a `timestamp`. Byte-pinned
//! to `tools/operator-cli/tests/deposit-authorisation-vectors.json` beside the
//! vault's own `sp.pack`.
//!
//! An authorisation binds the wallet, the session, the vault and the chain,
//! so one leaked to another party authorises nothing; it carries no nonce on
//! purpose — within its window it serves every deposit of that wallet into
//! that session — and the signing key never moves funds: a stolen one can
//! only widen who may pay in.

use crate::payload::{ChainId, PACK_MAGIC, PayloadError, VaultAddress};
use crate::sign::{PayoutSigner, SignError, sign_payload};
use num_bigint::BigInt;
use tezos_data_encoding::{enc::BinWriter, types::Zarith};
use tezos_smart_rollup_encoding::michelson::{
    MichelsonBytes, MichelsonInt, MichelsonPair, MichelsonString,
};
use tezos_wallet_signature::{DecodedAddress, KeyCurve, WalletSignatureError, decode_address};

/// Domain-separation tag `deposit` verifies an authorisation under — must
/// match `crypto/vault-contract/src/vault_contract/main.py` and
/// `local-env/admin-ops/gen_deposit_authorisation_vectors.py`.
pub const DEPOSIT_AUTHORISATION_DOMAIN: &str = "deposit-authorisation:v1";

const ADDRESS_HASH_LEN: usize = 20;

/// The depositing wallet: an implicit account, decoded once by its
/// base58check prefix. `tz4` and `KT1` are refused, as the vault refuses them
/// at `deposit` (the rollup can pay neither back).
///
/// The acceptance set is `tezos_wallet_signature::decode_address`'s, the
/// wallet-signable rule (`tz1`–`tz3`): today the vault's deposit rule and the
/// wallet rule are the same set. If the vault ever admits another sender
/// kind, this type stops borrowing the wallet rule and states its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SenderAddress {
    text: String,
    curve: KeyCurve,
    hash: [u8; ADDRESS_HASH_LEN],
}

impl SenderAddress {
    /// Decode `tz1…`/`tz2…`/`tz3…`, comparing the prefix bytes.
    pub fn parse(text: &str) -> Result<Self, PayloadError> {
        let decoded = decode_address(text).map_err(|_| PayloadError::InvalidSenderAddress {
            text: text.to_string(),
        })?;

        Ok(Self {
            text: text.to_string(),
            curve: decoded.curve,
            hash: decoded.hash,
        })
    }

    /// The address text as given.
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// The curve of the account's key, which is also its address kind.
    pub fn curve(&self) -> KeyCurve {
        self.curve
    }

    /// The forged `address` bytes `PACK` emits for an implicit account:
    /// `0x00 || curve tag || hash20`.
    pub(crate) fn forged(&self) -> Vec<u8> {
        DecodedAddress {
            curve: self.curve,
            hash: self.hash,
        }
        .forged_address()
        .to_vec()
    }
}

/// The bytes the authoriser signs for a deposit by `sender` into the session
/// `session_id` (its 16 raw bytes) on `vault` on chain `chain_id`, valid
/// until `expiry_unix` (Unix seconds, exclusive).
pub fn deposit_authorisation_payload(
    chain_id: &ChainId,
    vault: &VaultAddress,
    sender: &SenderAddress,
    session_id: &[u8; 16],
    expiry_unix: i64,
) -> Vec<u8> {
    let payload = MichelsonPair(
        MichelsonString(DEPOSIT_AUTHORISATION_DOMAIN.to_string()),
        MichelsonPair(
            MichelsonBytes(chain_id.raw().to_vec()),
            MichelsonPair(
                MichelsonBytes(vault.forged()),
                MichelsonPair(
                    MichelsonBytes(sender.forged()),
                    MichelsonPair(
                        MichelsonBytes(session_id.to_vec()),
                        MichelsonInt(Zarith(BigInt::from(expiry_unix))),
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

/// A signed deposit authorisation, in the form the vault's `deposit` takes
/// and a client carries: the two parameter fields plus the key that signed
/// and the payload it is over.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DepositAuthorisation {
    /// The authoriser's `sppk…` — what the vault holds as `deposit_authoriser`.
    pub authoriser: String,
    /// The `spsig1…` over the payload: `deposit`'s `authorisation_signature`.
    pub signature: String,
    /// `deposit`'s `authorisation_expiry`, Unix seconds.
    pub expiry_unix: i64,
    /// The payload the signature is over, kept beside it. Hex on the wire.
    #[cfg_attr(feature = "serde", serde(with = "crate::sign::serde_hex"))]
    pub payload: Vec<u8>,
}

/// Sign the authorisation of a deposit by `sender` into `session_id` on
/// `vault` on chain `chain_id`, good until `expiry_unix`, with `signer`, and
/// check the result under the signer's own key before returning it.
pub async fn sign_deposit_authorisation<S: PayoutSigner>(
    signer: &S,
    chain_id: &ChainId,
    vault: &VaultAddress,
    sender: &SenderAddress,
    session_id: &[u8; 16],
    expiry_unix: i64,
) -> Result<DepositAuthorisation, SignError> {
    let payload = deposit_authorisation_payload(chain_id, vault, sender, session_id, expiry_unix);
    let signature = sign_payload(signer, &payload).await?;

    Ok(DepositAuthorisation {
        authoriser: signer.public_key().to_string(),
        signature,
        expiry_unix,
        payload,
    })
}

/// Verify that `signature` is `public_key`'s signature over a
/// deposit-authorisation `payload` — the check the vault's `CHECK_SIGNATURE`
/// makes. Ed25519, secp256k1 and P-256 keys, as the vault admits any `key`.
pub fn verify_deposit_authorisation_signature(
    public_key: &str,
    signature: &str,
    payload: &[u8],
) -> Result<(), WalletSignatureError> {
    tezos_wallet_signature::verify_over(public_key, signature, payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::LocalSecp256k1Signer;

    const CHAIN_ID: &str = "NetXdQprcVkpaWU";
    const KT1: &str = "KT1BuEZtb68c1Q4yjtckcNjGELqWt56Xyesc";
    const TZ1: &str = "tz1UyQDepgtUBnWjyzzonqeDwaiWoQzRKSP5";
    const TZ2: &str = "tz2BFTyPeYRzxd5aiBchbXN3WCZhx7BqbMBq";
    const TZ3: &str = "tz3RDC3Jdn4j15J7bBHZd29EUee9gVB1CxD9";

    #[test]
    fn a_sender_is_an_implicit_account_forged_by_its_curve() {
        for (text, tag, curve) in [
            (TZ1, 0x00, KeyCurve::Ed25519),
            (TZ2, 0x01, KeyCurve::Secp256k1),
            (TZ3, 0x02, KeyCurve::P256),
        ] {
            let sender = SenderAddress::parse(text).expect(text);
            let forged = sender.forged();

            assert_eq!(sender.as_str(), text);
            assert_eq!(sender.curve(), curve);
            assert_eq!(forged.len(), 2 + ADDRESS_HASH_LEN, "{text}");
            assert_eq!(forged[0], 0x00, "{text}");
            assert_eq!(forged[1], tag, "{text}");
            assert_eq!(forged[1], curve.forge_tag(), "{text}");
            assert_eq!(&forged[2..], &sender.hash, "{text}");
        }
        for not_a_sender in [
            KT1,
            "sr1TMxAUtDA4sDL7C4r39L18iQjhRcBRzd8a",
            "",
            TZ1.to_uppercase().as_str(),
        ] {
            assert!(
                matches!(
                    SenderAddress::parse(not_a_sender),
                    Err(PayloadError::InvalidSenderAddress { .. })
                ),
                "{not_a_sender}"
            );
        }
    }

    #[test]
    fn the_payload_is_a_domain_tagged_six_tuple() {
        let chain = ChainId::parse(CHAIN_ID).expect("chain id");
        let vault = VaultAddress::parse(KT1).expect("kt1");
        let sender = SenderAddress::parse(TZ1).expect("tz1");
        let payload = deposit_authorisation_payload(&chain, &vault, &sender, &[0x11u8; 16], 900);

        assert_eq!(payload[0], PACK_MAGIC);
        // Pair, Pair(string, …): the domain is the first leaf.
        assert_eq!(&payload[1..3], &[0x07, 0x07]);
        assert_eq!(payload[3], 0x01, "string node");
        assert_eq!(
            &payload[8..8 + DEPOSIT_AUTHORISATION_DOMAIN.len()],
            DEPOSIT_AUTHORISATION_DOMAIN.as_bytes()
        );
        // The expiry is the last leaf: a Micheline int node, 900 as a zarith.
        assert_eq!(&payload[payload.len() - 3..], &[0x00, 0x84, 0x0e]);
        // Every field moves the bytes.
        assert_ne!(
            payload,
            deposit_authorisation_payload(&chain, &vault, &sender, &[0x11u8; 16], 901)
        );
        assert_ne!(
            payload,
            deposit_authorisation_payload(
                &chain,
                &vault,
                &SenderAddress::parse(TZ2).expect("tz2"),
                &[0x11u8; 16],
                900
            )
        );
    }

    #[tokio::test]
    async fn a_local_signer_signs_an_authorisation_its_own_key_verifies() {
        let signer = LocalSecp256k1Signer::from_secret_exponent(&[7u8; 32]).expect("exponent");
        let chain = ChainId::parse(CHAIN_ID).expect("chain id");
        let vault = VaultAddress::parse(KT1).expect("kt1");
        let sender = SenderAddress::parse(TZ1).expect("tz1");
        let signed =
            sign_deposit_authorisation(&signer, &chain, &vault, &sender, &[0x11u8; 16], 900)
                .await
                .expect("signed");

        assert!(signed.authoriser.starts_with("sppk"));
        assert!(signed.signature.starts_with("spsig1"));
        assert_eq!(signed.expiry_unix, 900);
        assert_eq!(
            signed.payload,
            deposit_authorisation_payload(&chain, &vault, &sender, &[0x11u8; 16], 900)
        );
        verify_deposit_authorisation_signature(
            &signed.authoriser,
            &signed.signature,
            &signed.payload,
        )
        .expect("verifies");
        // Not over the fast-payout bytes of the same session, nor another expiry.
        let other = deposit_authorisation_payload(&chain, &vault, &sender, &[0x11u8; 16], 901);

        assert!(
            verify_deposit_authorisation_signature(&signed.authoriser, &signed.signature, &other)
                .is_err()
        );
    }
}
