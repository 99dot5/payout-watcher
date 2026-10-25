//! The signed payload: `PACK(("fast-payout:v1", chain_id, vault, session_id,
//! amount))`, a 5-tuple right comb.
//!
//! The leaf encodings are the Michelson value types `PACK` serialises
//! (`tezos-smart-rollup-encoding`), prefixed with the `0x05` PACK magic; the
//! Micheline `Int` node the `mutez` amount becomes is the same bytes a `nat`
//! gets, and the session id is the 16 raw bytes, never its hyphenated text —
//! the rule every other wire in this repository follows. Chain ids and vault
//! addresses are decoded by the pinned `tezos_crypto_rs`'s typed decoders,
//! which compare the base58check prefix and the payload length.

use num_bigint::BigInt;
use tezos_crypto_rs::hash::{ChainId as ChainIdHash, ContractKt1Hash};
use tezos_data_encoding::{enc::BinWriter, types::Zarith};
use tezos_protocol::contract::Contract;
use tezos_smart_rollup_encoding::michelson::{
    MichelsonBytes, MichelsonInt, MichelsonPair, MichelsonString,
};
use thiserror::Error;

/// Domain-separation tag `fast_payout` verifies under — must match
/// `crypto/vault-contract/src/vault_contract/main.py` and
/// `local-env/admin-ops/gen_fast_payout_vectors.py`.
pub const FAST_PAYOUT_DOMAIN: &str = "fast-payout:v1";

/// The contract's `PAYOUT_SIGNER_COUNT`: a vault holds exactly this many
/// fast-payout signers — the sequencer, the validator and two cold recovery
/// keys (ADR 0027 §4.2, amendment 2026-10-20).
pub const PAYOUT_SIGNER_COUNT: usize = 4;

/// The contract's `PAYOUT_THRESHOLD`: how many of the set must sign.
pub const PAYOUT_THRESHOLD: usize = 2;

/// The `0x05` byte Tezos `PACK` prefixes every packed value with.
pub(crate) const PACK_MAGIC: u8 = 0x05;

const CHAIN_ID_LEN: usize = 4;
const ADDRESS_HASH_LEN: usize = 20;

/// Why a chain id or vault address was refused.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PayloadError {
    #[error("'{text}' is not a chain id (`Net…`, base58check with the Net prefix and 4 bytes)")]
    InvalidChainId { text: String },
    #[error("'{text}' is not an originated contract address (`KT1…`)")]
    InvalidVaultAddress { text: String },
    #[error("'{text}' is not an implicit account address (`tz1…`/`tz2…`/`tz3…`)")]
    InvalidSenderAddress { text: String },
}

/// A Tezos chain id, decoded once from its `Net…` text to the 4 raw bytes
/// `PACK` emits (the same bytes `sp.chain_id_cst` is given).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainId {
    text: String,
    raw: [u8; CHAIN_ID_LEN],
}

impl ChainId {
    /// Decode `Net…`, comparing the prefix bytes.
    pub fn parse(text: &str) -> Result<Self, PayloadError> {
        let chain_id =
            ChainIdHash::from_base58_check(text).map_err(|_| PayloadError::InvalidChainId {
                text: text.to_string(),
            })?;

        Ok(Self {
            text: text.to_string(),
            raw: *chain_id,
        })
    }

    /// The `Net…` text as given.
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// The 4 raw bytes.
    pub fn raw(&self) -> &[u8; CHAIN_ID_LEN] {
        &self.raw
    }
}

/// A vault's `KT1…` address, decoded once by prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultAddress {
    text: String,
    hash: [u8; ADDRESS_HASH_LEN],
}

impl VaultAddress {
    /// Decode `KT1…`, comparing the prefix bytes: a `tz1…` or `sr1…` pasted
    /// where a vault belongs is refused here, before anything is signed.
    pub fn parse(text: &str) -> Result<Self, PayloadError> {
        let hash = ContractKt1Hash::from_base58_check(text).map_err(|_| {
            PayloadError::InvalidVaultAddress {
                text: text.to_string(),
            }
        })?;

        Ok(Self {
            text: text.to_string(),
            hash: *hash,
        })
    }

    /// The `KT1…` text as given.
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// The 20-byte contract hash.
    pub fn hash(&self) -> &[u8; ADDRESS_HASH_LEN] {
        &self.hash
    }

    /// The forged `address` bytes `PACK` emits for an originated contract:
    /// `0x01 || hash20 || 0x00` (the default entrypoint).
    pub fn forged(&self) -> Vec<u8> {
        Contract::Originated(ContractKt1Hash::from(self.hash))
            .to_bytes()
            .expect("a contract always forges")
    }
}

/// The bytes two of the four payout signers sign for a fast payout of
/// `amount_mutez` to the session `session_id` (its 16 raw bytes) on `vault`,
/// on the chain `chain_id`.
pub fn fast_payout_payload(
    chain_id: &ChainId,
    vault: &VaultAddress,
    session_id: &[u8; 16],
    amount_mutez: u64,
) -> Vec<u8> {
    let payload = MichelsonPair(
        MichelsonString(FAST_PAYOUT_DOMAIN.to_string()),
        MichelsonPair(
            MichelsonBytes(chain_id.raw.to_vec()),
            MichelsonPair(
                MichelsonBytes(vault.forged()),
                MichelsonPair(
                    MichelsonBytes(session_id.to_vec()),
                    MichelsonInt(Zarith(BigInt::from(amount_mutez))),
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

#[cfg(test)]
mod tests {
    use super::*;

    const CHAIN_ID: &str = "NetXdQprcVkpaWU";
    const KT1: &str = "KT1BuEZtb68c1Q4yjtckcNjGELqWt56Xyesc";

    #[test]
    fn chain_id_decodes_to_the_four_bytes_sp_chain_id_cst_takes() {
        let chain = ChainId::parse(CHAIN_ID).expect("chain id");

        assert_eq!(chain.raw(), &[0x7a, 0x06, 0xa7, 0x70]);
        assert_eq!(chain.as_str(), CHAIN_ID);
    }

    #[test]
    fn a_vault_address_is_decoded_by_prefix_not_by_length() {
        let vault = VaultAddress::parse(KT1).expect("kt1");

        assert_eq!(vault.as_str(), KT1);
        assert_eq!(vault.forged()[0], 0x01);
        assert_eq!(&vault.forged()[1..21], vault.hash());
        assert_eq!(vault.forged()[21], 0x00);
        assert_eq!(vault.forged().len(), 22);
        // A tz1 and an sr1 are 23-byte base58check values too; only the
        // prefix tells them apart.
        for not_a_vault in [
            "tz1UyQDepgtUBnWjyzzonqeDwaiWoQzRKSP5",
            "sr1TMxAUtDA4sDL7C4r39L18iQjhRcBRzd8a",
            "KT1BuEZtb68c1Q4yjtckcNjGELqWt56Xyesd",
            "",
        ] {
            assert!(
                matches!(
                    VaultAddress::parse(not_a_vault),
                    Err(PayloadError::InvalidVaultAddress { .. })
                ),
                "{not_a_vault}"
            );
        }
        assert!(matches!(
            ChainId::parse(KT1),
            Err(PayloadError::InvalidChainId { .. })
        ));
    }

    #[test]
    fn the_payload_is_a_domain_tagged_five_tuple() {
        let chain = ChainId::parse(CHAIN_ID).expect("chain id");
        let vault = VaultAddress::parse(KT1).expect("kt1");
        let session_id = [0xAAu8; 16];
        let packed = fast_payout_payload(&chain, &vault, &session_id, 3_000_000);
        let mut expected = vec![0x05, 0x07, 0x07, 0x01, 0, 0, 0, 14];

        expected.extend_from_slice(b"fast-payout:v1");
        expected.extend_from_slice(&[0x07, 0x07, 0x0a, 0, 0, 0, 4, 0x7a, 0x06, 0xa7, 0x70]);
        expected.extend_from_slice(&[0x07, 0x07, 0x0a, 0, 0, 0, 22, 0x01]);
        expected.extend_from_slice(vault.hash());
        expected.push(0x00);
        expected.extend_from_slice(&[0x07, 0x07, 0x0a, 0, 0, 0, 16]);
        expected.extend_from_slice(&session_id);
        // zarith of 3_000_000: `80 9b ee 02`
        expected.extend_from_slice(&[0x00, 0x80, 0x9b, 0xee, 0x02]);

        assert_eq!(packed, expected);
    }
}
