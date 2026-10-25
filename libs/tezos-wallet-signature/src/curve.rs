//! The three supported curves and their base58check prefixes.
//!
//! The prefix literals stay `const` for callers that need them at compile
//! time (`HashType::base58check_prefix` is not `const`); a test pins each one
//! to the `tezos_crypto_rs` prefix it names, and decoding itself goes through
//! that crate.

use core::fmt;
use tezos_crypto_rs::hash::HashType;

/// Prefix of the generic `sig…` signature form, valid with any key.
pub const GENERIC_SIGNATURE_PREFIX: [u8; 3] = [4, 130, 43];
/// Raw length of every supported signature.
pub const SIGNATURE_LEN: usize = 64;
/// Length of an implicit-account address hash (`blake2b-160`).
pub const ADDRESS_HASH_LEN: usize = 20;

/// A supported signing curve.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyCurve {
    Ed25519,
    Secp256k1,
    P256,
}

impl KeyCurve {
    pub const ALL: [KeyCurve; 3] = [KeyCurve::Ed25519, KeyCurve::Secp256k1, KeyCurve::P256];

    /// Raw public-key length (Ed25519 32; compressed secp256k1/P-256 33).
    pub const fn public_key_len(self) -> usize {
        match self {
            KeyCurve::Ed25519 => 32,
            KeyCurve::Secp256k1 | KeyCurve::P256 => 33,
        }
    }

    /// `edpk` / `sppk` / `p2pk`.
    pub const fn public_key_prefix(self) -> &'static [u8] {
        match self {
            KeyCurve::Ed25519 => &[13, 15, 37, 217],
            KeyCurve::Secp256k1 => &[3, 254, 226, 86],
            KeyCurve::P256 => &[3, 178, 139, 127],
        }
    }

    /// `edsig` / `spsig1` / `p2sig`.
    pub const fn signature_prefix(self) -> &'static [u8] {
        match self {
            KeyCurve::Ed25519 => &[9, 245, 205, 134, 18],
            KeyCurve::Secp256k1 => &[13, 115, 101, 19, 63],
            KeyCurve::P256 => &[54, 240, 44, 52],
        }
    }

    /// `tz1` / `tz2` / `tz3`.
    pub const fn address_prefix(self) -> &'static [u8] {
        match self {
            KeyCurve::Ed25519 => &[6, 161, 159],
            KeyCurve::Secp256k1 => &[6, 161, 161],
            KeyCurve::P256 => &[6, 161, 164],
        }
    }

    /// The curve tag that leads a forged public key or public-key hash.
    pub const fn forge_tag(self) -> u8 {
        match self {
            KeyCurve::Ed25519 => 0,
            KeyCurve::Secp256k1 => 1,
            KeyCurve::P256 => 2,
        }
    }

    /// The curve a forged tag names; `None` for BLS (`3`) and unknown tags.
    pub const fn from_forge_tag(tag: u8) -> Option<KeyCurve> {
        match tag {
            0 => Some(KeyCurve::Ed25519),
            1 => Some(KeyCurve::Secp256k1),
            2 => Some(KeyCurve::P256),
            _ => None,
        }
    }

    /// The `tezos_crypto_rs` hash type of this curve's public key.
    pub(crate) fn public_key_type(self) -> HashType {
        match self {
            KeyCurve::Ed25519 => HashType::PublicKeyEd25519,
            KeyCurve::Secp256k1 => HashType::PublicKeySecp256k1,
            KeyCurve::P256 => HashType::PublicKeyP256,
        }
    }
}

/// The forged tag of a BLS key or `tz4` hash, recognised only to be refused.
pub(crate) const BLS_FORGE_TAG: u8 = 3;

impl fmt::Display for KeyCurve {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            KeyCurve::Ed25519 => "Ed25519",
            KeyCurve::Secp256k1 => "secp256k1",
            KeyCurve::P256 => "P-256",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every `const` literal above is the pinned crypto crate's prefix.
    #[test]
    fn prefix_literals_equal_the_crypto_crate_prefixes() {
        assert_eq!(
            GENERIC_SIGNATURE_PREFIX.as_slice(),
            HashType::UnknownSignature.base58check_prefix()
        );
        assert_eq!(SIGNATURE_LEN, HashType::UnknownSignature.size());
        assert_eq!(ADDRESS_HASH_LEN, HashType::ContractTz1Hash.size());

        let hash_types = [
            (HashType::Ed25519Signature, HashType::ContractTz1Hash),
            (HashType::Secp256k1Signature, HashType::ContractTz2Hash),
            (HashType::P256Signature, HashType::ContractTz3Hash),
        ];
        for (curve, (signature_type, address_type)) in KeyCurve::ALL.into_iter().zip(hash_types) {
            assert_eq!(
                curve.public_key_prefix(),
                curve.public_key_type().base58check_prefix(),
                "{curve} public key"
            );
            assert_eq!(
                curve.public_key_len(),
                curve.public_key_type().size(),
                "{curve} public key length"
            );
            assert_eq!(
                curve.signature_prefix(),
                signature_type.base58check_prefix(),
                "{curve} signature"
            );
            assert_eq!(
                SIGNATURE_LEN,
                signature_type.size(),
                "{curve} signature length"
            );
            assert_eq!(
                curve.address_prefix(),
                address_type.base58check_prefix(),
                "{curve} address"
            );
        }
    }

    /// The forge tags are the crypto crate's binary encoding tags.
    #[test]
    fn forge_tags_equal_the_crypto_crate_encoding() {
        use tezos_crypto_rs::hash::{
            PublicKeyBls, PublicKeyEd25519, PublicKeyP256, PublicKeySecp256k1,
        };
        use tezos_crypto_rs::public_key::PublicKey;
        use tezos_data_encoding::enc::BinWriter;

        let tag = |key: PublicKey| key.to_bytes().expect("forges")[0];
        let keys = [
            PublicKey::Ed25519(PublicKeyEd25519::default()),
            PublicKey::Secp256k1(PublicKeySecp256k1::default()),
            PublicKey::P256(PublicKeyP256::default()),
        ];

        for (curve, key) in KeyCurve::ALL.into_iter().zip(keys) {
            assert_eq!(curve.forge_tag(), tag(key), "{curve}");
            assert_eq!(KeyCurve::from_forge_tag(curve.forge_tag()), Some(curve));
        }
        assert_eq!(BLS_FORGE_TAG, tag(PublicKey::Bls(PublicKeyBls::default())));
        assert_eq!(KeyCurve::from_forge_tag(BLS_FORGE_TAG), None);
        assert_eq!(KeyCurve::from_forge_tag(4), None);
    }
}
