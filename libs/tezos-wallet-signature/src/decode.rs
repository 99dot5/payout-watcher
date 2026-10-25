//! Prefix-checked base58check decoding of keys, signatures and addresses,
//! through the pinned `tezos_crypto_rs` decoders.
//!
//! Every decoder runs the same three steps, so the error a caller observes is
//! fixed: the checksum alone (`InvalidBase58`), then the byte prefix (a BLS or
//! originated value is `UnsupportedCurve`, an unknown prefix `Unrecognized`),
//! then the typed parse of the recognised curve (a wrong length is
//! `Unrecognized`).

use crate::WalletSignatureError;
use crate::curve::{ADDRESS_HASH_LEN, BLS_FORGE_TAG, KeyCurve, SIGNATURE_LEN};
use tezos_crypto_rs::base58::FromBase58Check;
use tezos_crypto_rs::hash::{
    ContractTz1Hash, ContractTz2Hash, ContractTz3Hash, HashType, PublicKeyEd25519, PublicKeyP256,
    PublicKeySecp256k1, UnknownSignature,
};
use tezos_crypto_rs::public_key::PublicKey;
use tezos_crypto_rs::public_key_hash::PublicKeyHash;
use tezos_crypto_rs::signature::Signature;
use tezos_data_encoding::enc::BinWriter;
use tezos_data_encoding::nom::NomReader;
use tezos_protocol::contract::Contract;

/// A public key classified by `(prefix, payload length)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedPublicKey {
    pub curve: KeyCurve,
    pub raw: Vec<u8>,
}

/// A signature; `curve` is `None` for the generic `sig…` form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedSignature {
    pub curve: Option<KeyCurve>,
    pub raw: Vec<u8>,
}

/// An implicit-account address (`tz1`/`tz2`/`tz3`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodedAddress {
    pub curve: KeyCurve,
    pub hash: [u8; ADDRESS_HASH_LEN],
}

impl DecodedPublicKey {
    /// The forged key, `tag ‖ raw` (33 bytes for Ed25519, 34 otherwise).
    ///
    /// # Panics
    ///
    /// If `raw` is not the curve's key length, which no value returned by
    /// [`decode_public_key`] or [`public_key_from_forged`] is.
    pub fn forged(&self) -> Vec<u8> {
        self.public_key()
            .to_bytes()
            .expect("a public key always forges")
    }

    /// The key as `edpk…` / `sppk…` / `p2pk…` text.
    ///
    /// # Panics
    ///
    /// As [`DecodedPublicKey::forged`].
    pub fn to_base58_check(&self) -> String {
        self.public_key().to_b58check()
    }

    /// The crypto crate's typed form of this key.
    fn public_key(&self) -> PublicKey {
        let raw = self.raw.as_slice();

        match self.curve {
            KeyCurve::Ed25519 => PublicKeyEd25519::try_from(raw).map(PublicKey::Ed25519),
            KeyCurve::Secp256k1 => PublicKeySecp256k1::try_from(raw).map(PublicKey::Secp256k1),
            KeyCurve::P256 => PublicKeyP256::try_from(raw).map(PublicKey::P256),
        }
        .expect("raw is the curve's public-key length")
    }
}

impl DecodedAddress {
    /// The forged public-key hash, `tag ‖ hash` (the `public_key_hash` form).
    pub fn forged_implicit(&self) -> [u8; 21] {
        let bytes = self
            .public_key_hash()
            .to_bytes()
            .expect("a public-key hash always forges");

        bytes.try_into().expect("tag and a 20-byte hash")
    }

    /// The forged implicit contract, `00 ‖ tag ‖ hash` (the `address` form).
    pub fn forged_address(&self) -> [u8; 22] {
        let bytes = Contract::Implicit(self.public_key_hash())
            .to_bytes()
            .expect("a contract always forges");

        bytes
            .try_into()
            .expect("implicit marker, tag and a 20-byte hash")
    }

    /// The crypto crate's typed form of this address.
    pub(crate) fn public_key_hash(&self) -> PublicKeyHash {
        match self.curve {
            KeyCurve::Ed25519 => PublicKeyHash::Ed25519(ContractTz1Hash::from(self.hash)),
            KeyCurve::Secp256k1 => PublicKeyHash::Secp256k1(ContractTz2Hash::from(self.hash)),
            KeyCurve::P256 => PublicKeyHash::P256(ContractTz3Hash::from(self.hash)),
        }
    }
}

/// Step 1: the checksum alone, so a broken value is `InvalidBase58` whatever
/// its prefix.
fn base58check(text: &str) -> Result<Vec<u8>, WalletSignatureError> {
    text.from_base58check()
        .map_err(|_| WalletSignatureError::InvalidBase58)
}

/// Decode an `edpk…`/`sppk…`/`p2pk…` key; `BLpk…` is unsupported.
pub fn decode_public_key(key: &str) -> Result<DecodedPublicKey, WalletSignatureError> {
    const KIND: &str = "public key";
    let decoded = base58check(key)?;

    if decoded.starts_with(HashType::PublicKeyBls.base58check_prefix()) {
        return Err(WalletSignatureError::UnsupportedCurve { kind: KIND });
    }
    let curve = KeyCurve::ALL
        .into_iter()
        .find(|curve| decoded.starts_with(curve.public_key_type().base58check_prefix()))
        .ok_or(WalletSignatureError::Unrecognized { kind: KIND })?;
    let raw = match curve {
        KeyCurve::Ed25519 => PublicKeyEd25519::from_base58_check(key).map(|k| k.as_ref().to_vec()),
        KeyCurve::Secp256k1 => {
            PublicKeySecp256k1::from_base58_check(key).map(|k| k.as_ref().to_vec())
        }
        KeyCurve::P256 => PublicKeyP256::from_base58_check(key).map(|k| k.as_ref().to_vec()),
    }
    .map_err(|_| WalletSignatureError::Unrecognized { kind: KIND })?;

    Ok(DecodedPublicKey { curve, raw })
}

/// Decode an `edsig…`/`spsig1…`/`p2sig…`/`sig…` signature; `BLsig…` is unsupported.
pub fn decode_signature(signature: &str) -> Result<DecodedSignature, WalletSignatureError> {
    const KIND: &str = "signature";
    let decoded = base58check(signature)?;

    if decoded.starts_with(HashType::BlsSignature.base58check_prefix()) {
        return Err(WalletSignatureError::UnsupportedCurve { kind: KIND });
    }
    let (curve, raw) = match Signature::from_base58_check(signature) {
        Ok(Signature::Ed25519(s)) => (Some(KeyCurve::Ed25519), s.as_ref().to_vec()),
        Ok(Signature::Secp256k1(s)) => (Some(KeyCurve::Secp256k1), s.as_ref().to_vec()),
        Ok(Signature::P256(s)) => (Some(KeyCurve::P256), s.as_ref().to_vec()),
        Ok(Signature::Unknown(s)) => (None, s.as_ref().to_vec()),
        // Unreachable: a BLS prefix was refused above.
        Ok(Signature::Bls(_)) => {
            return Err(WalletSignatureError::UnsupportedCurve { kind: KIND });
        }
        // The checksum already passed, so any failure is the prefix or length.
        Err(_) => return Err(WalletSignatureError::Unrecognized { kind: KIND }),
    };

    Ok(DecodedSignature { curve, raw })
}

/// Decode a `tz1…`/`tz2…`/`tz3…` address (23 bytes); `tz4…`/`KT1…` are unsupported.
pub fn decode_address(address: &str) -> Result<DecodedAddress, WalletSignatureError> {
    const KIND: &str = "address";
    let decoded = base58check(address)?;
    let hash_follows = |hash_type: HashType| {
        decoded
            .strip_prefix(hash_type.base58check_prefix())
            .is_some_and(|raw| raw.len() == ADDRESS_HASH_LEN)
    };

    // A tz4 or KT1 address is unsupported only in its exact shape; the same
    // prefix over another length is not an address at all.
    if hash_follows(HashType::ContractTz4Hash) || hash_follows(HashType::ContractKt1Hash) {
        return Err(WalletSignatureError::UnsupportedCurve { kind: KIND });
    }
    let (curve, hash) = match PublicKeyHash::from_b58check(address) {
        Ok(PublicKeyHash::Ed25519(h)) => (KeyCurve::Ed25519, *h),
        Ok(PublicKeyHash::Secp256k1(h)) => (KeyCurve::Secp256k1, *h),
        Ok(PublicKeyHash::P256(h)) => (KeyCurve::P256, *h),
        // Unreachable: an exact tz4 was refused above.
        Ok(PublicKeyHash::Bls(_)) => {
            return Err(WalletSignatureError::UnsupportedCurve { kind: KIND });
        }
        // The checksum already passed, so any failure is the prefix or length.
        Err(_) => return Err(WalletSignatureError::Unrecognized { kind: KIND }),
    };

    Ok(DecodedAddress { curve, hash })
}

/// Read a forged public key (`tag ‖ raw`, exact width). Wallet policy, like
/// [`decode_public_key`]: a BLS tag is `UnsupportedCurve`; any other unknown
/// tag, a short or a long input is `Unrecognized`.
pub fn public_key_from_forged(forged: &[u8]) -> Result<DecodedPublicKey, WalletSignatureError> {
    const KIND: &str = "public key";

    if forged.first() == Some(&BLS_FORGE_TAG) {
        return Err(WalletSignatureError::UnsupportedCurve { kind: KIND });
    }
    let (curve, raw) = match PublicKey::nom_read_exact(forged) {
        Ok(PublicKey::Ed25519(k)) => (KeyCurve::Ed25519, k.as_ref().to_vec()),
        Ok(PublicKey::Secp256k1(k)) => (KeyCurve::Secp256k1, k.as_ref().to_vec()),
        Ok(PublicKey::P256(k)) => (KeyCurve::P256, k.as_ref().to_vec()),
        // Unreachable: the BLS tag was refused above.
        Ok(PublicKey::Bls(_)) => {
            return Err(WalletSignatureError::UnsupportedCurve { kind: KIND });
        }
        Err(_) => return Err(WalletSignatureError::Unrecognized { kind: KIND }),
    };

    Ok(DecodedPublicKey { curve, raw })
}

/// Render a forged `address` (exactly 22 bytes) as base58 text.
///
/// A renderer, not wallet policy: it takes everything the chain can hold, so
/// `tz1`–`tz4` (`00 ‖ tag ‖ hash`) and `KT1` (`01 ‖ hash ‖ 00`) all render.
/// A wrong width, an unknown tag or a non-zero `KT1` padding byte is
/// `Unrecognized { kind: "address" }`.
pub fn address_text_from_forged(forged: &[u8]) -> Result<String, WalletSignatureError> {
    Contract::nom_read_exact(forged)
        .map(|contract| contract.to_b58check())
        .map_err(|_| WalletSignatureError::Unrecognized { kind: "address" })
}

/// Validate address text and return it in canonical form.
///
/// A renderer, not wallet policy: `tz1`–`tz4` and `KT1` text all pass. A bad
/// checksum is `InvalidBase58`; an unknown prefix or a wrong length is
/// `Unrecognized { kind: "address" }`.
pub fn contract_address_text(address: &str) -> Result<String, WalletSignatureError> {
    base58check(address)?;

    Contract::from_b58check(address)
        .map(|contract| contract.to_b58check())
        .map_err(|_| WalletSignatureError::Unrecognized { kind: "address" })
}

/// Render 64 raw signature bytes in the generic `sig…` form.
pub fn generic_signature_text(raw: &[u8; SIGNATURE_LEN]) -> String {
    UnknownSignature::from(*raw).to_base58_check()
}

#[cfg(test)]
mod tests {
    use super::*;

    const TZ1: &str = "tz1RjtZUVeLhADFHDL8UwDZA6vjWWhojpu5w";
    const TZ2: &str = "tz2VGBaXuS6rnaa5hpC92qkgadRJKdEbeGwc";
    const TZ3: &str = "tz3WEJYwJ6pPwVbSL8FrSoAXRmFHHZTuEnMA";
    const TZ4: &str = "tz4FENGt5zkiGaHPm1ya4MgLomgkL1k7Dy7q";
    const KT1: &str = "KT1BuEZtb68c1Q4yjtckcNjGELqWt56Xyesc";
    const KEYS: [&str; 3] = [
        "edpkudAJxe2Bm3MiQGRnFHrmWS7Z44ReKgqE2qKi5ngKgvTNnvQgNM",
        "sppk7cBHLwFkicxGnn1k7zy9sCfjNLQrK52phCCanuDTS6y8dHbnEuE",
        "p2pk659GPvf5dB4NWic27VZU3tuLgEsnsr6Ev213DWniUegV6Kptm6T",
    ];

    /// The 20-byte hash behind an address, read with `bs58` (not the crate
    /// under test) so the expected forged bytes are independent of it.
    fn hash_of(address: &str) -> Vec<u8> {
        bs58::decode(address)
            .with_check(None)
            .into_vec()
            .expect("b58")[3..]
            .to_vec()
    }

    fn unrecognized_address() -> Result<String, WalletSignatureError> {
        Err(WalletSignatureError::Unrecognized { kind: "address" })
    }

    #[test]
    fn forged_address_is_the_implicit_marker_over_forged_implicit() {
        for (text, tag) in [(TZ1, 0u8), (TZ2, 1), (TZ3, 2)] {
            let address = decode_address(text).expect(text);
            let implicit = address.forged_implicit();
            let full = address.forged_address();

            assert_eq!(implicit.len(), 21, "{text}");
            assert_eq!(full.len(), 22, "{text}");
            assert_eq!(implicit.as_slice(), &full[1..], "{text}");
            assert_eq!(full[0], 0, "{text}");
            assert_eq!(
                implicit.as_slice(),
                [&[tag], hash_of(text).as_slice()].concat()
            );
            assert_eq!(address_text_from_forged(&full).as_deref(), Ok(text));
        }
    }

    #[test]
    fn address_text_from_forged_renders_every_chain_address() {
        for (text, tag) in [(TZ1, 0u8), (TZ2, 1), (TZ3, 2), (TZ4, 3)] {
            let forged = [&[0, tag], hash_of(text).as_slice()].concat();

            assert_eq!(address_text_from_forged(&forged).as_deref(), Ok(text));
        }
        let kt1 = [&[1], hash_of(KT1).as_slice(), &[0]].concat();
        assert_eq!(address_text_from_forged(&kt1).as_deref(), Ok(KT1));
    }

    #[test]
    fn address_text_from_forged_refuses_malformed_bytes() {
        let tz1 = [&[0, 0], hash_of(TZ1).as_slice()].concat();
        let mut kt1_padded = [&[1], hash_of(KT1).as_slice(), &[0]].concat();
        kt1_padded[21] = 1;
        let tag_4 = [&[0, 4], hash_of(TZ1).as_slice()].concat();

        assert_eq!(address_text_from_forged(&[]), unrecognized_address());
        assert_eq!(address_text_from_forged(&tz1[..21]), unrecognized_address());
        assert_eq!(
            address_text_from_forged(&[tz1.as_slice(), &[0]].concat()),
            unrecognized_address()
        );
        assert_eq!(address_text_from_forged(&tag_4), unrecognized_address());
        assert_eq!(
            address_text_from_forged(&kt1_padded),
            unrecognized_address()
        );
    }

    #[test]
    fn contract_address_text_passes_chain_addresses_through() {
        for text in [TZ1, TZ2, TZ3, TZ4, KT1] {
            assert_eq!(contract_address_text(text).as_deref(), Ok(text));
        }
        let mut broken = TZ4.to_string();
        broken.pop();
        broken.push('X');
        assert_eq!(
            contract_address_text(&broken),
            Err(WalletSignatureError::InvalidBase58)
        );
        assert_eq!(contract_address_text(KEYS[0]), unrecognized_address());
    }

    #[test]
    fn public_key_from_forged_round_trips_every_curve() {
        for text in KEYS {
            let key = decode_public_key(text).expect(text);
            let forged = key.forged();

            assert_eq!(forged[0], key.curve.forge_tag(), "{text}");
            assert_eq!(&forged[1..], key.raw.as_slice(), "{text}");
            let read = public_key_from_forged(&forged).expect(text);
            let rendered = bs58::encode([read.curve.public_key_prefix(), &read.raw].concat())
                .with_check()
                .into_string();
            assert_eq!(rendered, text);
            assert_eq!(read.to_base58_check(), text);
            assert_eq!(read, key);
            assert_eq!(
                public_key_from_forged(&forged[..forged.len() - 1]),
                Err(WalletSignatureError::Unrecognized { kind: "public key" })
            );
        }
    }

    #[test]
    fn public_key_from_forged_refuses_a_bls_key() {
        let unsupported = Err(WalletSignatureError::UnsupportedCurve { kind: "public key" });

        assert_eq!(
            public_key_from_forged(&[[3].as_slice(), &[0; 48]].concat()),
            unsupported
        );
        assert_eq!(public_key_from_forged(&[3]), unsupported);
        assert_eq!(
            public_key_from_forged(&[[4].as_slice(), &[0; 32]].concat()),
            Err(WalletSignatureError::Unrecognized { kind: "public key" })
        );
    }

    #[test]
    fn generic_signature_text_is_the_generic_form() {
        let raw = [7; SIGNATURE_LEN];
        let text = generic_signature_text(&raw);

        assert!(text.starts_with("sig"), "{text}");
        assert_eq!(
            decode_signature(&text),
            Ok(DecodedSignature {
                curve: None,
                raw: raw.to_vec()
            })
        );
    }
}
