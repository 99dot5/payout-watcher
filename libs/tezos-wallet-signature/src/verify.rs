//! Signature verification and the key → address binding.

use crate::WalletSignatureError;
use crate::curve::{ADDRESS_HASH_LEN, KeyCurve};
use crate::decode::{DecodedAddress, decode_address, decode_public_key, decode_signature};
use tezos_crypto_rs::{
    PublicKeySignatureVerifier, blake2b,
    hash::{
        Ed25519Signature, P256Signature, PublicKeyEd25519, PublicKeyP256, PublicKeySecp256k1,
        Secp256k1Signature,
    },
};

fn malformed(reason: impl ToString) -> WalletSignatureError {
    WalletSignatureError::Malformed {
        reason: reason.to_string(),
    }
}

/// Verify that `signature` is `public_key`'s signature over
/// `blake2b-256(payload)`. A curve-specific signature on another curve's key
/// is refused before any arithmetic; the generic `sig…` pairs with any key.
pub fn verify_over(
    public_key: &str,
    signature: &str,
    payload: &[u8],
) -> Result<(), WalletSignatureError> {
    let key = decode_public_key(public_key)?;
    let sig = decode_signature(signature)?;
    let key_curve = key.curve;

    if let Some(signature_curve) = sig.curve
        && signature_curve != key.curve
    {
        return Err(WalletSignatureError::SignatureCurveMismatch {
            key: key.curve,
            signature: signature_curve,
        });
    }

    // The crate's verifiers hash `payload` with blake2b-256 themselves.
    let sig = sig.raw.as_slice();
    let key = key.raw.as_slice();
    let verified = match key_curve {
        // `verify_strict` reports a failed verification as an error, not as
        // `Ok(false)`, so both arms of the result mean the same thing here.
        KeyCurve::Ed25519 => PublicKeyEd25519::try_from(key)
            .map_err(malformed)?
            .verify_signature(
                &Ed25519Signature::try_from(sig).map_err(malformed)?,
                payload,
            )
            .unwrap_or(false),
        KeyCurve::Secp256k1 => PublicKeySecp256k1::try_from(key)
            .map_err(malformed)?
            .verify_signature(
                &Secp256k1Signature::try_from(sig).map_err(malformed)?,
                payload,
            )
            .map_err(malformed)?,
        KeyCurve::P256 => PublicKeyP256::try_from(key)
            .map_err(malformed)?
            .verify_signature(&P256Signature::try_from(sig).map_err(malformed)?, payload)
            .map_err(malformed)?,
    };

    if verified {
        Ok(())
    } else {
        Err(WalletSignatureError::DoesNotVerify)
    }
}

fn key_hash(raw: &[u8]) -> [u8; ADDRESS_HASH_LEN] {
    blake2b::digest_160(raw)
}

/// The implicit-account address (`tz1`/`tz2`/`tz3`) of `public_key`:
/// `blake2b-160` of the raw key payload under the curve's address prefix.
pub fn address_of(public_key: &str) -> Result<String, WalletSignatureError> {
    let key = decode_public_key(public_key)?;
    let address = DecodedAddress {
        curve: key.curve,
        hash: key_hash(&key.raw),
    };

    Ok(address.public_key_hash().to_b58check())
}

/// Refuse a key that is not `address`'s: both must decode, and the key's curve
/// and `blake2b-160` hash must equal the address's, else `KeyAddressMismatch`.
pub fn check_key_matches_address(
    public_key: &str,
    address: &str,
) -> Result<(), WalletSignatureError> {
    let key = decode_public_key(public_key)?;
    let address = decode_address(address)?;

    if key.curve == address.curve && key_hash(&key.raw) == address.hash {
        Ok(())
    } else {
        Err(WalletSignatureError::KeyAddressMismatch)
    }
}
