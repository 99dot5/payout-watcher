//! Public keys, signatures and addresses as they appear in an operation or
//! a contract's storage, normalised to their base58check text.
//!
//! A node renders a `key` or a `signature` the way it was submitted: the
//! readable `{"string": "sppk…"}` form, or the optimised `{"bytes": …}` form
//! some wallets and SDKs send. Both are turned into the one base58check text
//! here, so a signer set read from storage compares equal to the keys in an
//! operation whichever form either used. Every value is decoded and rendered
//! by `tezos_wallet_signature`, which goes through the pinned crypto crate:
//! keys and signatures under its wallet rule (no BLS), addresses under its
//! chain rule (`tz1`–`tz4` and `KT1`, the shapes a treasury or a sweep
//! destination can take).

use crate::micheline::{MichelineError, as_bytes, as_string};
use serde_json::Value;
use tezos_wallet_signature::curve::{KeyCurve, SIGNATURE_LEN};
use tezos_wallet_signature::{
    address_text_from_forged, contract_address_text, decode_public_key, decode_signature,
    generic_signature_text, public_key_from_forged,
};

/// A `key` node as `edpk…` / `sppk…` / `p2pk…`. A string is checked to
/// decode under its own prefix; bytes are the forged tag and the raw key.
pub fn key_text(node: &Value) -> Result<String, MichelineError> {
    if let Ok(text) = as_string(node) {
        decode_public_key(text)
            .map_err(|e| MichelineError(format!("'{text}' is not a public key: {e}")))?;
        return Ok(text.to_string());
    }
    let bytes = as_bytes(node)?;
    let &tag = bytes
        .first()
        .ok_or_else(|| MichelineError("an empty key".to_string()))?;
    let curve = KeyCurve::from_forge_tag(tag)
        .ok_or_else(|| MichelineError(format!("key tag 0x{tag:02x} is not a supported curve")))?;
    let decoded = public_key_from_forged(&bytes).map_err(|_| {
        MichelineError(format!(
            "a {curve} key is {} bytes, found {}",
            curve.public_key_len(),
            bytes.len() - 1
        ))
    })?;

    Ok(decoded.to_base58_check())
}

/// An `address` node as `tz1…`/`tz2…`/`tz3…`/`tz4…`/`KT1…` text. A string
/// is checked to decode under one of those five prefixes with a 20-byte
/// hash; bytes are the 22-byte forged form, `00 ‖ curve tag ‖ hash` for an
/// implicit account and `01 ‖ hash ‖ 00` for an originated one.
pub fn address_text(node: &Value) -> Result<String, MichelineError> {
    if let Ok(text) = as_string(node) {
        return contract_address_text(text)
            .map_err(|e| MichelineError(format!("'{text}' is not an address: {e}")));
    }
    let bytes = as_bytes(node)?;
    if bytes.len() != 22 {
        return Err(MichelineError(format!(
            "a forged address is 22 bytes, found {}",
            bytes.len()
        )));
    }

    address_text_from_forged(&bytes).map_err(|_| {
        MichelineError(format!(
            "forged address {} is neither an implicit account nor an originated contract \
             with the default entrypoint",
            hex::encode(&bytes)
        ))
    })
}

/// A `signature` node as base58check text. A string is checked to decode;
/// 64 raw bytes carry no curve, so they become the generic `sig…` form, which
/// verifies against a key of any supported curve.
pub fn signature_text(node: &Value) -> Result<String, MichelineError> {
    if let Ok(text) = as_string(node) {
        decode_signature(text)
            .map_err(|e| MichelineError(format!("'{text}' is not a signature: {e}")))?;
        return Ok(text.to_string());
    }
    let raw = as_bytes(node)?;
    let raw: &[u8; SIGNATURE_LEN] = raw.as_slice().try_into().map_err(|_| {
        MichelineError(format!(
            "a signature is {SIGNATURE_LEN} bytes, found {}",
            raw.len()
        ))
    })?;

    Ok(generic_signature_text(raw))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const EDPK: &str = "edpkvHGNFNUxqbtfVujAwR3tRtbGK5UP5BMAY8PDvd6CfpAu3TpRUn";
    const SPPK: &str = "sppk7bWq3wGj9AuTowUc7N2dpRhMCWtw6pmDFcLrSTLyA1mnBJ9hL5T";

    const TZ4: &str = "tz4FMuvpW4vRVaER72VgCdonjM1Pqgk2QVXR";
    const KT1: &str = "KT1BuEZtb68c1Q4yjtckcNjGELqWt56Xyesc";

    fn forged(key: &str) -> String {
        hex::encode(decode_public_key(key).unwrap().forged())
    }

    /// The 20-byte hash behind an address, read with `bs58` so the forged
    /// fixtures do not come from the code under test.
    fn hash_of(address: &str) -> Vec<u8> {
        bs58::decode(address).with_check(None).into_vec().unwrap()[3..].to_vec()
    }

    fn forged_address(lead: &[u8], hash: &[u8], tail: &[u8]) -> Value {
        json!({ "bytes": hex::encode([lead, hash, tail].concat()) })
    }

    #[test]
    fn the_readable_and_optimised_key_forms_normalise_to_the_same_text() {
        for key in [EDPK, SPPK] {
            assert_eq!(key_text(&json!({ "string": key })).unwrap(), key);
            assert_eq!(key_text(&json!({ "bytes": forged(key) })).unwrap(), key);
        }
    }

    #[test]
    fn a_key_of_the_wrong_length_or_tag_is_refused() {
        let mut short = forged(SPPK);
        short.truncate(short.len() - 2);

        assert!(key_text(&json!({ "bytes": short })).is_err());
        assert!(key_text(&json!({ "bytes": format!("03{}", &forged(SPPK)[2..]) })).is_err());
        assert!(key_text(&json!({ "string": "KT1BuEZtb68c1Q4yjtckcNjGELqWt56Xyesc" })).is_err());
    }

    /// Every address shape a vault can hold or a sweep can name: the
    /// readable and the forged forms normalise to one text, and a forged
    /// originated address with an entrypoint, or an unknown tag, is refused.
    #[test]
    fn the_readable_and_forged_address_forms_normalise_to_the_same_text() {
        let cases = [
            ("tz1UyQDepgtUBnWjyzzonqeDwaiWoQzRKSP5", 0x00u8),
            ("tz2BFTyPeYRzxd5aiBchbXN3WCZhx7BqbMBq", 0x01),
            ("tz3WXYtyDUNL91qfiCJtVUX746QpNv5i5ve5", 0x02),
            ("tz4FMuvpW4vRVaER72VgCdonjM1Pqgk2QVXR", 0x03),
        ];

        for (text, tag) in cases {
            let decoded = bs58::decode(text).with_check(None).into_vec().unwrap();
            let hash = &decoded[3..];
            let mut forged = vec![0x00, tag];

            forged.extend_from_slice(hash);

            assert_eq!(address_text(&json!({ "string": text })).unwrap(), text);
            assert_eq!(
                address_text(&json!({ "bytes": hex::encode(&forged) })).unwrap(),
                text
            );
        }

        let decoded = bs58::decode(KT1).with_check(None).into_vec().unwrap();
        let mut forged = vec![0x01];

        forged.extend_from_slice(&decoded[3..]);
        forged.push(0x00);

        assert_eq!(address_text(&json!({ "string": KT1 })).unwrap(), KT1);
        assert_eq!(
            address_text(&json!({ "bytes": hex::encode(&forged) })).unwrap(),
            KT1
        );

        forged[21] = 0x01;

        assert!(address_text(&json!({ "bytes": hex::encode(&forged) })).is_err());
        assert!(address_text(&json!({ "bytes": "0004".to_string() + &"11".repeat(20) })).is_err());
        assert!(address_text(&json!({ "string": EDPK })).is_err());
        assert!(address_text(&json!({ "string": "not an address" })).is_err());
    }

    /// A BLS (`tz4`) treasury or sweep destination is a chain address, not a
    /// wallet one, so both of its forms pass.
    #[test]
    fn a_tz4_address_passes_in_both_forms() {
        assert_eq!(address_text(&json!({ "string": TZ4 })).unwrap(), TZ4);
        assert_eq!(
            address_text(&forged_address(&[0x00, 0x03], &hash_of(TZ4), &[])).unwrap(),
            TZ4
        );
    }

    /// A forged address is exactly 22 bytes with a known kind, a known tag
    /// and, for `KT1`, a zero padding byte; anything else is refused.
    #[test]
    fn a_forged_address_of_the_wrong_width_tag_or_padding_is_refused() {
        let tz1 = hash_of("tz1UyQDepgtUBnWjyzzonqeDwaiWoQzRKSP5");
        let kt1 = hash_of(KT1);

        for refused in [
            forged_address(&[0x00, 0x00], &tz1[..19], &[]),
            forged_address(&[0x00, 0x00], &tz1, &[0x00]),
            forged_address(&[0x01], &kt1[..19], &[0x00]),
            forged_address(&[0x01], &kt1, &[0x00, 0x00]),
            forged_address(&[0x00, 0x04], &tz1, &[]),
            forged_address(&[0x01], &kt1, &[0x01]),
            forged_address(&[0x01], &kt1, &[0xff]),
            forged_address(&[0x02], &kt1, &[0x00]),
        ] {
            assert!(address_text(&refused).is_err(), "{refused}");
        }
        assert_eq!(
            address_text(&forged_address(&[0x01], &kt1, &[0x00])).unwrap(),
            KT1
        );
    }

    #[test]
    fn a_bls_key_is_refused_in_both_forms() {
        let bls = format!("03{}", "11".repeat(48));

        assert!(
            key_text(&json!({ "bytes": bls }))
                .unwrap_err()
                .0
                .contains("0x03 is not a supported curve")
        );
        assert!(
            key_text(&json!({
                "string": "BLpk1v6UU2PNtycJRJkn5X7qVgVFNGbgTDcWVLPy2fx2upHFzDkcvQzzV8fT8TzPHXHfDQPbu73i"
            }))
            .unwrap_err()
            .0
            .contains("unsupported public key")
        );
    }

    #[test]
    fn raw_signature_bytes_become_the_generic_form() {
        let text = signature_text(&json!({ "bytes": "11".repeat(64) })).unwrap();

        assert!(text.starts_with("sig"), "{text}");
        assert_eq!(decode_signature(&text).unwrap().curve, None);
        assert!(signature_text(&json!({ "bytes": "11".repeat(63) })).is_err());
    }
}
