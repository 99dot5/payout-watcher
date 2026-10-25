//! Verification of Tezos wallet signatures (Ed25519, secp256k1, P-256) over
//! `blake2b-256(payload)` — the rule `octez-client sign bytes` and Michelson
//! `CHECK_SIGNATURE` apply — plus the address binding and the wallet sign-in
//! message builder.
//!
//! Ported from `tools/operator-cli/src/possession.rs` together with the
//! `encoding` helpers it imports; BLS is deliberately absent (a `BLpk` key,
//! `BLsig` signature or `tz4` address is [`WalletSignatureError::UnsupportedCurve`]).
//!
//! Every base58 value is decoded through the pinned `tezos_crypto_rs`: its
//! checksum decoder, its `HashType` prefixes and its typed decoders, which
//! compare the prefix and the payload length (ADR 0036). The prefix literals
//! in [`curve`] are kept for `const` callers and pinned to the crate's by a test.
//!
//! The crate holds two rules, and each function belongs to exactly one:
//!
//! - **Wallet-signable policy** — `decode_*` and its forged-key twin
//!   [`public_key_from_forged`]: only what a wallet can sign with,
//!   Ed25519, secp256k1 and P-256 keys and `tz1`–`tz3` addresses; BLS and
//!   `KT1` are refused.
//! - **Chain-representable rendering** — [`address_text_from_forged`] and
//!   [`contract_address_text`]: everything the chain can hold as an address,
//!   `tz1`–`tz4` and `KT1`, rendered as text without a wallet judgement.

pub mod curve;
pub mod decode;
pub mod sign_in;
pub mod verify;

pub use curve::KeyCurve;
pub use decode::{
    DecodedAddress, DecodedPublicKey, DecodedSignature, address_text_from_forged,
    contract_address_text, decode_address, decode_public_key, decode_signature,
    generic_signature_text, public_key_from_forged,
};
pub use verify::{address_of, check_key_matches_address, verify_over};

use thiserror::Error;

/// Why a key, signature, address or `(key, signature, payload)` triple was refused.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum WalletSignatureError {
    /// Not base58check at all (bad alphabet or checksum).
    #[error("not a base58check value")]
    InvalidBase58,
    /// base58check, but no known prefix with the exact payload length.
    #[error("unrecognised {kind} encoding")]
    Unrecognized { kind: &'static str },
    /// A BLS (`BLpk`/`BLsig`/`tz4`) value, or an originated `KT1` address.
    #[error("unsupported {kind}: only Ed25519, secp256k1 and P-256 implicit accounts")]
    UnsupportedCurve { kind: &'static str },
    /// A curve-specific signature on another curve's key (`spsig1…` with an `edpk…`).
    #[error("signature curve {signature} does not match key curve {key}")]
    SignatureCurveMismatch { key: KeyCurve, signature: KeyCurve },
    /// The key's curve or `blake2b-160` hash is not the address's.
    #[error("public key does not hash to the address")]
    KeyAddressMismatch,
    /// Decodes and the curves agree, but the signature does not verify.
    #[error("signature does not verify over the payload")]
    DoesNotVerify,
    /// The crypto backend could not read the key or signature bytes.
    #[error("cannot verify: {reason}")]
    Malformed { reason: String },
}
