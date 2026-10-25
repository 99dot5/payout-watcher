//! Signing a fast-payout payload with a secp256k1 key — the curve ADR 0027
//! §4.6 chooses for the two online signers (a cloud KMS can hold it, and an
//! EVM can verify it) — in the form the vault's `CHECK_SIGNATURE` accepts.
//!
//! The rule is the one `octez-client sign bytes` applies to every non-BLS
//! curve: the signature is an ECDSA signature over `blake2b-256(payload)`,
//! encoded as the 64 raw bytes `r || s` with the low-`s` normalisation and
//! wrapped as `spsig1…` (base58check, the curve's own prefix).
//!
//! The crate separates the two halves a KMS-backed signer splits: the
//! [`PayoutSigner`] trait signs a 32-byte digest and returns `r || s`, which is
//! exactly what a KMS `Sign` with `ECDSA_SHA_256` over a pre-hashed digest
//! does once its DER output is unpacked (the algorithm name fixes the digest
//! length, not what hashed it, so a blake2b digest is signed as given); the
//! crate owns the hashing before and the encoding and self-check after. A
//! [`LocalSecp256k1Signer`] holds the exponent in memory for tests, the
//! sandbox and the golden pin: its RFC 6979 nonce makes it reproduce, byte
//! for byte, the signatures pytezos wrote into the vectors.

use crate::payload::{ChainId, VaultAddress, fast_payout_payload};
use core::future::Future;
use tezos_crypto_rs::blake2b;
use tezos_crypto_rs::hash::{PublicKeySecp256k1, Secp256k1Signature};
use thiserror::Error;

/// Why a signing attempt was refused or failed.
#[derive(Debug, Error)]
pub enum SignError {
    /// The backend (a KMS call, a hardware signer) failed; retryable at the
    /// caller's discretion.
    #[error("the signer backend failed: {reason}")]
    Backend { reason: String },
    /// The backend answered with bytes that are not a secp256k1 signature
    /// over the digest under the signer's own public key. Never retryable
    /// blindly: a signer disagreeing with its own key is a key-material or
    /// configuration fault.
    #[error(
        "the signer produced a signature that does not verify under its own key {public_key}: {reason}"
    )]
    SelfCheckFailed { public_key: String, reason: String },
    /// A secret exponent that is not a valid secp256k1 scalar.
    #[error("the secret exponent is not a valid secp256k1 scalar")]
    InvalidSecretExponent,
}

/// A secp256k1 signer: anything that can sign a 32-byte digest under a key
/// whose `sppk…` it knows. Static dispatch, `impl Future` rather than `async
/// fn` in the trait, to match the workspace convention.
pub trait PayoutSigner {
    /// The signer's public key, `sppk…`.
    fn public_key(&self) -> &str;

    /// ECDSA-sign `digest` (already `blake2b-256(payload)`), returning the 64
    /// raw bytes `r || s`. Implementations need not normalise `s`; the crate
    /// does, so a high-`s` answer from a backend is not a failure.
    fn sign_digest(&self, digest: &[u8; 32]) -> impl Future<Output = Result<[u8; 64], SignError>>;
}

/// A fast-payout signature in the form the vault takes.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct FastPayoutSignature {
    /// The signer's `sppk…` — the key of the `signatures` map entry.
    pub public_key: String,
    /// The `spsig1…` over the payload.
    pub signature: String,
    /// The payload the signature is over, kept beside it so a submitter can
    /// carry both without re-deriving. Hex on the wire, so it reads in a
    /// workflow history.
    #[cfg_attr(feature = "serde", serde(with = "serde_hex"))]
    pub payload: Vec<u8>,
}

/// `Vec<u8>` as lowercase hex, for the `serde` feature.
#[cfg(feature = "serde")]
pub(crate) mod serde_hex {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(deserializer)?;

        hex::decode(text).map_err(serde::de::Error::custom)
    }
}

/// Sign the fast payout of `amount_mutez` to `session_id` on `vault` on chain
/// `chain_id` with `signer`, and check the result under the signer's own key
/// before returning it.
pub async fn sign_fast_payout<S: PayoutSigner>(
    signer: &S,
    chain_id: &ChainId,
    vault: &VaultAddress,
    session_id: &[u8; 16],
    amount_mutez: u64,
) -> Result<FastPayoutSignature, SignError> {
    let payload = fast_payout_payload(chain_id, vault, session_id, amount_mutez);
    let signature = sign_payload(signer, &payload).await?;

    Ok(FastPayoutSignature {
        public_key: signer.public_key().to_string(),
        signature,
        payload,
    })
}

/// Sign any PACK `payload` the vault verifies with `CHECK_SIGNATURE` — a fast
/// payout, a deposit authorisation — the way `octez-client sign bytes` does:
/// ECDSA over `blake2b-256(payload)`, low-S, encoded `spsig1…`, and checked
/// under the signer's own key before it is returned. The one hashing and
/// encoding path for every payload domain; a backend only ever signs a digest.
pub async fn sign_payload<S: PayoutSigner>(
    signer: &S,
    payload: &[u8],
) -> Result<String, SignError> {
    let digest = digest(payload);
    let raw = signer.sign_digest(&digest).await?;
    let signature = encode_signature(&normalise_low_s(raw));

    // The vault counts only signatures that verify (a fast payout lands as a
    // silent `Under threshold`, a deposit as `Invalid deposit authorisation`);
    // a signer that disagrees with its own key is refused here instead.
    tezos_wallet_signature::verify_over(signer.public_key(), &signature, payload).map_err(|e| {
        SignError::SelfCheckFailed {
            public_key: signer.public_key().to_string(),
            reason: e.to_string(),
        }
    })?;

    Ok(signature)
}

/// The byte Tezos prefixes to the forged bytes of a manager operation before
/// hashing them for the signature (`Signature.Generic_operation` watermark).
pub const OPERATION_WATERMARK: u8 = 0x03;

/// A signature over a forged L1 operation, in both forms a submitter needs:
/// the 64 raw bytes appended to the forged bytes for `/injection/operation`,
/// and the `spsig1…` an RPC or a log names it by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationSignature {
    pub raw: [u8; 64],
    pub encoded: String,
}

/// Sign the forged bytes of an L1 manager operation with the same key that
/// signs fast payouts, the way `octez-client` signs one: ECDSA over
/// `blake2b-256(0x03 || forged)`, low-S, self-checked under the signer's own
/// key before it is returned. This is what lets the sequencer's payout key
/// also carry the `fast_payout` operation to L1 and pay its fee (ADR 0028
/// §4.2 step 5): the hashing and encoding stay here, the backend signs a
/// digest and nothing else.
pub async fn sign_l1_operation<S: PayoutSigner>(
    signer: &S,
    forged: &[u8],
) -> Result<OperationSignature, SignError> {
    let mut watermarked = Vec::with_capacity(1 + forged.len());

    watermarked.push(OPERATION_WATERMARK);
    watermarked.extend_from_slice(forged);

    let digest = digest(&watermarked);
    let raw = normalise_low_s(signer.sign_digest(&digest).await?);
    let encoded = encode_signature(&raw);

    tezos_wallet_signature::verify_over(signer.public_key(), &encoded, &watermarked).map_err(
        |e| SignError::SelfCheckFailed {
            public_key: signer.public_key().to_string(),
            reason: e.to_string(),
        },
    )?;

    Ok(OperationSignature { raw, encoded })
}

/// `blake2b-256(payload)`: the message every Ed25519/secp256k1/P-256 Tezos
/// signature is over.
pub fn digest(payload: &[u8]) -> [u8; 32] {
    blake2b::digest_256(payload)
}

/// Re-serialise `r || s` with `s` in the low half of the group order, the
/// form Tezos (and every strict verifier) accepts.
fn normalise_low_s(raw: [u8; 64]) -> [u8; 64] {
    match libsecp256k1::Signature::parse_overflowing_slice(&raw) {
        Ok(mut signature) => {
            signature.normalize_s();

            signature.serialize()
        }
        // Not parseable as a signature at all: hand the bytes on unchanged so
        // the self-check names the fault.
        Err(_) => raw,
    }
}

/// `spsig1…`: the curve's own base58check prefix over the 64 raw bytes.
fn encode_signature(raw: &[u8; 64]) -> String {
    Secp256k1Signature::from(*raw).to_base58_check()
}

/// `sppk…`: the curve's own base58check prefix over the 33-byte compressed
/// point.
pub fn encode_public_key(compressed: &[u8; 33]) -> String {
    PublicKeySecp256k1::from(*compressed).to_base58_check()
}

/// The `SubjectPublicKeyInfo` header a key service hands out for a secp256k1
/// public key (AWS KMS `GetPublicKey` on an `ECC_SECG_P256K1` key, `openssl
/// ec -pubout -outform DER`): `SEQUENCE { SEQUENCE { OID ecPublicKey, OID
/// secp256k1 }, BIT STRING }`, ahead of the 65-byte uncompressed point
/// `0x04 ‖ X ‖ Y`.
pub const SECP256K1_SPKI_PREFIX: [u8; 23] = [
    0x30, 0x56, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b,
    0x81, 0x04, 0x00, 0x0a, 0x03, 0x42, 0x00,
];

/// Why a `SubjectPublicKeyInfo` is not a secp256k1 public key the vault can
/// hold.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SpkiError {
    /// Another curve's header (P-256 is the usual one), or not DER at all.
    #[error(
        "expected the ecPublicKey/secp256k1 header, got {byte_count} bytes starting {leading_hex}"
    )]
    NotSecp256k1 {
        byte_count: usize,
        leading_hex: String,
    },
    /// The right header over something other than a 65-byte point.
    #[error("expected a 65-byte uncompressed point, got {byte_count} bytes")]
    WrongPointLength { byte_count: usize },
    /// A point in some form other than the uncompressed `0x04 ‖ X ‖ Y`.
    #[error("expected an uncompressed point (0x04), got 0x{form:02x}")]
    NotUncompressed { form: u8 },
    /// Sixty-five bytes that are not a point of the curve.
    #[error("the point is not on secp256k1")]
    NotOnCurve,
}

/// The 33-byte compressed point of a secp256k1 `SubjectPublicKeyInfo` — the
/// bytes behind the `sppk…` the vault's `payout_signers` set holds. One
/// decoder for both readers of a key service's public key: the KMS signer at
/// boot and the operator CLI's `key from-spki` before a vault is originated.
/// Refuses any other curve's header, a point of the wrong length or form, and
/// a point that is not on the curve.
pub fn compress_secp256k1_spki(der: &[u8]) -> Result<[u8; 33], SpkiError> {
    let Some(point) = der.strip_prefix(&SECP256K1_SPKI_PREFIX) else {
        return Err(SpkiError::NotSecp256k1 {
            byte_count: der.len(),
            leading_hex: hex::encode(&der[..der.len().min(8)]),
        });
    };
    let point: &[u8; 65] = point.try_into().map_err(|_| SpkiError::WrongPointLength {
        byte_count: point.len(),
    })?;
    if point[0] != 0x04 {
        return Err(SpkiError::NotUncompressed { form: point[0] });
    }
    let public = libsecp256k1::PublicKey::parse(point).map_err(|_| SpkiError::NotOnCurve)?;

    Ok(public.serialize_compressed())
}

/// A secp256k1 signer holding its secret exponent in memory: tests, the
/// sandbox, and the golden pin. Never a production signer: a production key
/// lives in a key service or hardware signer and never leaves it.
#[derive(Clone)]
pub struct LocalSecp256k1Signer {
    secret: libsecp256k1::SecretKey,
    public_key: String,
}

impl core::fmt::Debug for LocalSecp256k1Signer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Never the exponent.
        f.debug_struct("LocalSecp256k1Signer")
            .field("public_key", &self.public_key)
            .finish_non_exhaustive()
    }
}

impl LocalSecp256k1Signer {
    /// Build from a 32-byte secret exponent (big-endian scalar).
    pub fn from_secret_exponent(exponent: &[u8; 32]) -> Result<Self, SignError> {
        let secret = libsecp256k1::SecretKey::parse(exponent)
            .map_err(|_| SignError::InvalidSecretExponent)?;
        let public = libsecp256k1::PublicKey::from_secret_key(&secret);

        Ok(Self {
            secret,
            public_key: encode_public_key(&public.serialize_compressed()),
        })
    }
}

impl PayoutSigner for LocalSecp256k1Signer {
    fn public_key(&self) -> &str {
        &self.public_key
    }

    async fn sign_digest(&self, digest: &[u8; 32]) -> Result<[u8; 64], SignError> {
        let message = libsecp256k1::Message::parse(digest);
        // RFC 6979 deterministic nonce, low-S normalised by the library.
        let (signature, _recovery_id) = libsecp256k1::sign(&message, &self.secret);

        Ok(signature.serialize())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHAIN_ID: &str = "NetXdQprcVkpaWU";
    const KT1: &str = "KT1BuEZtb68c1Q4yjtckcNjGELqWt56Xyesc";

    fn signer() -> LocalSecp256k1Signer {
        LocalSecp256k1Signer::from_secret_exponent(&[7u8; 32]).expect("valid exponent")
    }

    #[tokio::test]
    async fn a_local_signer_signs_a_payout_its_own_key_verifies() {
        let chain = ChainId::parse(CHAIN_ID).expect("chain id");
        let vault = VaultAddress::parse(KT1).expect("kt1");
        let signed = sign_fast_payout(&signer(), &chain, &vault, &[0x11u8; 16], 1_000_000)
            .await
            .expect("signed");

        assert!(signed.public_key.starts_with("sppk"));
        assert!(signed.signature.starts_with("spsig1"));
        assert_eq!(
            signed.payload,
            fast_payout_payload(&chain, &vault, &[0x11u8; 16], 1_000_000)
        );
        crate::verify_fast_payout_signature(&signed.public_key, &signed.signature, &signed.payload)
            .expect("verifies");
        // Over any other amount it does not.
        let other = fast_payout_payload(&chain, &vault, &[0x11u8; 16], 1_000_001);

        assert!(
            crate::verify_fast_payout_signature(&signed.public_key, &signed.signature, &other)
                .is_err()
        );
    }

    /// An L1 operation is signed over `blake2b(0x03 || forged)`, the rule
    /// octez applies to manager operations: the signature verifies over the
    /// watermarked bytes and not over the bare ones, so it can never be
    /// replayed as a fast-payout signature or vice versa.
    #[tokio::test]
    async fn an_l1_operation_is_signed_under_the_operation_watermark() {
        let forged = [0x8f, 0xcf, 0x23, 0x36, 0x6c, 0x01, 0x02];
        let signed = sign_l1_operation(&signer(), &forged).await.expect("signed");
        let mut watermarked = vec![OPERATION_WATERMARK];

        watermarked.extend_from_slice(&forged);

        assert!(signed.encoded.starts_with("spsig1"));
        tezos_wallet_signature::verify_over(signer().public_key(), &signed.encoded, &watermarked)
            .expect("verifies over the watermarked bytes");
        assert!(
            tezos_wallet_signature::verify_over(signer().public_key(), &signed.encoded, &forged)
                .is_err(),
            "not over the bare bytes"
        );
        assert_eq!(
            signed,
            sign_l1_operation(&signer(), &forged).await.expect("signed"),
            "deterministic"
        );

        let decoded = bs58::decode(&signed.encoded)
            .with_check(None)
            .into_vec()
            .expect("base58check");

        assert_eq!(&decoded[decoded.len() - 64..], &signed.raw[..]);
    }

    #[tokio::test]
    async fn signing_is_deterministic() {
        let chain = ChainId::parse(CHAIN_ID).expect("chain id");
        let vault = VaultAddress::parse(KT1).expect("kt1");
        let a = sign_fast_payout(&signer(), &chain, &vault, &[0x11u8; 16], 5)
            .await
            .expect("signed");
        let b = sign_fast_payout(&signer(), &chain, &vault, &[0x11u8; 16], 5)
            .await
            .expect("signed");

        assert_eq!(a, b);
    }

    /// A backend that returns a signature from another key: refused by the
    /// self-check rather than handed on as a silent `Under threshold`.
    struct WrongKeyBackend {
        claimed: LocalSecp256k1Signer,
        actual: LocalSecp256k1Signer,
    }

    impl PayoutSigner for WrongKeyBackend {
        fn public_key(&self) -> &str {
            self.claimed.public_key()
        }

        async fn sign_digest(&self, digest: &[u8; 32]) -> Result<[u8; 64], SignError> {
            self.actual.sign_digest(digest).await
        }
    }

    #[tokio::test]
    async fn a_backend_signing_with_another_key_fails_the_self_check() {
        let chain = ChainId::parse(CHAIN_ID).expect("chain id");
        let vault = VaultAddress::parse(KT1).expect("kt1");
        let backend = WrongKeyBackend {
            claimed: signer(),
            actual: LocalSecp256k1Signer::from_secret_exponent(&[9u8; 32]).expect("valid"),
        };
        let err = sign_fast_payout(&backend, &chain, &vault, &[0x11u8; 16], 5)
            .await
            .expect_err("self-check");

        assert!(matches!(err, SignError::SelfCheckFailed { .. }), "{err}");
    }

    #[test]
    fn a_zero_exponent_is_refused() {
        assert!(matches!(
            LocalSecp256k1Signer::from_secret_exponent(&[0u8; 32]),
            Err(SignError::InvalidSecretExponent)
        ));
    }

    #[test]
    fn debug_never_prints_the_exponent() {
        let text = format!("{:?}", signer());

        assert!(text.contains("sppk"));
        assert!(!text.contains("secret"));
    }
}

#[cfg(test)]
mod spki_tests {
    use super::*;

    /// The generator point: the public key of the exponent `…01`.
    const GENERATOR_X: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    const GENERATOR_Y: &str = "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";

    fn generator_point() -> [u8; 65] {
        let mut point = [0u8; 65];
        point[0] = 0x04;
        point[1..33].copy_from_slice(&hex::decode(GENERATOR_X).unwrap());
        point[33..].copy_from_slice(&hex::decode(GENERATOR_Y).unwrap());

        point
    }

    fn spki(point: &[u8; 65]) -> Vec<u8> {
        let mut der = SECP256K1_SPKI_PREFIX.to_vec();
        der.extend_from_slice(point);

        der
    }

    #[test]
    fn the_spki_a_key_service_returns_compresses_to_the_local_signers_sppk() {
        let compressed =
            compress_secp256k1_spki(&spki(&generator_point())).expect("a secp256k1 SPKI");

        let mut exponent = [0u8; 32];
        exponent[31] = 1;
        let local = LocalSecp256k1Signer::from_secret_exponent(&exponent).expect("signer");
        assert_eq!(encode_public_key(&compressed), local.public_key());
        // Y is even, so the compressed form leads with 0x02; both constants are
        // independent of the code under test.
        assert_eq!(
            hex::encode(compressed),
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        );
        assert_eq!(
            encode_public_key(&compressed),
            "sppk7aEFdrScsCDxdaQ7Ev1JxpWZESrEK6UsWRhr79JfGKkPYGTsudN"
        );
    }

    #[test]
    fn another_curves_header_is_refused() {
        // prime256v1's OID (1.2.840.10045.3.1.7) in place of secp256k1's.
        let mut der = vec![
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,
            0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
        ];
        der.extend_from_slice(&generator_point());

        let err = compress_secp256k1_spki(&der).expect_err("P-256 header");

        assert!(
            matches!(err, SpkiError::NotSecp256k1 { byte_count: 91, .. }),
            "{err}"
        );
        assert!(err.to_string().contains("secp256k1"), "{err}");
    }

    #[test]
    fn a_truncated_off_curve_or_compressed_point_is_refused() {
        let mut der = spki(&generator_point());
        der.truncate(der.len() - 1);
        assert_eq!(
            compress_secp256k1_spki(&der),
            Err(SpkiError::WrongPointLength { byte_count: 64 })
        );

        let mut off_curve = generator_point();
        off_curve[64] ^= 0x01;
        assert_eq!(
            compress_secp256k1_spki(&spki(&off_curve)),
            Err(SpkiError::NotOnCurve)
        );

        let mut compressed_form = generator_point();
        compressed_form[0] = 0x02;
        assert_eq!(
            compress_secp256k1_spki(&spki(&compressed_form)),
            Err(SpkiError::NotUncompressed { form: 0x02 })
        );

        assert!(
            matches!(
                compress_secp256k1_spki(&[]),
                Err(SpkiError::NotSecp256k1 { byte_count: 0, .. })
            ),
            "empty"
        );
    }
}
