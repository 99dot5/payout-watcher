//! The running kernel's identity, as every fast-payout checker pins it (ADR
//! 0027 §1.3 condition 2): the kernel installed on chain, "checked against
//! `/kernel/info`, and around a governed upgrade (ADR 0014), against the root
//! hash".
//!
//! `/kernel/info` names a crate version, which a governed upgrade may well
//! keep (a kernel rebuilt from the same version with a change the checker's
//! operator has not reviewed). So the version pin is necessary and not
//! sufficient, and the second check is the one that cannot be fooled: the
//! **reveal-tree root hash of the installed kernel bytes**, computed from
//! `/kernel/boot.wasm` at a finalised block with the same `prepare_preimages`
//! the installer and `99dot5 smart-rollup build-installer` derive it with.
//! That hash is the 33-byte value the multisig signs in
//! `ProposeKernelUpgrade` and the release records, so a pin names the exact
//! artefact its operator verified.
//!
//! Shared here because two independent checkers compute it from their own
//! node's bytes: the validator (`services/validator`), which refuses to sign
//! under a kernel other than the pinned one, and the public overpayment
//! watcher (`tools/payout-watcher`), which alarms when the kernel whose records
//! it compares fast payouts against is not the one its runner pinned.

use tezos_smart_rollup_encoding::dac::pages::prepare_preimages;
use thiserror::Error;

/// A reveal-tree root hash: the `0x00` blake2b tag and 32 hash bytes, as the
/// kernel stores it and the multisig signs it (ADR 0014).
pub type RootHash = [u8; 33];

/// The tag every root hash the kernel accepts starts with.
pub const ROOT_HASH_TAG: u8 = 0x00;

/// Why a configured root hash was refused.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RootHashParseError {
    #[error("a root hash is 66 hex characters (33 bytes), got {len}")]
    Length { len: usize },
    #[error("a root hash is hex: {reason}")]
    Hex { reason: String },
    #[error("a root hash starts with the 0x00 blake2b tag, got 0x{tag:02x}")]
    Tag { tag: u8 },
}

/// Parse the 66-hex-character form the release notes and the multisig
/// ceremony use.
pub fn parse_root_hash(text: &str) -> Result<RootHash, RootHashParseError> {
    let text = text.trim();
    if text.len() != 66 {
        return Err(RootHashParseError::Length { len: text.len() });
    }
    let bytes = hex::decode(text).map_err(|e| RootHashParseError::Hex {
        reason: e.to_string(),
    })?;
    let hash: RootHash = bytes
        .try_into()
        .map_err(|_| RootHashParseError::Length { len: text.len() })?;
    if hash[0] != ROOT_HASH_TAG {
        return Err(RootHashParseError::Tag { tag: hash[0] });
    }

    Ok(hash)
}

/// The hex form, for logs and refusals.
pub fn format_root_hash(hash: &RootHash) -> String {
    hex::encode(hash)
}

/// The reveal-tree root hash of `kernel`: the content pages, then the hash
/// pages up to one root, exactly as the installer builds the preimages the
/// kernel reveals and verifies (`libs/smart-rollup/src/admin/handlers.rs`).
/// The only failure is blake2b refusing a page, which the chunking rules out.
pub fn root_hash_of(kernel: &[u8]) -> Result<RootHash, String> {
    prepare_preimages(kernel, |_hash, _page| {})
        .map(|hash| *hash.as_ref())
        .map_err(|e| format!("{e:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tezos_data_encoding::enc::BinWriter;
    use tezos_smart_rollup_encoding::dac::pages::{
        Page, V0ContentPage, V0HashPage, make_preimage_hash,
    };

    /// A deterministic, incompressible-looking content of `len` bytes.
    fn content(len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| (i as u32).wrapping_mul(2_654_435_761).to_le_bytes()[i % 4])
            .collect()
    }

    fn page_hash(page: &Page) -> RootHash {
        let mut encoded = Vec::new();
        page.bin_write(&mut encoded).expect("encode");

        make_preimage_hash(&encoded).expect("hash")
    }

    #[test]
    fn a_single_page_kernel_hashes_to_its_content_page() {
        let kernel = content(1000);
        let mut pages = V0ContentPage::new_pages(&kernel);
        let expected = page_hash(&Page::V0ContentPage(pages.next().expect("one page")));
        assert!(pages.next().is_none(), "fits one page");

        assert_eq!(root_hash_of(&kernel).expect("root"), expected);
        assert_eq!(expected[0], ROOT_HASH_TAG);
    }

    #[test]
    fn a_multi_page_kernel_hashes_to_the_hash_page_over_its_content_pages() {
        // Three content pages, well under one hash page.
        let kernel = content(V0ContentPage::MAX_CONTENT_SIZE * 2 + 17);
        let leaves: Vec<RootHash> = V0ContentPage::new_pages(&kernel)
            .map(|page| page_hash(&Page::V0ContentPage(page)))
            .collect();
        assert_eq!(leaves.len(), 3);
        let mut hash_pages = V0HashPage::new_pages(&leaves);
        let expected = page_hash(&Page::V0HashPage(hash_pages.next().expect("one hash page")));
        assert!(hash_pages.next().is_none(), "three hashes fit one page");

        assert_eq!(root_hash_of(&kernel).expect("root"), expected);
    }

    #[test]
    fn one_changed_byte_changes_the_root() {
        let kernel = content(10_000);
        let mut other = kernel.clone();
        other[7_777] ^= 0x01;

        assert_ne!(root_hash_of(&kernel), root_hash_of(&other));
    }

    #[test]
    fn the_hex_form_round_trips_and_the_tag_is_enforced() {
        let hash = root_hash_of(&content(100)).expect("root");
        let text = format_root_hash(&hash);
        assert_eq!(text.len(), 66);
        assert_eq!(parse_root_hash(&text), Ok(hash));
        assert_eq!(
            parse_root_hash(&format!("  {text}\n")),
            Ok(hash),
            "whitespace trimmed"
        );

        assert_eq!(
            parse_root_hash(&text[..64]),
            Err(RootHashParseError::Length { len: 64 })
        );
        assert!(matches!(
            parse_root_hash(&format!("zz{}", &text[2..])),
            Err(RootHashParseError::Hex { .. })
        ));
        assert_eq!(
            parse_root_hash(&format!("01{}", &text[2..])),
            Err(RootHashParseError::Tag { tag: 0x01 })
        );
    }
}
