use core::fmt;
use thiserror::Error;

/// A Tezos block hash (`B…`), the same on both nodes: base58check whose
/// decoded bytes are the `B` prefix and a 32-byte digest.
///
/// Only [`BlockHash::parse`] builds one, so a hash anchor can never render as
/// another identifier (`head~1`) or carry a step of its own.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BlockHash(String);

/// A string [`BlockHash::parse`] refuses.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{raw:?} is not a block hash: expected base58check B… of 34 decoded bytes")]
pub struct InvalidBlockHash {
    pub raw: String,
}

impl BlockHash {
    /// `raw` when its base58check checksum holds, it decodes to 34 bytes and
    /// those start with the block-hash prefix: the pinned crypto crate's typed
    /// decoder, which compares all three.
    pub fn parse(raw: &str) -> Result<Self, InvalidBlockHash> {
        match tezos_crypto_rs::hash::BlockHash::from_base58_check(raw) {
            Ok(_) => Ok(Self(raw.to_string())),
            Err(_) => Err(InvalidBlockHash {
                raw: raw.to_string(),
            }),
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for BlockHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A genuine block hash: base58check over the `B` prefix and a 32-byte digest.
    const GENESIS: &str = "BLockGenesisGenesisGenesisGenesisGenesisb83baZgbyZe";

    #[test]
    fn accepts_a_genuine_block_hash() {
        assert_eq!(
            BlockHash::parse(GENESIS).expect("a block hash").as_str(),
            GENESIS
        );
    }

    #[test]
    fn refuses_anything_else() {
        for raw in [
            "",
            "head",
            "head~1",
            // The genesis hash with its last character changed: a bad checksum.
            "BLockGenesisGenesisGenesisGenesisGenesisb83baZgbyZf",
            // A valid base58check chain id: the wrong prefix and length.
            "NetXdQprcVkpaWU",
            "BLockGenesisGenesisGenesisGenesisGenesisb83baZgbyZe~1",
            // A valid operation hash: a 32-byte digest under another prefix.
            &tezos_crypto_rs::hash::OperationHash::from([7u8; 32]).to_base58_check(),
        ] {
            assert_eq!(
                BlockHash::parse(raw),
                Err(InvalidBlockHash {
                    raw: raw.to_string()
                }),
                "{raw:?}"
            );
        }
    }
}
