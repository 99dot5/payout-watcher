use crate::BlockHash;
use core::fmt;

/// A block of the rollup node, as `/global/block/{id}` takes it.
///
/// Measured against `octez-smart-rollup-node`: `head`, `finalized`,
/// `cemented`, a level and a block hash, and NO relative form: every `~n` and
/// `+n`, on any of them, is a 400. Unlike the L1 node there is no
/// `genesis`/`checkpoint`/`savepoint`/`caboose`.
///
/// [`fmt::Display`] is the only serialiser.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum BlockId {
    Head,
    Finalized,
    Cemented,
    Level(u32),
    /// A block hash.
    Hash(BlockHash),
}

impl fmt::Display for BlockId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Head => f.write_str("head"),
            Self::Finalized => f.write_str("finalized"),
            Self::Cemented => f.write_str("cemented"),
            Self::Level(level) => write!(f, "{level}"),
            Self::Hash(hash) => write!(f, "{hash}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every identifier the rollup node was measured to accept.
    #[test]
    fn renders_every_measured_identifier() {
        let hash = "BLockGenesisGenesisGenesisGenesisGenesisb83baZgbyZe";
        let block_hash = BlockHash::parse(hash).expect("a block hash");
        let cases = [
            (BlockId::Head, "head"),
            (BlockId::Finalized, "finalized"),
            (BlockId::Cemented, "cemented"),
            (BlockId::Level(127), "127"),
            (BlockId::Hash(block_hash), hash),
        ];

        for (id, expected) in cases {
            assert_eq!(id.to_string(), expected, "{id:?}");
        }
    }
}
