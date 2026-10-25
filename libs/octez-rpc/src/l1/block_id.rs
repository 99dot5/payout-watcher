use crate::BlockHash;
use core::fmt;

/// A block of the L1 node, as `/chains/main/blocks/{id}` takes it.
///
/// Measured against `octez-node`: the anchors are `head`, `genesis`,
/// `checkpoint`, `savepoint`, `caboose`, a level and a block hash; every
/// anchor takes exactly ONE relative step, `~n` (the nth block before) or
/// `+n` (the nth after), and `n = 0` is accepted (`head~0`). Steps do not
/// nest (`head~1~1` is a 400), and `finalized` is not an L1 identifier (a
/// 400; it belongs to the rollup node, [`crate::rollup::BlockId`]). A step
/// past the chain's end (`head+1`) is a 400 too, but from absence, not syntax.
///
/// The type admits exactly that grammar; [`fmt::Display`] is its only
/// serialiser.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BlockId {
    pub anchor: L1Anchor,
    pub step: Option<Step>,
}

/// What an L1 [`BlockId`] counts from.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum L1Anchor {
    Head,
    Genesis,
    Checkpoint,
    Savepoint,
    Caboose,
    Level(u32),
    /// A block hash (`B…`).
    Hash(BlockHash),
}

/// One relative step from an [`L1Anchor`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Step {
    /// `~n`: the nth block before the anchor.
    Back(u32),
    /// `+n`: the nth block after the anchor.
    Forward(u32),
}

impl BlockId {
    pub const HEAD: Self = Self::at(L1Anchor::Head);

    /// The anchor itself, no step.
    pub const fn at(anchor: L1Anchor) -> Self {
        Self { anchor, step: None }
    }

    /// The block `n` before `anchor` (`anchor~n`).
    pub const fn back(anchor: L1Anchor, n: u32) -> Self {
        Self {
            anchor,
            step: Some(Step::Back(n)),
        }
    }

    /// The block `n` after `anchor` (`anchor+n`).
    pub const fn forward(anchor: L1Anchor, n: u32) -> Self {
        Self {
            anchor,
            step: Some(Step::Forward(n)),
        }
    }

    pub const fn level(level: u32) -> Self {
        Self::at(L1Anchor::Level(level))
    }

    pub const fn hash(hash: BlockHash) -> Self {
        Self::at(L1Anchor::Hash(hash))
    }
}

impl fmt::Display for L1Anchor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Head => f.write_str("head"),
            Self::Genesis => f.write_str("genesis"),
            Self::Checkpoint => f.write_str("checkpoint"),
            Self::Savepoint => f.write_str("savepoint"),
            Self::Caboose => f.write_str("caboose"),
            Self::Level(level) => write!(f, "{level}"),
            Self::Hash(hash) => write!(f, "{hash}"),
        }
    }
}

impl fmt::Display for Step {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Back(n) => write!(f, "~{n}"),
            Self::Forward(n) => write!(f, "+{n}"),
        }
    }
}

impl fmt::Display for BlockId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.anchor)?;

        if let Some(step) = self.step {
            write!(f, "{step}")?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LEVEL: u32 = 127;
    const HASH: &str = "BLockGenesisGenesisGenesisGenesisGenesisb83baZgbyZe";

    fn hash() -> L1Anchor {
        L1Anchor::Hash(BlockHash::parse(HASH).expect("a block hash"))
    }

    /// Every identifier the L1 node was measured to accept.
    #[test]
    fn renders_every_measured_identifier() {
        let cases = [
            (BlockId::HEAD, "head".to_string()),
            (BlockId::at(L1Anchor::Genesis), "genesis".to_string()),
            (BlockId::at(L1Anchor::Checkpoint), "checkpoint".to_string()),
            (BlockId::at(L1Anchor::Savepoint), "savepoint".to_string()),
            (BlockId::at(L1Anchor::Caboose), "caboose".to_string()),
            (BlockId::level(LEVEL), "127".to_string()),
            (BlockId::at(hash()), HASH.to_string()),
            (BlockId::back(L1Anchor::Head, 1), "head~1".to_string()),
            (
                BlockId::back(L1Anchor::Checkpoint, 1),
                "checkpoint~1".to_string(),
            ),
            (
                BlockId::forward(L1Anchor::Genesis, 1),
                "genesis+1".to_string(),
            ),
            (
                BlockId::back(L1Anchor::Savepoint, 1),
                "savepoint~1".to_string(),
            ),
            (
                BlockId::forward(L1Anchor::Caboose, 1),
                "caboose+1".to_string(),
            ),
            (
                BlockId::back(L1Anchor::Level(LEVEL), 1),
                "127~1".to_string(),
            ),
            (
                BlockId::forward(L1Anchor::Level(LEVEL), 1),
                "127+1".to_string(),
            ),
            (BlockId::back(hash(), 1), format!("{HASH}~1")),
            (BlockId::forward(hash(), 1), format!("{HASH}+1")),
            (BlockId::back(L1Anchor::Head, 0), "head~0".to_string()),
        ];

        for (id, expected) in cases {
            assert_eq!(id.to_string(), expected, "{id:?}");
        }
    }
}
