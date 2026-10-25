use std::fmt;

/// One of the four validation passes a block's operations are grouped in.
///
/// Octez validates a block's operations in these four passes, in this
/// order. Pass 3 holds the manager operations: transactions, originations,
/// delegations, reveals and smart-rollup messages. The RPC names a pass by
/// its [`ValidationPass::index`], which is also how it displays.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ValidationPass {
    Consensus,
    Voting,
    Anonymous,
    Manager,
}

impl ValidationPass {
    /// The pass's number in the RPC path: 0 to 3.
    pub const fn index(self) -> u32 {
        match self {
            Self::Consensus => 0,
            Self::Voting => 1,
            Self::Anonymous => 2,
            Self::Manager => 3,
        }
    }
}

impl fmt::Display for ValidationPass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.index())
    }
}
