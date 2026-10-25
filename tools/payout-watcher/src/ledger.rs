//! The vault's per-session paid ledger, as pure functions
//! (ADR 0027 §4.3).
//!
//! `paid[session]` is the total the vault has paid the session's owner
//! through either path. The two events report what each execution did to it:
//!
//! - a **fast payout** is refused once anything is on the ledger, so it
//!   always starts from zero and pays its whole amount:
//!   `previous = 0`, `paid_now = fast`, `paid_total = fast`;
//! - a **cemented payout** of `c` over a previous total `p` pays the
//!   remainder and records the larger: `paid_now = max(0, c − p)`,
//!   `paid_total = max(p, c)`. An over-paid session (`p > c`) is left
//!   standing, nothing is clawed back — the fast-payout check is what catches
//!   that overpayment, not this one.
//!
//! The previous total is the watcher's own replay of every earlier event of
//! the vault, never the event's own claim, so a vault that paid twice cannot
//! describe itself into agreement.

/// What an execution should have written, given the previous total.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LedgerMove {
    pub paid_now: u128,
    pub paid_total: u128,
}

/// The fast payout's move: refused unless nothing is paid yet, then the
/// whole amount. `None` when `previous` is non-zero: the vault should have
/// refused it (`Already paid`).
pub fn expected_fast(previous: u128, fast: u128) -> Option<LedgerMove> {
    (previous == 0).then_some(LedgerMove {
        paid_now: fast,
        paid_total: fast,
    })
}

/// The cemented payout's move: the remainder over the previous total.
pub fn expected_cemented(previous: u128, cemented: u128) -> LedgerMove {
    LedgerMove {
        paid_now: cemented.saturating_sub(previous),
        paid_total: previous.max(cemented),
    }
}

/// A reported move that is not the expected one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LedgerMismatch {
    pub previous: u128,
    /// `None` for a fast payout over a non-zero ledger, which has no
    /// expected move at all.
    pub expected: Option<LedgerMove>,
    pub reported: LedgerMove,
}

/// Check a fast payout event against the ledger.
pub fn check_fast(previous: u128, fast: u128, reported: LedgerMove) -> Option<LedgerMismatch> {
    let expected = expected_fast(previous, fast);

    (expected != Some(reported)).then_some(LedgerMismatch {
        previous,
        expected,
        reported,
    })
}

/// Check a cemented payout event against the ledger.
pub fn check_cemented(
    previous: u128,
    cemented: u128,
    reported: LedgerMove,
) -> Option<LedgerMismatch> {
    let expected = expected_cemented(previous, cemented);

    (expected != reported).then_some(LedgerMismatch {
        previous,
        expected: Some(expected),
        reported,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mv(paid_now: u128, paid_total: u128) -> LedgerMove {
        LedgerMove {
            paid_now,
            paid_total,
        }
    }

    #[test]
    fn the_spec_d2_table_rows_hold() {
        // Fast first (a), cemented later (c > a): pays c − a, records c.
        assert_eq!(expected_fast(0, 3), Some(mv(3, 3)));
        assert_eq!(expected_cemented(3, 5), mv(2, 5));
        // Cemented first: pays c, records c; a later fast payout is refused.
        assert_eq!(expected_cemented(0, 5), mv(5, 5));
        assert_eq!(expected_fast(5, 5), None);
        // Fast short (a < c): the cemented tops up to the kernel's number.
        assert_eq!(expected_cemented(1, 5), mv(4, 5));
        // Fast over (a > c): nothing moves, the overpayment stands.
        assert_eq!(expected_cemented(7, 5), mv(0, 7));
        // Already paid in full: no-op.
        assert_eq!(expected_cemented(5, 5), mv(0, 5));
        // Zero amount: no-op.
        assert_eq!(expected_cemented(0, 0), mv(0, 0));
    }

    #[test]
    fn a_reported_move_that_differs_is_a_mismatch() {
        assert_eq!(check_fast(0, 3, mv(3, 3)), None);
        assert_eq!(check_cemented(3, 5, mv(2, 5)), None);

        // The vault paid the cemented amount in full over a fast payout:
        // paid twice.
        assert_eq!(
            check_cemented(3, 5, mv(5, 8)),
            Some(LedgerMismatch {
                previous: 3,
                expected: Some(mv(2, 5)),
                reported: mv(5, 8),
            })
        );
        // A fast payout over a non-zero ledger has no right answer.
        assert_eq!(
            check_fast(3, 2, mv(2, 2)),
            Some(LedgerMismatch {
                previous: 3,
                expected: None,
                reported: mv(2, 2),
            })
        );
        // A fast payout reporting less paid than it asked for.
        assert!(check_fast(0, 3, mv(2, 2)).is_some());
    }

    #[test]
    fn the_rule_holds_at_the_u128_edges() {
        assert_eq!(expected_cemented(u128::MAX, 0), mv(0, u128::MAX));
        assert_eq!(expected_cemented(0, u128::MAX), mv(u128::MAX, u128::MAX));
    }
}
