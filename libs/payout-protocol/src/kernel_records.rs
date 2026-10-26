//! Where the kernel keeps what a fast-payout checker reads: the durable keys
//! of a session's record and of its `session-{session_id}-end-payout` transaction record,
//! the block they are read at, and the one asset v1 pays in.
//!
//! The validator (`services/validator`) reads these to decide what to sign;
//! the public overpayment watcher (`tools/payout-watcher`) reads the same
//! records to check what was paid. One definition of each key, so the two
//! cannot drift apart: a watcher that looked at another key than the signer
//! would prove nothing about the signer's number.
//!
//! The sweep records are here for the same reason: the kernel books every
//! vault's house equity at `…/equity/{KT1}` and writes a `sweep-{level}-{id}`
//! transaction record for each sweep it authorises, and the public watcher
//! matches every `sweep` event on L1 against both. One builder per key, one
//! spelling of the reference, one encoding of the 16-byte sweep id.
//!
//! The path grammar itself is `smart_rollup_storage::paths` (templates 10, 11
//! and 26); these builders render the paths the two checkers need.

use uuid::Uuid;

/// The only asset a fast payout pays in v1 (ADR 0027 §4.1); the vault's
/// `amount` is `mutez`, and `money::ASSET_REGISTRY` makes TEZ's atomic unit
/// the mutez, so the kernel's `u128` is handed to the vault 1:1.
pub const TEZ: &str = "TEZ";

/// The block every read is made at: Tezos blocks are final after two levels,
/// so nothing read here can be reorganised away (ADR 0027 §1.3 condition 1).
/// The same block id the seed provisioner reads acceptance at.
pub const FINALIZED_BLOCK: &str = "finalized";

/// The durable key of the kernel's identity record.
pub const KERNEL_INFO_KEY: &str = "/kernel/info";

/// The durable key of the installed kernel's bytes.
pub const KERNEL_BOOT_KEY: &str = "/kernel/boot.wasm";

/// The durable key of a proposed, not yet activated, governed upgrade.
pub const PENDING_UPGRADE_KEY: &str = "/config/kernel-upgrade/pending";

/// The durable key of a session's record.
pub fn session_key(tenant: &str, pool: &str, session_id: &Uuid) -> String {
    format!("/tenants/{tenant}/pools/{pool}/sessions/{session_id}")
}

/// The durable key of a session's payout record: the kernel's
/// `session-{session_id}-end-payout` reference under the pool's transaction ledger for
/// `asset` (`libs/smart-rollup/src/transactions.rs`).
///
/// The row there is the `SessionEndPayout` that `EndSession` writes: the session's
/// balance leaving the rollup. `RoundEndPayout` is the per-round credit at
/// `round-{round_id}-end-payout` and is never at this key; a reader that expects
/// it here refuses every real session.
pub fn session_end_payout_key(tenant: &str, pool: &str, asset: &str, session_id: &Uuid) -> String {
    format!("/tenants/{tenant}/pools/{pool}/transactions/{asset}/session-{session_id}-end-payout")
}

/// The durable key of a vault's house-equity record: the four monotone
/// counters (`funded`, `stakes`, `payouts`, `swept`) the kernel bounds every
/// sweep by (`docs/specs/house-equity-and-sweeps.md` H1), a
/// `HouseEquityEnvelope` beside the vault's status record.
pub fn house_equity_key(tenant: &str, pool: &str, vault: &str) -> String {
    format!("/tenants/{tenant}/pools/{pool}/equity/{vault}")
}

/// The reference of the kernel's record of one authorised sweep:
/// `sweep-{level}-{id}`, the L1 inbox level and message index of the
/// administrator's `Sweep` operation. The same two numbers ride the
/// `execute_sweep` outbox message as its 16-byte sweep id
/// ([`sweep_id_bytes`]), so an execution on L1 names exactly this record.
pub fn sweep_reference(level: u64, id: u64) -> String {
    format!("sweep-{level}-{id}")
}

/// The durable key of a sweep's record: [`sweep_reference`] under the pool's
/// transaction ledger for `asset`, a `StoredTransactionEnvelope` of kind
/// `Sweep` whose account is the vault swept and whose amount is the sweep's.
pub fn sweep_key(tenant: &str, pool: &str, asset: &str, level: u64, id: u64) -> String {
    format!(
        "/tenants/{tenant}/pools/{pool}/transactions/{asset}/{}",
        sweep_reference(level, id)
    )
}

/// The two numbers a 16-byte sweep id carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SweepId {
    /// The L1 inbox level of the `Sweep` operation.
    pub level: u64,
    /// The operation's message index within that level.
    pub id: u64,
}

impl SweepId {
    /// The `sweep-{level}-{id}` reference of the record this id names.
    pub fn reference(self) -> String {
        sweep_reference(self.level, self.id)
    }
}

/// The 16 raw bytes an `execute_sweep` carries as its `sweep_id`:
/// `u64 BE level ‖ u64 BE id`, the frozen layout of
/// `docs/specs/house-equity-and-sweeps.md` H4. Big-endian so the bytes sort
/// like the levels they name.
pub fn sweep_id_bytes(level: u64, id: u64) -> [u8; 16] {
    let mut bytes = [0u8; 16];

    bytes[..8].copy_from_slice(&level.to_be_bytes());
    bytes[8..].copy_from_slice(&id.to_be_bytes());

    bytes
}

/// The level and index a 16-byte sweep id names: the inverse of
/// [`sweep_id_bytes`].
pub fn parse_sweep_id(bytes: &[u8; 16]) -> SweepId {
    let (level, id) = bytes.split_at(8);

    SweepId {
        level: u64::from_be_bytes(level.try_into().expect("eight bytes")),
        id: u64::from_be_bytes(id.try_into().expect("eight bytes")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_follow_the_kernels_paths() {
        let id = Uuid::parse_str("660e8400-e29b-41d4-a716-446655440099").expect("uuid");

        assert_eq!(
            session_key("t", "p", &id),
            "/tenants/t/pools/p/sessions/660e8400-e29b-41d4-a716-446655440099"
        );
        assert_eq!(
            session_end_payout_key("t", "p", "TEZ", &id),
            "/tenants/t/pools/p/transactions/TEZ/session-660e8400-e29b-41d4-a716-446655440099-end-payout"
        );
        assert_eq!(
            house_equity_key("t", "p", "KT1BuEZtb68c1Q4yjtckcNjGELqWt56Xyesc"),
            "/tenants/t/pools/p/equity/KT1BuEZtb68c1Q4yjtckcNjGELqWt56Xyesc"
        );
        assert_eq!(sweep_reference(123, 4), "sweep-123-4");
        assert_eq!(
            sweep_key("t", "p", "TEZ", 123, 4),
            "/tenants/t/pools/p/transactions/TEZ/sweep-123-4"
        );
    }

    /// `u64 BE level ‖ u64 BE id`, the kernel's frozen layout, and its
    /// inverse: a level and an id are not interchangeable.
    #[test]
    fn the_sweep_id_is_level_then_id_big_endian_and_round_trips() {
        let bytes = sweep_id_bytes(0x0102_0304, 0x1112_1314);

        assert_eq!(
            bytes,
            [
                0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x00, 0x00, 0x11, 0x12,
                0x13, 0x14,
            ]
        );
        assert_eq!(
            parse_sweep_id(&bytes),
            SweepId {
                level: 0x0102_0304,
                id: 0x1112_1314
            }
        );
        assert_eq!(
            parse_sweep_id(&bytes).reference(),
            "sweep-16909060-286397204"
        );
        assert_ne!(sweep_id_bytes(1, 2), sweep_id_bytes(2, 1));
    }
}
