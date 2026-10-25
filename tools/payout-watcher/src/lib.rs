//! payout-watcher: a public check that every fast payout a 99dot5 vault makes
//! on Tezos L1 is backed by the rollup kernel's own record (ADR 0027 §4.8).
//!
//! A vault pays a session's balance two ways. The cemented payout is
//! authorised by the rollup itself, about two weeks after the session ends.
//! The fast payout is authorised by two of four signers minutes after it
//! ends, before anything cements — so two signers acting together could pay
//! more than the kernel computed. This tool makes that impossible to do
//! quietly. For each watched vault it reads every `fast_payout` and
//! `cemented_payout` event from an L1 node, and:
//!
//! - compares each fast payout with the kernel's `payout-{session_id}` record
//!   and the session record, read from the runner's OWN rollup node at its
//!   finalised block ([`kernel`]);
//! - re-verifies every signature the fast payout was submitted with against
//!   the vault's on-chain `payout_signers` ([`signatures`]), and reports a
//!   change of that set;
//! - checks every event's move of the vault's paid ledger ([`ledger`]);
//! - matches every `sweep` event — house profit leaving the vault for its
//!   treasury, authorised by the kernel — against the kernel's
//!   `sweep-{level}-{id}` record, the equity it bounded the sweep by and
//!   the treasury baked into the vault ([`sweep`]).
//!
//! Every input is public chain data. Findings are JSON lines; alarms are at
//! `ERROR` and make a `--once` run exit non-zero.

#![forbid(unsafe_code)]

pub mod alarm;
pub mod app_config;
pub mod kernel;
pub mod ledger;
pub mod signatures;
pub mod source;
pub mod state;
pub mod sweep;
pub mod vault_storage;
pub mod watcher;

// The block decoder, the Micheline reader and the key normaliser live in
// `payout_protocol` (the sweep tracker reads a block the same way); the
// watcher's paths to them are kept.
pub use payout_protocol::{events, keys, micheline};
