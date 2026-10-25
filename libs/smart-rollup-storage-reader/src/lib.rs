//! Fetch + decode the Tezos smart-rollup's durable storage over its RPC.
//!
//! Two halves, cleanly separated so backends stay swappable:
//!
//! - [`decode`] — a **sync, `reqwest`-free** decode core. Given a durable-storage
//!   key + its raw bytes, it resolves the key against the shared path grammar in
//!   [`smart_rollup_storage::paths`], borsh-deserializes the matching per-type
//!   envelope (or parses a raw scalar), and yields a labeled [`DecodedValue`]. A
//!   decode failure never hides the bytes — it falls back to `kind = "unknown"`
//!   with `raw_hex` populated.
//! - [`store`] — the [`DurableStore`] trait (async `subkeys`/`value`/`length`)
//!   plus [`StoreError`], with the live [`LiveDurableStore`] backend in [`live`]
//!   reading through `octez_rpc::rollup`.

pub use decode::{DecodedValue, decode};
pub use live::{InvalidBlock, LiveDurableStore, parse_block, parse_durable_value};
pub use store::{DurableStore, StoreError};

pub mod decode;
pub mod live;
pub mod store;
