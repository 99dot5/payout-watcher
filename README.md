# payout-watcher

A public check that every fast payout a 99dot5 vault makes on Tezos L1 is
backed by the rollup kernel's own record. Run it against your own Tezos node
and your own rollup node.

The tool and how to run it: [tools/payout-watcher/README.md](tools/payout-watcher/README.md).

## Building and testing

```sh
cargo build --release --locked -p payout-watcher
cargo test --locked -p payout-watcher
```

## Layout

- `tools/payout-watcher/`: the watcher.
- `libs/`: the libraries it builds against: the fast-payout payload
  encoder and verifier, the wallet-signature verifier, the rollup's durable
  storage layouts and their reader, the Octez node RPC client under it, and
  the JSON log format.
- `tools/operator-cli/tests/fast-payout-vectors.json`: the shared test
  vectors the payload, the signatures and the watcher's decoding are pinned
  to.

## Provenance

This tree is exported from the 99dot5 monorepo; `EXPORT_COMMIT` names the
commit. Every source file is copied verbatim. Only this README, `LICENSE`,
the workspace `Cargo.toml`, `rust-toolchain.toml`, `Cargo.lock` (the
monorepo's, trimmed by cargo to this workspace) and the CI workflow are
generated.
