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

## Releases

Each `payout-watcher-v<version>` release of this repository carries the Linux
arm64 build of that version as CI built it, `payout-watcher-linux-arm64`,
beside its `payout-watcher-linux-arm64.sha256`. A published asset is never
replaced: a new version is a new release. The release notes name the source
commit the binary was built from.

## Provenance

This tree is exported from the 99dot5 monorepo; `EXPORT_COMMIT` names the
commit. Every source file is copied verbatim. Only this README, `LICENSE`,
the workspace `Cargo.toml`, `rust-toolchain.toml`, `Cargo.lock` (the
monorepo's, trimmed by cargo to this workspace) and the CI workflow are
generated.
