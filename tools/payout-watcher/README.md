# payout-watcher

A public check that every **fast payout** a 99dot5 vault makes on Tezos L1 is
backed by the rollup kernel's own record of what the session was owed. Run it
against **your own** Tezos node and **your own** rollup node; it trusts
neither the operator nor any service the operator runs.

## Why it exists

A vault pays a session's balance back to the wallet that funded it in one of
two ways:

- the **cemented payout**: the rollup's own outbox message, executable about
  two weeks after the session ends, once the rollup's commitment cements;
- the **fast payout**: the same payment minutes after the session ends,
  authorised by **two of the vault's four payout signers**.

The vault cannot check a fast payout's amount itself: before cementation, only
a rollup node knows what the kernel computed. So two signers acting together
could pay more than the session was owed. That cannot be prevented without
capital, but it can be made impossible to do quietly: every fast payout names
its session on L1, and the kernel's record for that session is public. This
tool compares the two within minutes of the payout.

## What it checks

For each vault you list, it reads every `fast_payout` and `cemented_payout`
event the vault emitted, from the vault's origination onward, and:

1. **Against the kernel** (each fast payout), read from your rollup node at
   its *finalised* block:
   - the amount paid is not above the kernel's `session-{session_id}-end-payout` record
     (`fast_payout_above_kernel`);
   - the session exists (`session_not_recorded`), has ended
     (`session_not_ended`), ended with a payout record (`payout_not_recorded`)
     that is the session's `SessionEndPayout` row (`payout_record_not_a_session_end_payout`;
     `RoundEndPayout` is a round's credit inside the rollup), is a TEZ session
     (`session_asset_not_tez`), and was funded through the vault that paid
     (`funding_vault_mismatch`).

   The session's tenant and pool come from the paying vault's own storage,
   where they are fixed at origination.

2. **The signatures** (each fast payout): every signature in the submitted
   operation's parameters is re-verified over
   `PACK(("fast-payout:v1", chain_id, vault, session_id, amount))` against the
   vault's on-chain `payout_signers` as they stood before the payout's block.
   A key outside the set (`signer_outside_set`), a member's signature that
   does not verify (`signature_invalid`) and fewer than two valid ones
   (`under_threshold`) are alarms. So is a change of the set itself between
   two payouts (`payout_signers_changed`), and, if you configure the set you
   expect, any other set (`unexpected_payout_signers`).

3. **The paid ledger** (every event): a fast payout starts from nothing paid
   and pays its whole amount; a cemented payout of `c` over a previous total
   `p` pays `max(0, c − p)` and leaves `max(p, c)` recorded. The previous
   total is this tool's own replay of the vault's earlier events, never the
   event's claim about itself (`ledger_mismatch`).

4. **The kernel itself** (optional): pin the `/kernel/info` version and the
   reveal-tree root hash of the installed `/kernel/boot.wasm`, and every pass
   checks your node runs that kernel (`kernel_identity_mismatch`).

5. **Sweeps** (each `sweep` event): house profit leaves a vault only through
   `execute_sweep`, an outbox message the rollup kernel emits for a sweep it
   authorised within the vault's house equity, and the vault pays it to the
   treasury baked into its own storage. Every sweep executed on L1 must name
   a `sweep-{level}-{id}` record the kernel holds for that vault and amount
   (`sweep_not_recorded`, `sweep_record_not_a_sweep`, `sweep_vault_mismatch`,
   `sweep_amount_mismatch`), pay the vault's `treasury`
   (`sweep_treasury_mismatch`), and the kernel's equity record as it stood at
   the level of the request — read back from your rollup node's history, so
   the node must keep it: the default `archive` mode does — must hold the
   reservation and satisfy the bound the kernel checked, `payouts + swept ≤
   funded + stakes` (`sweep_equity_not_recorded`, `sweep_above_equity`). A
   sweep that passes is logged with the equity it was bounded by. This is
   what proves that no sweep, however it was signed, took anything the
   kernel owed a player.

Paying *less* than the kernel's number is not an alarm: the cemented payout
tops the session up to the kernel's figure, and the tool logs a warning.

## Running it

You need a Tezos L1 node and a smart-rollup node for the 99dot5 rollup, both
yours, with their RPC reachable from where this runs. The rollup node can run
in observer mode; the tool reads only `value` from durable storage, which the
node's default RPC ACL allows. Build with a Rust toolchain:

```sh
cargo build --release --bin payout-watcher
```

Write a configuration file. TOML is shown; YAML or JSON work too, chosen by
the file's extension:

```toml
l1_node_url = "http://127.0.0.1:8732"
rollup_node_url = "http://127.0.0.1:8932"
state_file = "payout-watcher-state.json"
# How far the rollup node may trail L1 before a pass reports itself blind.
max_rollup_lag_levels = 60

# Optional: the kernel you have verified.
[kernel]
expected_version = "0.8.10"
expected_root_hash = "00…"            # 66 hex characters

[[vaults]]
address = "KT1…"                      # a vault of the rollup's pools
start_level = 1234567                 # its origination level
# Optional: the four signers you expect it to hold.
expected_payout_signers = ["sppk…", "sppk…", "edpk…", "edpk…"]
```

`l1_node_url` is the L1 node's RPC.

The vault addresses of a deployment are on chain: the rollup's administrator
registers each one with a `RegisterPoolVault` operation, which the round
verifier lists. Then:

```sh
# One pass up to L1's final level, then exit (for cron).
payout-watcher --config watcher.toml --once

# Keep polling.
payout-watcher --config watcher.toml --follow --poll-interval-secs 30
```

Any scalar in the file can be overridden by an environment variable named
`APP__` plus its path, sections joined by a double underscore:
`APP__ROLLUP_NODE_URL`, `APP__STATE_FILE`, `APP__MAX_ROLLUP_LAG_LEVELS`,
`APP__KERNEL__EXPECTED_ROOT_HASH`. The `[[vaults]]` list stays in the file.

### Output and exit status

Every line is one JSON object on stdout. An alarm is at `level: "ERROR"` with
`alarm` naming the kind and the fields `vault_address`, `tenant_id`,
`pool_id`, `session_id`, `l1_level`, `reference` (the operation hash),
`amount_mutez`, `kernel_amount_mutez`, `paid_now_mutez`, `paid_total_mutez`,
`public_key`, and for a sweep `sweep_id` (the kernel's `sweep-{level}-{id}`
reference) and `treasury`, where they apply. Amounts are decimal strings in
mutez.

| Exit | Meaning |
| ---- | ------- |
| `0`  | Nothing to report. |
| `1`  | At least one alarm. |
| `2`  | A usage or configuration error. |
| `3`  | The pass could not finish: a node did not answer, the state file could not be written, or the rollup node trails L1 by more than `max_rollup_lag_levels` while a fast payout waits. Retry. |

### State and resuming

The state file holds a cursor per vault, the paid ledger replayed so far and
the signer set last seen. It is written after every level, so a pass that
stops resumes where it stopped, and an alarm is raised once. A fast payout at
a level your rollup node has not finalised yet is **deferred**: nothing about
that level is reported or recorded until a later pass, so a lagging node never
reads as a missing record.

## Replaying a snapshot

`--snapshot <file>` replaces both nodes with a recorded snapshot of their
answers: the L1 blocks and scripts, the rollup node's durable values at its
finalised block, and (`durable_at_level`) the values a sweep's request level
is read back at. `testdata/` holds one per alarm and a clean one; each
directory has the config, the snapshot and the expected result:

```sh
APP__STATE_FILE=/tmp/state.json payout-watcher --once \
  --config testdata/overpayment/config.toml \
  --snapshot testdata/overpayment/snapshot.json
```

The fast payouts in them are the shared fast-payout test vectors: the same
payload bytes and signatures the vault's own tests and an independent pytezos
implementation agree on.

## Tests

```sh
cargo test -p payout-watcher
```

The signature verification and the parameter decoding are pinned to the
shared fast-payout vectors in both the readable and the optimised Micheline
forms; every snapshot in `testdata/` is regenerated by the test suite and run
through the binary.
