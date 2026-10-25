//! `payout-watcher`: check a vault's fast payouts against the rollup kernel.
//!
//! Exit status: `0` nothing to report; `1` at least one alarm; `2` a usage or
//! configuration error; `3` the pass could not finish (a node did not answer,
//! the state file could not be written, or the rollup node trails L1 too far
//! to check what was paid) — retry.

use clap::Parser;
use payout_watcher::alarm::{Alarm, Notice, emit, note};
use payout_watcher::app_config::AppConfig;
use payout_watcher::source::{L1Node, LiveL1Node, LiveRollupNode, RollupNode, Snapshot};
use payout_watcher::state::{self, State};
use payout_watcher::watcher::{PassError, PassReport, Sink, WatchConfig, run_pass};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

const SERVICE_NAME: &str = "payout-watcher";
const EXIT_ALARM: u8 = 1;
const EXIT_USAGE: u8 = 2;
const EXIT_RETRY: u8 = 3;

#[derive(Debug, Parser)]
#[command(
    name = "payout-watcher",
    version,
    about = "Check every fast payout of a 99dot5 vault against the rollup kernel's record"
)]
struct Cli {
    /// The configuration file (TOML, YAML or JSON, by extension): the vaults,
    /// the nodes, the state file and an optional kernel pin. Any scalar in it
    /// is overridden by an `APP__`-prefixed environment variable
    /// (`APP__ROLLUP_NODE_URL`, `APP__KERNEL__EXPECTED_VERSION`, …).
    #[arg(long)]
    config: PathBuf,
    /// Replay a recorded snapshot of both nodes instead of reading live ones;
    /// the node URLs are then not needed.
    #[arg(long)]
    snapshot: Option<PathBuf>,
    /// One pass up to the final level, then exit (for cron).
    #[arg(long, conflicts_with = "follow")]
    once: bool,
    /// Keep polling the final head.
    #[arg(long)]
    follow: bool,
    /// Seconds between passes in `--follow`.
    #[arg(long, default_value_t = 30)]
    poll_interval_secs: u64,
}

struct LogSink<'a> {
    state_file: &'a Path,
}

impl Sink for LogSink<'_> {
    fn alarm(&mut self, alarm: &Alarm) {
        emit(alarm);
    }

    fn notice(&mut self, notice: &Notice) {
        note(notice);
    }

    fn commit(&mut self, state: &State) -> std::io::Result<()> {
        state::save(self.state_file, state)
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let _guard = observability::init(SERVICE_NAME, env!("CARGO_PKG_VERSION"));
    let cli = Cli::parse();
    let (file, config) = match load_config(&cli.config) {
        Ok(loaded) => loaded,
        Err(e) => {
            tracing::error!(error = %e, "configuration refused");
            return ExitCode::from(EXIT_USAGE);
        }
    };
    if cli.once == cli.follow {
        tracing::error!(error = "pass exactly one of --once or --follow", "usage");
        return ExitCode::from(EXIT_USAGE);
    }
    let Some(state_file) = file.state_file.clone() else {
        tracing::error!(
            error = "no state file: set state_file or APP__STATE_FILE",
            "usage"
        );
        return ExitCode::from(EXIT_USAGE);
    };

    if let Some(path) = &cli.snapshot {
        let snapshot = match Snapshot::load(path) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(error = %e, "snapshot refused");
                return ExitCode::from(EXIT_USAGE);
            }
        };
        return run(&cli, &config, &state_file, &snapshot.l1, &snapshot.rollup).await;
    }
    let (Some(l1_url), Some(rollup_url)) = (file.l1_node_url.clone(), file.rollup_node_url.clone())
    else {
        tracing::error!(
            error = "both an L1 RPC URL and a rollup node URL are required",
            "usage"
        );
        return ExitCode::from(EXIT_USAGE);
    };
    tracing::info!(
        l1_node_url = %l1_url,
        rollup_node_url = %rollup_url,
        vault_count = config.vaults.len(),
        "payout watcher starting"
    );

    let nodes = LiveL1Node::new(l1_url).and_then(|l1| Ok((l1, LiveRollupNode::new(rollup_url)?)));
    let (l1, rollup) = match nodes {
        Ok(nodes) => nodes,
        Err(e) => {
            tracing::error!(error = %e, "could not build the node clients");
            return ExitCode::from(EXIT_RETRY);
        }
    };

    run(&cli, &config, &state_file, &l1, &rollup).await
}

fn load_config(path: &Path) -> Result<(AppConfig, WatchConfig), String> {
    let file = AppConfig::load(path)?;
    let config = file.watch_config()?;

    Ok((file, config))
}

async fn run<L: L1Node, R: RollupNode>(
    cli: &Cli,
    config: &WatchConfig,
    state_file: &Path,
    l1: &L,
    rollup: &R,
) -> ExitCode {
    let mut state = match state::load(state_file) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "state file refused");
            return ExitCode::from(EXIT_USAGE);
        }
    };
    let mut sink = LogSink { state_file };

    if cli.once {
        return match run_pass(l1, rollup, config, &mut state, &mut sink).await {
            Ok(report) => {
                summarise(&report);
                if report.alarm_count > 0 {
                    ExitCode::from(EXIT_ALARM)
                } else if report.blind {
                    ExitCode::from(EXIT_RETRY)
                } else {
                    ExitCode::SUCCESS
                }
            }
            Err(e) => {
                failed(&e);
                ExitCode::from(EXIT_RETRY)
            }
        };
    }

    let interval = Duration::from_secs(cli.poll_interval_secs.max(1));
    loop {
        match run_pass(l1, rollup, config, &mut state, &mut sink).await {
            Ok(report) => summarise(&report),
            Err(e) => {
                failed(&e);
                // Resume from what was committed, not from what was in memory.
                if let Ok(reloaded) = state::load(state_file) {
                    state = reloaded;
                }
            }
        }
        tokio::select! {
            () = tokio::time::sleep(interval) => {}
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("interrupted; exiting");
                return ExitCode::SUCCESS;
            }
        }
    }
}

fn summarise(report: &PassReport) {
    if report.blind {
        tracing::error!(
            l1_level = report.l1_finalized_level,
            rollup_finalized_level = report.rollup_finalized_level,
            deferred_count = report.deferred.len(),
            "the rollup node trails L1 too far: fast payouts past its finalised level are unchecked"
        );
    }
    tracing::info!(
        l1_level = report.l1_finalized_level,
        rollup_finalized_level = report.rollup_finalized_level,
        alarm_count = report.alarm_count,
        deferred_count = report.deferred.len(),
        "pass complete"
    );
}

fn failed(error: &PassError) {
    tracing::error!(error = %error, "pass stopped; the next one resumes from the state file");
}
