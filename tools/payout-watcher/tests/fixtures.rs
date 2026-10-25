//! The fixture runs: every case of `fixtures/cases.rs` is pinned to its
//! checked-in files under `testdata/<case>/` (so a reader can run the same
//! `--once` by hand), then run through the real binary against them, and the
//! exit status and the `alarm` kinds of its JSON lines compared with what the
//! case expects.
//!
//! Regenerate the checked-in files after a deliberate change with
//! `PAYOUT_WATCHER_REGENERATE=1 cargo test -p payout-watcher --test fixtures`.

#[path = "fixtures/cases.rs"]
mod cases;
#[path = "fixtures/chain.rs"]
mod chain;

use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Command;

fn testdata() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata")
}

fn pretty(value: &Value) -> String {
    let mut text = serde_json::to_string_pretty(value).expect("json");
    text.push('\n');
    text
}

fn expected_json(case: &cases::Case) -> Value {
    serde_json::json!({ "exit_code": case.exit_code, "alarms": case.alarms })
}

/// The case's three files, as they must be on disk.
fn files(case: &cases::Case) -> Vec<(PathBuf, String)> {
    let dir = testdata().join(case.name);
    vec![
        (dir.join("config.toml"), case.config.clone()),
        (dir.join("snapshot.json"), pretty(&case.snapshot)),
        (dir.join("expected.json"), pretty(&expected_json(case))),
    ]
}

struct Run {
    exit_code: i32,
    alarms: Vec<String>,
    lines: Vec<Value>,
    state: Value,
}

fn run_once(dir: &Path, scratch: &Path) -> Run {
    let state = scratch.join("state.json");
    let _ = std::fs::remove_file(&state);
    let output = Command::new(env!("CARGO_BIN_EXE_payout-watcher"))
        .arg("--config")
        .arg(dir.join("config.toml"))
        .arg("--snapshot")
        .arg(dir.join("snapshot.json"))
        .env("APP__STATE_FILE", &state)
        .arg("--once")
        .env("RUST_LOG", "info")
        .output()
        .expect("the binary runs");
    let lines: Vec<Value> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();
    let mut alarms: Vec<String> = lines
        .iter()
        .filter(|l| l["level"] == "ERROR")
        .filter_map(|l| l["alarm"].as_str().map(str::to_string))
        .collect();
    alarms.sort();
    let state = std::fs::read(&state)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or(Value::Null);

    Run {
        exit_code: output.status.code().expect("exited"),
        alarms,
        lines,
        state,
    }
}

fn scratch_dir(name: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("payout-watcher-test-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

#[tokio::test]
async fn the_checked_in_fixtures_are_the_generated_ones() {
    let regenerate = std::env::var_os("PAYOUT_WATCHER_REGENERATE").is_some();
    let mut stale = Vec::new();

    for case in cases::all().await {
        for (path, content) in files(&case) {
            if regenerate {
                std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                std::fs::write(&path, &content).unwrap();
            } else if std::fs::read_to_string(&path).ok().as_deref() != Some(content.as_str()) {
                stale.push(path.display().to_string());
            }
        }
    }

    assert!(
        stale.is_empty(),
        "stale fixtures (regenerate with PAYOUT_WATCHER_REGENERATE=1): {stale:#?}"
    );
}

#[tokio::test]
async fn every_case_reproduces_its_alarms_and_exit_status() {
    for case in cases::all().await {
        let scratch = scratch_dir(case.name);
        let run = run_once(&testdata().join(case.name), &scratch);
        let expected: Vec<String> = case.alarms.iter().map(|s| s.to_string()).collect();

        assert_eq!(run.alarms, expected, "{}: {:#?}", case.name, run.lines);
        assert_eq!(
            run.exit_code, case.exit_code,
            "{}: {:#?}",
            case.name, run.lines
        );
        // Every alarm carries the canonical scope fields.
        for line in run.lines.iter().filter(|l| l["alarm"].is_string()) {
            if line["alarm"] == "kernel_identity_mismatch" {
                continue;
            }
            assert_eq!(line["tenant_id"], "golden-tenant", "{}: {line}", case.name);
            assert_eq!(line["pool_id"], "golden-pool", "{}: {line}", case.name);
            assert!(line["l1_level"].is_i64(), "{}: {line}", case.name);
            assert!(line.get("level").is_some());
        }
        let _ = std::fs::remove_dir_all(&scratch);
    }
}

#[tokio::test]
async fn an_alarm_names_the_session_the_amounts_and_the_operation() {
    let scratch = scratch_dir("overpayment-fields");
    let run = run_once(&testdata().join("overpayment"), &scratch);
    let line = run
        .lines
        .iter()
        .find(|l| l["alarm"] == "fast_payout_above_kernel")
        .expect("the alarm line");

    assert_eq!(line["session_id"], "01020304-0506-0708-090a-0b0c0d0e0f10");
    assert_eq!(line["amount_mutez"], "1500000");
    assert_eq!(line["kernel_amount_mutez"], "1000000");
    assert_eq!(
        line["vault_address"],
        "KT1BuEZtb68c1Q4yjtckcNjGELqWt56Xyesc"
    );
    assert_eq!(line["l1_level"], 105);
    assert_eq!(line["reference"], chain::operation_hash(1));
    let _ = std::fs::remove_dir_all(&scratch);
}

#[tokio::test]
async fn a_deferred_level_keeps_the_cursor_and_a_rerun_resumes_there() {
    let scratch = scratch_dir("deferred-cursor");
    let deferred = run_once(&testdata().join("deferred"), &scratch);
    let vault = "KT1BuEZtb68c1Q4yjtckcNjGELqWt56Xyesc";

    assert_eq!(deferred.state["vaults"][vault]["next_level"], 105);
    assert!(
        deferred.lines.iter().any(|l| l["level"] == "WARN"
            && l["message"]
                .as_str()
                .is_some_and(|m| m.starts_with("deferred"))),
        "{:#?}",
        deferred.lines
    );

    // A clean run checks through the head and records the replayed ledger.
    let clean = run_once(&testdata().join("clean"), &scratch);
    assert_eq!(clean.state["vaults"][vault]["next_level"], 131);
    assert_eq!(
        clean.state["vaults"][vault]["paid"]["0102030405060708090a0b0c0d0e0f10"],
        "1500000"
    );
    let _ = std::fs::remove_dir_all(&scratch);
}

#[test]
fn a_resumed_run_does_not_raise_an_alarm_twice() {
    let scratch = scratch_dir("resume");
    let state = scratch.join("state.json");
    let dir = testdata().join("overpayment");
    let run = |state: &Path| {
        Command::new(env!("CARGO_BIN_EXE_payout-watcher"))
            .args(["--once", "--config"])
            .arg(dir.join("config.toml"))
            .arg("--snapshot")
            .arg(dir.join("snapshot.json"))
            .env("APP__STATE_FILE", state)
            .stdout(std::process::Stdio::null())
            .status()
            .expect("runs")
            .code()
    };

    assert_eq!(run(&state), Some(1), "the first pass alarms");
    assert_eq!(
        run(&state),
        Some(0),
        "the second resumes past the alarmed level"
    );
    let _ = std::fs::remove_dir_all(&scratch);
}
