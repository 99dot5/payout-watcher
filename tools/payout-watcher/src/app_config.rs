//! The watcher's configuration, loaded the way the repository's services load
//! theirs (the `config` crate): a file, then `APP__`-prefixed environment
//! variables over it. Nothing has a default address: the vaults, the L1 RPC
//! and the rollup node are the runner's choice.
//!
//! The file is TOML, YAML or JSON, chosen by its extension:
//!
//! ```toml
//! l1_node_url = "http://127.0.0.1:8732"
//! rollup_node_url = "http://127.0.0.1:8932"
//! state_file = "payout-watcher-state.json"
//! max_rollup_lag_levels = 60
//!
//! [kernel]                       # optional pins
//! expected_version = "0.8.10"
//! expected_root_hash = "00…"     # 66 hex characters
//!
//! [[vaults]]
//! address = "KT1…"
//! start_level = 1234567          # the vault's origination level
//! expected_payout_signers = ["sppk…", "sppk…", "edpk…", "edpk…"]   # optional
//! ```
//!
//! Any scalar can be overridden from the environment, sections joined by a
//! double underscore: `APP__ROLLUP_NODE_URL`, `APP__STATE_FILE`,
//! `APP__KERNEL__EXPECTED_ROOT_HASH`. The vault list stays in the file.

use crate::kernel::KernelPin;
use crate::watcher::{WatchConfig, WatchedVault};
use config::{Config, Environment, File, FileFormat};
use octez_rpc::NodeUrl;
use payout_protocol::VaultAddress;
use payout_protocol::kernel_identity::parse_root_hash;
use serde::Deserialize;
use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use tezos_wallet_signature::decode_public_key;

/// The default lag past which a pass that had to defer reports itself blind.
pub const DEFAULT_MAX_ROLLUP_LAG_LEVELS: i64 = 60;

/// The configuration as loaded. The root accepts unknown keys, because the
/// `APP__` environment of a shared host may carry another service's; the
/// sections refuse them, so a mistyped field fails at load.
#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    /// The L1 node.
    #[serde(default)]
    pub l1_node_url: Option<NodeUrl>,
    #[serde(default)]
    pub rollup_node_url: Option<NodeUrl>,
    pub state_file: Option<PathBuf>,
    pub max_rollup_lag_levels: Option<i64>,
    #[serde(default)]
    pub kernel: Option<KernelSection>,
    #[serde(default)]
    pub vaults: Vec<VaultSection>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelSection {
    pub expected_version: Option<String>,
    pub expected_root_hash: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultSection {
    pub address: String,
    pub start_level: i64,
    pub expected_payout_signers: Option<Vec<String>>,
}

/// The `APP__` environment layer, as the services build it.
fn environment() -> Environment {
    Environment::with_prefix("APP")
        .prefix_separator("__")
        .separator("__")
}

impl AppConfig {
    /// Load `path`, then the process's `APP__` environment over it.
    pub fn load(path: &Path) -> Result<Self, String> {
        Self::build(File::from(path).required(true), environment())
            .map_err(|e| format!("{}: {e}", path.display()))
    }

    /// Load from a file's text and an explicit environment map, through the
    /// same layers as [`Self::load`]; for tests that must not read the
    /// process environment.
    pub fn from_parts(
        text: &str,
        format: FileFormat,
        env: &[(&str, &str)],
    ) -> Result<Self, String> {
        let map: HashMap<String, String> = env
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();

        Self::build(
            File::from_str(text, format),
            environment().source(Some(map)),
        )
        .map_err(|e| e.to_string())
    }

    fn build<F>(file: F, env: Environment) -> Result<Self, config::ConfigError>
    where
        F: config::Source + Send + Sync + 'static,
    {
        Config::builder()
            .add_source(file)
            .add_source(env)
            .build()?
            .try_deserialize()
    }

    /// Validate and lower to what a pass needs: every vault a `KT1…` by
    /// prefix, every expected signer a key, the root hash 33 tagged bytes.
    pub fn watch_config(&self) -> Result<WatchConfig, String> {
        if self.vaults.is_empty() {
            return Err("the config lists no [[vaults]]".to_string());
        }
        let mut seen = BTreeSet::new();
        let mut vaults = Vec::new();
        for v in &self.vaults {
            VaultAddress::parse(&v.address).map_err(|e| e.to_string())?;
            if !seen.insert(v.address.clone()) {
                return Err(format!("vault {} is listed twice", v.address));
            }
            if v.start_level < 1 {
                return Err(format!("vault {}: start_level must be positive", v.address));
            }
            let expected = v
                .expected_payout_signers
                .as_ref()
                .map(|keys| {
                    keys.iter()
                        .map(|k| {
                            decode_public_key(k)
                                .map(|_| k.clone())
                                .map_err(|e| format!("vault {}: '{k}': {e}", v.address))
                        })
                        .collect::<Result<BTreeSet<_>, _>>()
                })
                .transpose()?;
            vaults.push(WatchedVault {
                address: v.address.clone(),
                start_level: v.start_level,
                expected_payout_signers: expected,
            });
        }
        let kernel = match &self.kernel {
            None => KernelPin::default(),
            Some(k) => KernelPin {
                version: k.expected_version.clone(),
                root_hash: k
                    .expected_root_hash
                    .as_deref()
                    .map(parse_root_hash)
                    .transpose()
                    .map_err(|e| e.to_string())?,
            },
        };

        Ok(WatchConfig {
            vaults,
            kernel,
            max_rollup_lag_levels: self
                .max_rollup_lag_levels
                .unwrap_or(DEFAULT_MAX_ROLLUP_LAG_LEVELS),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VAULT: &str = "KT1BuEZtb68c1Q4yjtckcNjGELqWt56Xyesc";

    fn toml(text: &str, env: &[(&str, &str)]) -> Result<WatchConfig, String> {
        AppConfig::from_parts(text, FileFormat::Toml, env)?.watch_config()
    }

    fn minimal() -> String {
        format!("[[vaults]]\naddress = \"{VAULT}\"\nstart_level = 10\n")
    }

    #[test]
    fn a_minimal_config_lowers() {
        let config = toml(&minimal(), &[]).unwrap();

        assert_eq!(config.vaults.len(), 1);
        assert_eq!(config.max_rollup_lag_levels, DEFAULT_MAX_ROLLUP_LAG_LEVELS);
        assert_eq!(config.kernel, KernelPin::default());
    }

    #[test]
    fn app_environment_variables_override_the_file() {
        let text = format!(
            "rollup_node_url = \"http://file:8932\"\nmax_rollup_lag_levels = 5\n{}",
            minimal()
        );
        let loaded = AppConfig::from_parts(
            &text,
            FileFormat::Toml,
            &[
                ("APP__ROLLUP_NODE_URL", "http://env:8932"),
                ("APP__STATE_FILE", "/var/lib/watcher/state.json"),
                ("APP__MAX_ROLLUP_LAG_LEVELS", "90"),
                ("APP__KERNEL__EXPECTED_VERSION", "0.8.10"),
                // Another service's variable on a shared host is ignored.
                ("APP__DB__URL", "postgres://elsewhere"),
            ],
        )
        .unwrap();

        assert_eq!(
            loaded.rollup_node_url.as_ref().map(NodeUrl::as_str),
            Some("http://env:8932/")
        );
        assert_eq!(
            loaded.state_file.as_deref(),
            Some(Path::new("/var/lib/watcher/state.json"))
        );
        let lowered = loaded.watch_config().unwrap();
        assert_eq!(lowered.max_rollup_lag_levels, 90);
        assert_eq!(lowered.kernel.version.as_deref(), Some("0.8.10"));
    }

    #[test]
    fn the_node_urls_load_validated() {
        let text = format!(
            "l1_node_url = \"http://127.0.0.1:8732\"\nrollup_node_url = \"https://node.example/rpc\"\n{}",
            minimal()
        );
        let loaded = AppConfig::from_parts(&text, FileFormat::Toml, &[]).unwrap();

        assert_eq!(
            loaded.l1_node_url.as_ref().map(NodeUrl::as_str),
            Some("http://127.0.0.1:8732/")
        );
        assert_eq!(
            loaded.rollup_node_url.as_ref().map(NodeUrl::as_str),
            Some("https://node.example/rpc")
        );

        let neither = AppConfig::from_parts(&minimal(), FileFormat::Toml, &[]).unwrap();

        assert!(neither.l1_node_url.is_none());
        assert!(neither.rollup_node_url.is_none());
    }

    #[test]
    fn an_l1_node_url_that_is_not_a_node_url_is_refused_naming_the_field() {
        let text = format!("l1_node_url = \"ftp://x\"\n{}", minimal());
        let error = AppConfig::from_parts(&text, FileFormat::Toml, &[]).unwrap_err();

        assert!(error.contains("for key `l1_node_url`"), "{error}");
        assert!(error.contains("ftp://x/"), "{error}");
        assert!(error.contains("scheme"), "{error}");
    }

    #[test]
    fn a_rollup_node_url_override_that_is_not_a_node_url_is_refused_naming_the_field() {
        let error = AppConfig::from_parts(
            &minimal(),
            FileFormat::Toml,
            &[("APP__ROLLUP_NODE_URL", "http://x?a=1")],
        )
        .unwrap_err();

        assert!(error.contains("for key `rollup_node_url`"), "{error}");
        assert!(error.contains("http://x/?a=1"), "{error}");
        assert!(error.contains("query"), "{error}");
    }

    #[test]
    fn the_same_config_reads_from_yaml() {
        let yaml = format!("vaults:\n  - address: {VAULT}\n    start_level: 10\n");
        let config = AppConfig::from_parts(&yaml, FileFormat::Yaml, &[])
            .unwrap()
            .watch_config()
            .unwrap();

        assert_eq!(config.vaults[0].start_level, 10);
    }

    #[test]
    fn a_bad_vault_signer_or_hash_is_refused() {
        let refuse = |text: &str| toml(text, &[]).is_err();

        assert!(refuse("vaults = []\n"));
        assert!(refuse(
            "[[vaults]]\naddress = \"tz1UyQDepgtUBnWjyzzonqeDwaiWoQzRKSP5\"\nstart_level = 1\n"
        ));
        assert!(refuse(&format!("{}{}", minimal(), minimal())));
        assert!(refuse(&format!(
            "[[vaults]]\naddress = \"{VAULT}\"\nstart_level = 1\nexpected_payout_signers = [\"{VAULT}\"]\n"
        )));
        assert!(refuse(&format!(
            "[kernel]\nexpected_root_hash = \"01\"\n{}",
            minimal()
        )));
        assert!(refuse(&format!(
            "[[vaults]]\naddress = \"{VAULT}\"\nstart_level = 1\nstart_levle = 2\n"
        )));
        assert!(
            toml(&minimal(), &[("APP__KERNEL__EXPECTED_ROOT_HASH", "01")]).is_err(),
            "an environment override is validated like the file"
        );
    }
}
