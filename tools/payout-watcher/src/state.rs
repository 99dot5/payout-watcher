//! The watcher's state file: a cursor per vault, the paid ledger it has
//! replayed, and the signer set it last saw. Written atomically (a temporary
//! file renamed over the old one) after every level, so a run that stops for
//! any reason resumes at the first level it had not finished.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::Path;

/// Everything the watcher remembers between runs.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    #[serde(default)]
    pub vaults: BTreeMap<String, VaultState>,
}

/// One vault's progress.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultState {
    /// The first L1 level not yet checked.
    pub next_level: i64,
    /// The paid ledger replayed from this vault's events: session id (32 hex
    /// characters) → total paid, in mutez, as a decimal string.
    #[serde(default)]
    pub paid: BTreeMap<String, String>,
    /// The `payout_signers` last seen, as base58check keys.
    #[serde(default)]
    pub payout_signers: Option<BTreeSet<String>>,
}

impl VaultState {
    pub fn new(next_level: i64) -> Self {
        Self {
            next_level,
            paid: BTreeMap::new(),
            payout_signers: None,
        }
    }

    /// The replayed total for `session_id`; zero when nothing was paid.
    pub fn paid(&self, session_id: &[u8; 16]) -> io::Result<u128> {
        match self.paid.get(&hex::encode(session_id)) {
            None => Ok(0),
            Some(text) => text.parse().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("state: '{text}' is not a mutez amount"),
                )
            }),
        }
    }

    pub fn set_paid(&mut self, session_id: &[u8; 16], total: u128) {
        self.paid.insert(hex::encode(session_id), total.to_string());
    }
}

/// Read the state file; a missing file is an empty state.
pub fn load(path: &Path) -> io::Result<State> {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("state file: {e}"))),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(State::default()),
        Err(e) => Err(e),
    }
}

/// Write the state file atomically.
pub fn save(path: &Path, state: &State) -> io::Result<()> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = std::path::PathBuf::from(tmp);
    let mut text = serde_json::to_vec_pretty(state)?;
    text.push(b'\n');
    std::fs::write(&tmp, text)?;

    std::fs::rename(&tmp, path)
}
