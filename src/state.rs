//! Persistent state: the plant registry and the alert log.
//!
//! The registry never stores planted values, only ids, paths and hashes, so
//! reading it does not put a matchable token into an agent's context.

use std::ffi::CStr;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::matcher::Encoding;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Env,
    Aws,
    Npm,
    Ssh,
    /// A file planted alongside tokens that holds none, such as `.aws/config`.
    #[value(skip)]
    Support,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenField {
    pub id: String,
    pub field: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlantedFile {
    pub path: PathBuf,
    pub kind: Kind,
    pub sha256: String,
    pub tokens: Vec<TokenField>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Plant {
    pub id: String,
    pub created: String,
    pub root: PathBuf,
    pub files: Vec<PlantedFile>,
    /// Directories this plant created, parents before children.
    pub created_dirs: Vec<PathBuf>,
    pub listen: Option<u16>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Registry {
    pub plants: Vec<Plant>,
}

/// Where a registered token lives.
#[derive(Debug, Clone, Copy)]
pub struct Location<'a> {
    pub plant: &'a Plant,
    pub file: &'a PlantedFile,
    pub field: &'a str,
}

impl Registry {
    pub fn lookup(&self, id: &str) -> Option<Location<'_>> {
        self.files().find_map(|(plant, file)| {
            file.tokens.iter().find(|t| t.id == id).map(|t| Location {
                plant,
                file,
                field: &t.field,
            })
        })
    }

    pub fn has_id(&self, id: &str) -> bool {
        self.lookup(id).is_some()
    }

    /// Every planted file across all plants.
    pub fn files(&self) -> impl Iterator<Item = (&Plant, &PlantedFile)> {
        self.plants
            .iter()
            .flat_map(|p| p.files.iter().map(move |f| (p, f)))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AlertKind {
    Exfil,
    Use,
    Read,
    ReadAttempt,
    Modified,
    Deleted,
    Disclosed,
    Mention,
    Unregistered,
}

impl AlertKind {
    pub fn as_str(self) -> &'static str {
        match self {
            AlertKind::Exfil => "exfil",
            AlertKind::Use => "use",
            AlertKind::Read => "read",
            AlertKind::ReadAttempt => "read-attempt",
            AlertKind::Modified => "modified",
            AlertKind::Deleted => "deleted",
            AlertKind::Disclosed => "disclosed",
            AlertKind::Mention => "mention",
            AlertKind::Unregistered => "unregistered",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Alert {
    pub time: String,
    pub kind: Option<AlertKind>,
    pub source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plant_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encoding: Option<Encoding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process: Option<String>,
    /// Redacted context; never contains a token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl Alert {
    pub fn new(kind: AlertKind, source: &str) -> Alert {
        Alert {
            time: now_rfc3339(),
            kind: Some(kind),
            source: source.to_string(),
            ..Alert::default()
        }
    }

    /// Fills token, plant, file and field from the registry. Ids that are not
    /// registered turn the alert into `unregistered`.
    pub fn with_token(mut self, registry: &Registry, id: &str, encoding: Encoding) -> Alert {
        self.token_id = Some(id.to_string());
        self.encoding = Some(encoding);
        match registry.lookup(id) {
            Some(loc) => {
                self.plant_id = Some(loc.plant.id.clone());
                self.file = Some(loc.file.path.clone());
                self.field = Some(loc.field.to_string());
            }
            None => self.kind = Some(AlertKind::Unregistered),
        }
        self
    }

    /// One human-readable line.
    pub fn summary(&self) -> String {
        let mut parts = vec![
            self.time.clone(),
            self.kind.map_or("?", AlertKind::as_str).to_uppercase(),
            format!("[{}]", self.source),
        ];
        if let Some(id) = &self.token_id {
            parts.push(format!("token {id}"));
        }
        if let Some(plant) = &self.plant_id {
            parts.push(format!("plant {plant}"));
        }
        if let Some(file) = &self.file {
            let field = self
                .field
                .as_deref()
                .map(|f| format!(" ({f})"))
                .unwrap_or_default();
            parts.push(format!("{}{field}", file.display()));
        }
        if let Some(enc) = self.encoding.filter(|e| *e != Encoding::Raw) {
            parts.push(format!("encoded {}", enc.as_str()));
        }
        if let Some(tool) = &self.tool {
            parts.push(format!("tool {tool}"));
        }
        if let Some(process) = &self.process {
            parts.push(format!("process {process}"));
        }
        if let Some(detail) = &self.detail {
            parts.push(format!("— {detail}"));
        }
        parts.join(" ")
    }
}

pub struct State {
    dir: PathBuf,
}

/// Held while the registry is being changed; see [`State::lock`].
pub struct RegistryLock {
    _file: std::fs::File,
}

impl State {
    pub fn at(dir: impl Into<PathBuf>) -> State {
        State { dir: dir.into() }
    }

    /// `$TRIPWIRE_STATE_DIR`, else `$XDG_STATE_HOME/agent-tripwire`, else
    /// `<real home>/.local/state/agent-tripwire`.
    pub fn locate() -> Result<State> {
        if let Some(dir) = std::env::var_os("TRIPWIRE_STATE_DIR").filter(|d| !d.is_empty()) {
            return Ok(State::at(dir));
        }
        if let Some(dir) = std::env::var_os("XDG_STATE_HOME").filter(|d| !d.is_empty()) {
            return Ok(State::at(Path::new(&dir).join("agent-tripwire")));
        }
        Ok(State::at(real_home()?.join(".local/state/agent-tripwire")))
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn registry_path(&self) -> PathBuf {
        self.dir.join("registry.json")
    }

    pub fn alerts_path(&self) -> PathBuf {
        self.dir.join("alerts.jsonl")
    }

    fn ensure_dir(&self) -> Result<()> {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&self.dir)
            .with_context(|| format!("creating state directory {}", self.dir.display()))
    }

    /// Exclusive lock for a load-modify-save of the registry, released on
    /// drop. Readers do not lock: saves replace the file atomically.
    pub fn lock(&self) -> Result<RegistryLock> {
        self.ensure_dir()?;
        let path = self.dir.join("registry.lock");
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(&path)
            .with_context(|| format!("opening {}", path.display()))?;
        file.lock()
            .with_context(|| format!("locking {}", path.display()))?;
        Ok(RegistryLock { _file: file })
    }

    pub fn load_registry(&self) -> Result<Registry> {
        let path = self.registry_path();
        match fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .with_context(|| format!("parsing {}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Registry::default()),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }

    pub fn save_registry(&self, registry: &Registry) -> Result<()> {
        self.ensure_dir()?;
        let path = self.registry_path();
        let tmp = self
            .dir
            .join(format!("registry.json.{}.tmp", std::process::id()));
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .with_context(|| format!("writing {}", tmp.display()))?;
        serde_json::to_writer_pretty(&mut file, registry)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        fs::rename(&tmp, &path).with_context(|| format!("replacing {}", path.display()))
    }

    pub fn append_alert(&self, alert: &Alert) -> Result<()> {
        self.ensure_dir()?;
        let mut line = serde_json::to_vec(alert)?;
        line.push(b'\n');
        let path = self.alerts_path();
        OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .open(&path)
            .and_then(|mut f| f.write_all(&line))
            .with_context(|| format!("appending to {}", path.display()))
    }

    /// Alerts in log order. Lines that do not parse are skipped.
    pub fn read_alerts(&self) -> Result<Vec<Alert>> {
        let path = self.alerts_path();
        let text = match fs::read_to_string(&path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        Ok(text
            .lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect())
    }
}

/// The current user's home directory from the password database. `$HOME` is
/// deliberately ignored because a sandbox overrides it.
pub fn real_home() -> Result<PathBuf> {
    let mut buf = vec![0 as libc::c_char; 16 * 1024];
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: every pointer refers to live, correctly sized storage owned by
    // this frame, and `pw_dir` is read only while `buf` is alive.
    let rc = unsafe {
        libc::getpwuid_r(
            libc::getuid(),
            &mut pwd,
            buf.as_mut_ptr(),
            buf.len(),
            &mut result,
        )
    };
    if rc != 0 || result.is_null() || pwd.pw_dir.is_null() {
        bail!("cannot read the home directory from the password database");
    }
    let dir = unsafe { CStr::from_ptr(pwd.pw_dir) };
    Ok(PathBuf::from(dir.to_string_lossy().into_owned()))
}

pub fn now_rfc3339() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    rfc3339(secs)
}

/// UTC timestamp `YYYY-MM-DDTHH:MM:SSZ` for seconds since the Unix epoch.
pub fn rfc3339(secs: u64) -> String {
    let (days, rem) = (secs / 86_400, secs % 86_400);
    // Civil-from-days, after Howard Hinnant's date algorithms.
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_registry() -> Registry {
        Registry {
            plants: vec![Plant {
                id: "p-abc123".into(),
                created: "2026-11-12T00:00:00Z".into(),
                root: "/sandbox".into(),
                files: vec![PlantedFile {
                    path: "/sandbox/.aws/credentials".into(),
                    kind: Kind::Aws,
                    sha256: "00".into(),
                    tokens: vec![
                        TokenField {
                            id: "AAAAAAAA".into(),
                            field: "aws_access_key_id".into(),
                        },
                        TokenField {
                            id: "BBBBBBBB".into(),
                            field: "aws_secret_access_key".into(),
                        },
                    ],
                }],
                created_dirs: vec!["/sandbox/.aws".into()],
                listen: None,
            }],
        }
    }

    #[test]
    fn lookup_finds_file_and_field() {
        let reg = sample_registry();
        let loc = reg.lookup("BBBBBBBB").unwrap();
        assert_eq!(loc.plant.id, "p-abc123");
        assert_eq!(loc.file.path, Path::new("/sandbox/.aws/credentials"));
        assert_eq!(loc.field, "aws_secret_access_key");
        assert!(reg.lookup("CCCCCCCC").is_none());
    }

    #[test]
    fn missing_registry_loads_empty() {
        let dir = tempfile::tempdir().unwrap();
        let state = State::at(dir.path().join("state"));
        assert_eq!(state.load_registry().unwrap(), Registry::default());
    }

    #[test]
    fn registry_round_trips_and_creates_dir() {
        let dir = tempfile::tempdir().unwrap();
        let state = State::at(dir.path().join("nested/state"));
        state.save_registry(&sample_registry()).unwrap();
        assert_eq!(state.load_registry().unwrap(), sample_registry());
    }

    #[test]
    fn alerts_append_and_read_back() {
        let dir = tempfile::tempdir().unwrap();
        let state = State::at(dir.path());
        let reg = sample_registry();
        let a = Alert::new(AlertKind::Read, "hook").with_token(&reg, "AAAAAAAA", Encoding::Raw);
        let b = Alert::new(AlertKind::Exfil, "scan").with_token(&reg, "ZZZZZZZZ", Encoding::Hex);
        state.append_alert(&a).unwrap();
        state.append_alert(&b).unwrap();
        let read = state.read_alerts().unwrap();
        assert_eq!(read, vec![a.clone(), b.clone()]);
        assert_eq!(read[0].field.as_deref(), Some("aws_access_key_id"));
        assert_eq!(read[1].kind, Some(AlertKind::Unregistered));
    }

    #[test]
    fn missing_alert_log_reads_empty() {
        let dir = tempfile::tempdir().unwrap();
        assert!(State::at(dir.path()).read_alerts().unwrap().is_empty());
    }

    #[test]
    fn formats_utc_timestamps() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(rfc3339(1_794_485_703), "2026-11-12T12:15:03Z");
    }

    #[test]
    fn real_home_is_absolute() {
        assert!(real_home().unwrap().is_absolute());
    }
}
