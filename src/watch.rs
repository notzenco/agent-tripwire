//! File-access monitoring of planted files, and live transcript tailing.
//!
//! Reads are detected with inotify on Linux and with access-time arming
//! elsewhere (see `docs/design.md`). Modification and deletion are detected by
//! polling metadata on every platform.

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{ErrorKind, Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use anyhow::Result;

use crate::plant::arm_atime;
use crate::scan::{collect_paths, scan_line};
use crate::state::{Alert, AlertKind, Registry, State};

/// Re-list transcript directories every this many polls.
const RESCAN_EVERY: u32 = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    Inotify,
    Atime,
}

struct Watched {
    plant_id: String,
    size: u64,
    mtime: (i64, i64),
    gone: bool,
}

pub struct Watcher {
    state: State,
    registry: Registry,
    registry_stamp: Option<SystemTime>,
    files: HashMap<PathBuf, Watched>,
    #[cfg(target_os = "linux")]
    inotify: Option<linux::Reads>,
    transcript_dirs: Vec<PathBuf>,
    offsets: HashMap<PathBuf, u64>,
    polls: u32,
}

impl Watcher {
    pub fn new(state: State, transcript_dirs: Vec<PathBuf>) -> Result<Watcher> {
        let mut watcher = Watcher {
            state,
            registry: Registry::default(),
            registry_stamp: None,
            files: HashMap::new(),
            #[cfg(target_os = "linux")]
            inotify: None,
            transcript_dirs,
            offsets: HashMap::new(),
            polls: 0,
        };
        watcher.reload()?;
        // Existing transcript content is history, not a new event.
        for path in watcher.transcript_files() {
            let len = fs::metadata(&path).map_or(0, |m| m.len());
            watcher.offsets.insert(path, len);
        }
        Ok(watcher)
    }

    pub fn backend(&self) -> Backend {
        #[cfg(target_os = "linux")]
        if self.inotify.is_some() {
            return Backend::Inotify;
        }
        Backend::Atime
    }

    pub fn file_count(&self) -> usize {
        self.files.len()
    }

    /// Alerts since the previous poll.
    pub fn poll(&mut self) -> Vec<Alert> {
        self.polls = self.polls.wrapping_add(1);
        if self.registry_changed()
            && let Err(e) = self.reload()
        {
            eprintln!("tripwire watch: reloading registry: {e:#}");
        }
        let mut alerts = self.poll_files();
        alerts.extend(self.poll_transcripts());
        alerts
    }

    fn registry_changed(&self) -> bool {
        registry_stamp(&self.state) != self.registry_stamp
    }

    /// Loads the registry and starts watching any new files. Files already
    /// watched keep their baseline.
    fn reload(&mut self) -> Result<()> {
        self.registry_stamp = registry_stamp(&self.state);
        self.registry = self.state.load_registry()?;
        let mut files = HashMap::new();
        for (plant, file) in self.registry.files() {
            let watched = match self.files.remove(&file.path) {
                Some(existing) => existing,
                None => {
                    // Arm before taking the baseline so arming is not a change.
                    let _ = arm_atime(&file.path);
                    let meta = fs::symlink_metadata(&file.path).ok();
                    Watched {
                        plant_id: plant.id.clone(),
                        size: meta.as_ref().map_or(0, |m| m.len()),
                        mtime: meta.as_ref().map_or((0, 0), mtime),
                        gone: meta.is_none(),
                    }
                }
            };
            files.insert(file.path.clone(), watched);
        }
        self.files = files;
        #[cfg(target_os = "linux")]
        {
            self.inotify = linux::Reads::new(self.files.keys());
        }
        Ok(())
    }

    fn poll_files(&mut self) -> Vec<Alert> {
        #[cfg(target_os = "linux")]
        let inotify_reads = self.inotify.as_mut().map(linux::Reads::drain);

        let mut alerts = Vec::new();
        let mut paths: Vec<_> = self.files.keys().cloned().collect();
        paths.sort();
        for path in paths {
            let watched = self.files.get_mut(&path).expect("key from map");
            let alert = |kind| {
                let mut a = Alert::new(kind, "watch");
                a.plant_id = Some(watched.plant_id.clone());
                a.file = Some(path.clone());
                a
            };
            let meta = match fs::symlink_metadata(&path) {
                Ok(meta) => meta,
                Err(e) if e.kind() == ErrorKind::NotFound => {
                    if !watched.gone {
                        watched.gone = true;
                        alerts.push(alert(AlertKind::Deleted));
                    }
                    continue;
                }
                Err(_) => continue,
            };
            let returned = std::mem::replace(&mut watched.gone, false);

            #[cfg(target_os = "linux")]
            let read = match &inotify_reads {
                Some(reads) => reads.contains(&path),
                None => meta.atime() > meta.mtime(),
            };
            #[cfg(not(target_os = "linux"))]
            let read = (meta.atime(), meta.atime_nsec()) > mtime(&meta);

            let changed = returned || meta.len() != watched.size || mtime(&meta) != watched.mtime;
            if read {
                let mut a = alert(AlertKind::Read);
                a.process = holders(&path);
                alerts.push(a);
            }
            if changed {
                watched.size = meta.len();
                watched.mtime = mtime(&meta);
                alerts.push(alert(AlertKind::Modified));
            }
            if read || changed {
                let _ = arm_atime(&path);
            }
        }
        alerts
    }

    fn transcript_files(&self) -> Vec<PathBuf> {
        if self.transcript_dirs.is_empty() {
            return Vec::new();
        }
        collect_paths(&self.transcript_dirs).unwrap_or_default()
    }

    fn poll_transcripts(&mut self) -> Vec<Alert> {
        if self.polls.is_multiple_of(RESCAN_EVERY) {
            for path in self.transcript_files() {
                self.offsets.entry(path).or_insert(0);
            }
        }
        let mut alerts = Vec::new();
        let mut paths: Vec<_> = self.offsets.keys().cloned().collect();
        paths.sort();
        for path in paths {
            let offset = self.offsets[&path];
            let Ok((lines, next)) = read_new_lines(&path, offset) else {
                continue;
            };
            self.offsets.insert(path.clone(), next);
            for line in lines {
                for finding in scan_line(&line, &self.registry) {
                    let mut a = Alert::new(finding.kind, "transcript").with_token(
                        &self.registry,
                        &finding.id,
                        finding.encoding,
                    );
                    a.detail = Some(format!(
                        "{} at {}: {}",
                        path.display(),
                        finding.location,
                        finding.excerpt
                    ));
                    alerts.push(a);
                }
            }
        }
        alerts
    }
}

fn registry_stamp(state: &State) -> Option<SystemTime> {
    fs::metadata(state.dir().join("registry.json"))
        .and_then(|m| m.modified())
        .ok()
}

fn mtime(meta: &fs::Metadata) -> (i64, i64) {
    (meta.mtime(), meta.mtime_nsec())
}

/// Complete lines appended since `offset`, and the offset after them. A
/// shorter file is treated as rewritten and read from the start.
fn read_new_lines(path: &Path, offset: u64) -> std::io::Result<(Vec<String>, u64)> {
    let mut file = File::open(path)?;
    let len = file.metadata()?.len();
    let start = if len < offset { 0 } else { offset };
    file.seek(SeekFrom::Start(start))?;
    let mut buf = Vec::new();
    file.take(len - start).read_to_end(&mut buf)?;
    let Some(end) = buf.iter().rposition(|&b| b == b'\n') else {
        return Ok((Vec::new(), start));
    };
    let text = String::from_utf8_lossy(&buf[..end]);
    let lines = text.lines().map(str::to_string).collect();
    Ok((lines, start + end as u64 + 1))
}

/// Best-effort list of processes holding `path` open (Linux only).
#[cfg(target_os = "linux")]
fn holders(path: &Path) -> Option<String> {
    let mut found = Vec::new();
    for entry in fs::read_dir("/proc").ok()?.flatten() {
        let pid = entry.file_name();
        let Some(pid) = pid
            .to_str()
            .filter(|p| p.bytes().all(|b| b.is_ascii_digit()))
        else {
            continue;
        };
        let Ok(fds) = fs::read_dir(entry.path().join("fd")) else {
            continue;
        };
        if fds
            .flatten()
            .any(|fd| fs::read_link(fd.path()).is_ok_and(|t| t == path))
        {
            let comm = fs::read_to_string(entry.path().join("comm")).unwrap_or_default();
            found.push(format!("{pid} ({})", comm.trim()));
        }
    }
    (!found.is_empty()).then(|| found.join(", "))
}

#[cfg(not(target_os = "linux"))]
fn holders(_: &Path) -> Option<String> {
    None
}

#[cfg(target_os = "linux")]
mod linux {
    use std::collections::{HashMap, HashSet};
    use std::path::PathBuf;

    use inotify::{Inotify, WatchDescriptor, WatchMask};

    /// inotify read events for planted files. `IN_ACCESS` fires when data is
    /// read, but not when a file is merely opened, written or stat'ed.
    pub struct Reads {
        inotify: Inotify,
        paths: HashMap<WatchDescriptor, PathBuf>,
    }

    impl Reads {
        pub fn new<'a>(files: impl Iterator<Item = &'a PathBuf>) -> Option<Reads> {
            let inotify = Inotify::init().ok()?;
            let mut paths = HashMap::new();
            for path in files {
                if let Ok(wd) = inotify.watches().add(path, WatchMask::ACCESS) {
                    paths.insert(wd, path.clone());
                }
            }
            Some(Reads { inotify, paths })
        }

        /// Paths read since the last drain.
        pub fn drain(&mut self) -> HashSet<PathBuf> {
            let mut out = HashSet::new();
            let mut buffer = [0u8; 4096];
            while let Ok(events) = self.inotify.read_events(&mut buffer) {
                let mut any = false;
                for event in events {
                    any = true;
                    if let Some(path) = self.paths.get(&event.wd) {
                        out.insert(path.clone());
                    }
                }
                if !any {
                    break;
                }
            }
            out
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plant::{PlantRequest, plant};
    use crate::state::Kind;
    use crate::token::{MARKER, new_id};
    use std::io::Write;
    use tempfile::TempDir;

    struct Env {
        _tmp: TempDir,
        base: PathBuf,
        state_dir: PathBuf,
    }

    fn env() -> Env {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().canonicalize().unwrap();
        fs::create_dir(base.join("home")).unwrap();
        Env {
            state_dir: base.join("state"),
            base,
            _tmp: tmp,
        }
    }

    impl Env {
        fn plant(&self, name: &str) -> PathBuf {
            let root = self.base.join(name);
            fs::create_dir(&root).unwrap();
            let req = PlantRequest {
                root: root.clone(),
                create_root: false,
                kinds: vec![Kind::Env],
                listen: None,
                real_home: self.base.join("home"),
                never_index: false,
            };
            plant(&State::at(&self.state_dir), &req).unwrap();
            root.join(".env")
        }

        fn watcher(&self, transcripts: Vec<PathBuf>) -> Watcher {
            Watcher::new(State::at(&self.state_dir), transcripts).unwrap()
        }
    }

    fn kinds(alerts: &[Alert]) -> Vec<AlertKind> {
        alerts.iter().filter_map(|a| a.kind).collect()
    }

    #[test]
    fn detects_each_read_once() {
        let env = env();
        let dotenv = env.plant("work");
        let mut w = env.watcher(vec![]);
        assert_eq!(w.file_count(), 1);
        assert!(w.poll().is_empty());

        fs::read(&dotenv).unwrap();
        let alerts = w.poll();
        assert_eq!(kinds(&alerts), vec![AlertKind::Read]);
        assert_eq!(alerts[0].file.as_deref(), Some(dotenv.as_path()));
        assert_eq!(alerts[0].source, "watch");
        assert!(alerts[0].plant_id.is_some());
        assert!(w.poll().is_empty());

        fs::read(&dotenv).unwrap();
        assert_eq!(kinds(&w.poll()), vec![AlertKind::Read]);
    }

    #[test]
    fn backend_matches_platform() {
        let env = env();
        env.plant("work");
        let expected = if cfg!(target_os = "linux") {
            Backend::Inotify
        } else {
            Backend::Atime
        };
        assert_eq!(env.watcher(vec![]).backend(), expected);
    }

    #[test]
    fn metadata_lookups_are_not_reads() {
        let env = env();
        let dotenv = env.plant("work");
        let mut w = env.watcher(vec![]);
        fs::metadata(&dotenv).unwrap();
        fs::read_dir(dotenv.parent().unwrap())
            .unwrap()
            .for_each(drop);
        assert!(w.poll().is_empty());
    }

    #[test]
    fn detects_modification_and_deletion() {
        let env = env();
        let dotenv = env.plant("work");
        let mut w = env.watcher(vec![]);
        fs::OpenOptions::new()
            .append(true)
            .open(&dotenv)
            .unwrap()
            .write_all(b"X=1\n")
            .unwrap();
        assert_eq!(kinds(&w.poll()), vec![AlertKind::Modified]);
        assert!(w.poll().is_empty());
        fs::remove_file(&dotenv).unwrap();
        assert_eq!(kinds(&w.poll()), vec![AlertKind::Deleted]);
        assert!(w.poll().is_empty());
    }

    #[test]
    fn picks_up_plants_added_after_start() {
        let env = env();
        env.plant("first");
        let mut w = env.watcher(vec![]);
        let second = env.plant("second");
        assert!(w.poll().is_empty());
        assert_eq!(w.file_count(), 2);
        fs::read(&second).unwrap();
        assert_eq!(kinds(&w.poll()), vec![AlertKind::Read]);
    }

    #[test]
    fn tails_transcripts_from_their_current_end() {
        let env = env();
        env.plant("work");
        let registry = State::at(&env.state_dir).load_registry().unwrap();
        let id = &registry.plants[0].files[0].tokens[0].id;
        let token = format!("{MARKER}{id}");
        let dir = env.base.join("sessions");
        fs::create_dir(&dir).unwrap();
        let old = dir.join("old.jsonl");
        fs::write(
            &old,
            format!("{{\"type\":\"user\",\"message\":\"{token}\"}}\n"),
        )
        .unwrap();

        let mut w = env.watcher(vec![dir.clone()]);
        assert!(w.poll().is_empty(), "existing content is not re-reported");

        let call = format!(
            "{{\"type\":\"assistant\",\"message\":{{\"content\":[{{\"type\":\"tool_use\",\"input\":{{\"command\":\"echo {token}\"}}}}]}}}}\n"
        );
        let mut f = fs::OpenOptions::new().append(true).open(&old).unwrap();
        f.write_all(call.as_bytes()).unwrap();
        f.write_all(b"{\"partial\":").unwrap();
        let alerts = w.poll();
        assert_eq!(kinds(&alerts), vec![AlertKind::Exfil]);
        assert_eq!(alerts[0].source, "transcript");
        assert!(crate::matcher::find(alerts[0].detail.as_deref().unwrap()).is_empty());

        let other = format!("{MARKER}{}", new_id(|c| registry.has_id(c)));
        fs::write(dir.join("new.jsonl"), format!("{other}\n")).unwrap();
        for _ in 0..RESCAN_EVERY {
            let alerts = w.poll();
            if !alerts.is_empty() {
                assert_eq!(kinds(&alerts), vec![AlertKind::Unregistered]);
                return;
            }
        }
        panic!("new transcript was not picked up");
    }
}
