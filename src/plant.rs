//! Planting honeytoken files and removing them again.
//!
//! Safety rules (see `docs/design.md`): write only beneath an explicit
//! target, never into the real home or its credential directories, never
//! overwrite, never follow symlinks, and remove only what is unchanged.

use std::fs::{self, File, FileTimes, OpenOptions};
use std::io::{ErrorKind, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use sha2::{Digest, Sha256};

use crate::state::{Kind, Plant, PlantedFile, Registry, State, TokenField, now_rfc3339};
use crate::token::{BASE32, BASE62, BASE64, MARKER, new_id, random_string};

/// Directories under the real home that hold real credentials.
const SENSITIVE_HOME_DIRS: &[&str] = &[
    ".aws", ".ssh", ".gnupg", ".config", ".docker", ".kube", ".azure", ".gcloud", ".npm",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Profile {
    Home,
    Project,
}

impl Profile {
    pub fn kinds(self) -> Vec<Kind> {
        match self {
            Profile::Home => vec![Kind::Aws, Kind::Npm, Kind::Ssh],
            Profile::Project => vec![Kind::Env],
        }
    }
}

#[derive(Debug, Clone)]
pub struct PlantRequest {
    pub root: PathBuf,
    /// Create `root` (it must not exist) and remove it again on `remove`.
    pub create_root: bool,
    pub kinds: Vec<Kind>,
    pub listen: Option<u16>,
    /// Real home from the password database; injected so tests can use a fake.
    pub real_home: PathBuf,
    /// Write `.metadata_never_index` so Spotlight skips the directory.
    pub never_index: bool,
}

#[derive(Debug)]
pub struct PlantOutcome {
    pub plant: Plant,
    pub warnings: Vec<String>,
}

#[derive(Debug, Default)]
pub struct RemoveReport {
    pub removed: Vec<PathBuf>,
    /// Paths left in place, with the reason.
    pub left: Vec<(PathBuf, String)>,
}

/// A file to write, relative to the plant root.
struct Planned {
    rel: PathBuf,
    kind: Kind,
    mode: u32,
    contents: String,
    tokens: Vec<TokenField>,
}

pub fn plant(state: &State, req: &PlantRequest) -> Result<PlantOutcome> {
    let _lock = state.lock()?;
    let mut registry = state.load_registry()?;
    let root = resolve_root(req)?;
    check_target(&root, &req.real_home)?;
    let planned = render(req, &registry);
    for p in &planned {
        preflight(&root, &p.rel)?;
    }

    let mut written = Vec::new();
    let mut created_dirs = Vec::new();
    let files = match write_all(req, &root, &planned, &mut written, &mut created_dirs) {
        Ok(files) => files,
        Err(e) => {
            rollback(&written, &created_dirs);
            return Err(e);
        }
    };

    let plant = Plant {
        id: new_plant_id(&registry),
        created: now_rfc3339(),
        root: root.clone(),
        files,
        created_dirs: created_dirs.clone(),
        listen: req.listen,
    };
    registry.plants.push(plant.clone());
    if let Err(e) = state.save_registry(&registry) {
        rollback(&written, &created_dirs);
        return Err(e);
    }

    let mut warnings = Vec::new();
    if planned.iter().any(|p| p.kind == Kind::Env) && git_says_not_ignored(&root, ".env") {
        warnings.push(format!(
            ".env is not ignored by Git in {}; do not commit it",
            root.display()
        ));
    }
    Ok(PlantOutcome { plant, warnings })
}

pub fn remove(state: &State, plant_id: &str) -> Result<RemoveReport> {
    let _lock = state.lock()?;
    let mut registry = state.load_registry()?;
    let Some(index) = registry.plants.iter().position(|p| p.id == plant_id) else {
        bail!("no plant with id {plant_id}");
    };
    let plant = registry.plants.remove(index);
    let mut report = RemoveReport::default();

    for file in &plant.files {
        let path = &file.path;
        match fs::symlink_metadata(path) {
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(e) => report.left.push((path.clone(), e.to_string())),
            Ok(meta) if !meta.file_type().is_file() => report.left.push((
                path.clone(),
                "no longer a regular file; left in place".into(),
            )),
            Ok(_) => {
                let same = fs::read(path).is_ok_and(|bytes| sha256_hex(&bytes) == file.sha256);
                if !same {
                    report.left.push((
                        path.clone(),
                        "modified since planting; left in place".into(),
                    ));
                } else if let Err(e) = fs::remove_file(path) {
                    report.left.push((path.clone(), e.to_string()));
                } else {
                    report.removed.push(path.clone());
                }
            }
        }
    }
    for dir in plant.created_dirs.iter().rev() {
        match fs::remove_dir(dir) {
            Ok(()) => report.removed.push(dir.clone()),
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(_) => report
                .left
                .push((dir.clone(), "not empty; left in place".into())),
        }
    }

    state.save_registry(&registry)?;
    Ok(report)
}

/// Sets the access time a minute before the modification time, so the next
/// read moves it forward (also under Linux `relatime`).
pub fn arm_atime(path: &Path) -> std::io::Result<()> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    arm_file(&file)
}

fn arm_file(file: &File) -> std::io::Result<()> {
    let modified = file.metadata()?.modified()?;
    let accessed = modified
        .checked_sub(Duration::from_secs(60))
        .unwrap_or(modified);
    file.set_times(
        FileTimes::new()
            .set_accessed(accessed)
            .set_modified(modified),
    )
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The canonical root to plant into. A root to be created must not exist;
/// its parent is created if needed and canonicalised.
fn resolve_root(req: &PlantRequest) -> Result<PathBuf> {
    let root = std::path::absolute(&req.root)
        .with_context(|| format!("resolving {}", req.root.display()))?;
    if !req.create_root {
        let canonical = root
            .canonicalize()
            .with_context(|| format!("{} does not exist", root.display()))?;
        if !canonical.is_dir() {
            bail!("{} is not a directory", canonical.display());
        }
        return Ok(canonical);
    }
    if fs::symlink_metadata(&root).is_ok() {
        bail!("{} already exists; choose a new path", root.display());
    }
    let (Some(parent), Some(Component::Normal(name))) =
        (root.parent(), root.components().next_back())
    else {
        bail!("{} is not a usable directory path", root.display());
    };
    fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    Ok(parent.canonicalize()?.join(name))
}

/// Refuses the real home and credential directories inside it.
fn check_target(root: &Path, real_home: &Path) -> Result<()> {
    let home = real_home
        .canonicalize()
        .unwrap_or_else(|_| real_home.to_path_buf());
    if root == home {
        bail!(
            "refusing to plant into the real home directory {}; use `tripwire sandbox` or name another directory",
            home.display()
        );
    }
    for dir in SENSITIVE_HOME_DIRS {
        if root.starts_with(home.join(dir)) {
            bail!(
                "refusing to plant inside {}, a credential directory in the real home",
                home.join(dir).display()
            );
        }
    }
    Ok(())
}

/// Checks that every existing parent of `rel` is a real directory and that
/// the file itself does not exist (not even as a dangling symlink).
fn preflight(root: &Path, rel: &Path) -> Result<()> {
    let mut current = root.to_path_buf();
    if let Some(parent) = rel.parent() {
        for component in parent.components() {
            current.push(component);
            match fs::symlink_metadata(&current) {
                Ok(meta) if meta.file_type().is_symlink() => {
                    bail!("{} is a symlink; refusing to follow it", current.display())
                }
                Ok(meta) if !meta.is_dir() => bail!("{} is not a directory", current.display()),
                Ok(_) => {}
                Err(e) if e.kind() == ErrorKind::NotFound => break,
                Err(e) => return Err(e).with_context(|| current.display().to_string()),
            }
        }
    }
    let path = root.join(rel);
    match fs::symlink_metadata(&path) {
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
        Ok(_) => bail!(
            "{} already exists; refusing to overwrite it",
            path.display()
        ),
        Err(e) => Err(e).with_context(|| path.display().to_string()),
    }
}

fn write_all(
    req: &PlantRequest,
    root: &Path,
    planned: &[Planned],
    written: &mut Vec<PathBuf>,
    created_dirs: &mut Vec<PathBuf>,
) -> Result<Vec<PlantedFile>> {
    if req.create_root {
        make_dir(root)?;
        created_dirs.push(root.to_path_buf());
    }
    let mut files = Vec::new();
    for p in planned {
        let mut dir = root.to_path_buf();
        for component in p.rel.parent().into_iter().flat_map(Path::components) {
            dir.push(component);
            match fs::symlink_metadata(&dir) {
                Ok(meta) if meta.is_dir() => {}
                Ok(_) => bail!("{} is not a directory", dir.display()),
                Err(e) if e.kind() == ErrorKind::NotFound => {
                    make_dir(&dir)?;
                    created_dirs.push(dir.clone());
                }
                Err(e) => return Err(e).with_context(|| dir.display().to_string()),
            }
        }
        let path = root.join(&p.rel);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(p.mode)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
            .with_context(|| format!("creating {}", path.display()))?;
        written.push(path.clone());
        file.write_all(p.contents.as_bytes())?;
        file.sync_all()?;
        arm_file(&file)?;
        files.push(PlantedFile {
            path,
            kind: p.kind,
            sha256: sha256_hex(p.contents.as_bytes()),
            tokens: p.tokens.clone(),
        });
    }
    Ok(files)
}

fn make_dir(path: &Path) -> Result<()> {
    fs::DirBuilder::new()
        .mode(0o700)
        .create(path)
        .with_context(|| format!("creating {}", path.display()))
}

fn rollback(written: &[PathBuf], created_dirs: &[PathBuf]) {
    for path in written.iter().rev() {
        let _ = fs::remove_file(path);
    }
    for dir in created_dirs.iter().rev() {
        let _ = fs::remove_dir(dir);
    }
}

fn git_says_not_ignored(root: &Path, rel: &str) -> bool {
    // Exit status 1 means "not ignored"; 128 means not a work tree.
    Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["check-ignore", "-q", rel])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.code() == Some(1))
}

fn new_plant_id(registry: &Registry) -> String {
    loop {
        let id = format!("p-{}", random_string(BASE32, 6).to_lowercase());
        if !registry.plants.iter().any(|p| p.id == id) {
            return id;
        }
    }
}

/// Generates token values whose ids are unused in the registry and in this plant.
struct Tokens<'a> {
    registry: &'a Registry,
    used: Vec<String>,
}

impl Tokens<'_> {
    /// `TRIPWIRE<id>`, recording `field` for the file being built.
    fn next(&mut self, fields: &mut Vec<TokenField>, field: &str) -> String {
        let id = new_id(|c| self.registry.has_id(c) || self.used.iter().any(|u| u == c));
        self.used.push(id.clone());
        fields.push(TokenField {
            id: id.clone(),
            field: field.to_string(),
        });
        format!("{MARKER}{id}")
    }
}

fn render(req: &PlantRequest, registry: &Registry) -> Vec<Planned> {
    let mut tokens = Tokens {
        registry,
        used: Vec::new(),
    };
    let listen_url = req.listen.map(|port| format!("http://127.0.0.1:{port}"));
    let mut out = Vec::new();
    if req.never_index {
        out.push(Planned {
            rel: ".metadata_never_index".into(),
            kind: Kind::Support,
            mode: 0o644,
            contents: String::new(),
            tokens: Vec::new(),
        });
    }
    let mut kinds = req.kinds.clone();
    kinds.dedup();
    for kind in kinds {
        let mut fields = Vec::new();
        let (rel, contents) = match kind {
            Kind::Env => {
                let key_id = tokens.next(&mut fields, "AWS_ACCESS_KEY_ID");
                let secret = tokens.next(&mut fields, "AWS_SECRET_ACCESS_KEY");
                let db = tokens.next(&mut fields, "DATABASE_URL");
                let api = tokens.next(&mut fields, "API_TOKEN");
                let mut text = format!(
                    "NODE_ENV=production\n\
                     AWS_ACCESS_KEY_ID=AKIA{key_id}\n\
                     AWS_SECRET_ACCESS_KEY={secret}{}\n\
                     AWS_REGION=us-east-1\n\
                     DATABASE_URL=postgres://app:{db}{}@db.internal.invalid:5432/app\n\
                     API_TOKEN={api}{}\n",
                    random_string(BASE64, 24),
                    random_string(BASE62, 16),
                    random_string(BASE62, 32),
                );
                if let Some(url) = &listen_url {
                    text.push_str(&format!("API_BASE_URL={url}\n"));
                }
                (".env", text)
            }
            Kind::Aws => {
                let key_id = tokens.next(&mut fields, "aws_access_key_id");
                let secret = tokens.next(&mut fields, "aws_secret_access_key");
                if let Some(url) = &listen_url {
                    out.push(Planned {
                        rel: ".aws/config".into(),
                        kind: Kind::Support,
                        mode: 0o600,
                        contents: format!("[default]\nregion = us-east-1\nendpoint_url = {url}\n"),
                        tokens: Vec::new(),
                    });
                }
                (
                    ".aws/credentials",
                    format!(
                        "[default]\n\
                         aws_access_key_id = AKIA{key_id}\n\
                         aws_secret_access_key = {secret}{}\n",
                        random_string(BASE64, 24)
                    ),
                )
            }
            Kind::Npm => {
                let token = format!(
                    "npm_{}{}",
                    tokens.next(&mut fields, "_authToken"),
                    random_string(BASE62, 20)
                );
                let text = match &listen_url {
                    Some(url) => format!(
                        "registry={url}/\n//{}/:_authToken={token}\n",
                        url.trim_start_matches("http://")
                    ),
                    None => format!("//registry.npmjs.org/:_authToken={token}\n"),
                };
                (".npmrc", text)
            }
            Kind::Ssh => {
                let marker = tokens.next(&mut fields, "private_key");
                (".ssh/id_ed25519", ssh_private_key(&marker))
            }
            Kind::Support => continue,
        };
        out.push(Planned {
            rel: rel.into(),
            kind,
            mode: 0o600,
            contents,
            tokens: fields,
        });
    }
    out
}

/// An OpenSSH private-key block with a genuine ed25519 header, then the
/// marker, then random filler. It does not parse as a key.
fn ssh_private_key(marker: &str) -> String {
    let mut header = b"openssh-key-v1\0".to_vec();
    for field in [&b"none"[..], b"none", b""] {
        header.extend((field.len() as u32).to_be_bytes());
        header.extend(field);
    }
    header.extend(1u32.to_be_bytes());
    header.extend(51u32.to_be_bytes());
    header.extend(11u32.to_be_bytes());
    header.extend(b"ssh-ed25519");
    header.extend(32u32.to_be_bytes());
    // 60 bytes encode to 80 characters with no padding.
    let mut body = STANDARD.encode(&header[..60]);
    body.push_str(marker);
    body.push_str(&random_string(BASE64, 400 - body.len()));
    let mut text = String::from("-----BEGIN OPENSSH PRIVATE KEY-----\n");
    for line in body.as_bytes().chunks(70) {
        text.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
        text.push('\n');
    }
    text.push_str("-----END OPENSSH PRIVATE KEY-----\n");
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::matcher;
    use std::collections::HashSet;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use tempfile::TempDir;

    struct Env {
        _tmp: TempDir,
        home: PathBuf,
        work: PathBuf,
        state: State,
    }

    fn env() -> Env {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().canonicalize().unwrap();
        let home = base.join("home");
        let work = base.join("work");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(&work).unwrap();
        let state = State::at(base.join("state"));
        Env {
            _tmp: tmp,
            home,
            work,
            state,
        }
    }

    fn request(env: &Env, root: &Path, kinds: &[Kind]) -> PlantRequest {
        PlantRequest {
            root: root.to_path_buf(),
            create_root: false,
            kinds: kinds.to_vec(),
            listen: None,
            real_home: env.home.clone(),
            never_index: false,
        }
    }

    fn all_kinds() -> Vec<Kind> {
        vec![Kind::Env, Kind::Aws, Kind::Npm, Kind::Ssh]
    }

    fn tree(dir: &Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            out.push(path.clone());
            if path.is_dir() && !path.is_symlink() {
                out.extend(tree(&path));
            }
        }
        out.sort();
        out
    }

    #[test]
    fn plants_each_kind_with_registered_tokens() {
        let env = env();
        let out = plant(&env.state, &request(&env, &env.work, &all_kinds())).unwrap();
        let reg = env.state.load_registry().unwrap();
        assert_eq!(reg.plants, vec![out.plant.clone()]);

        let rels: Vec<_> = out
            .plant
            .files
            .iter()
            .map(|f| f.path.strip_prefix(&env.work).unwrap().to_path_buf())
            .collect();
        for rel in [".env", ".aws/credentials", ".npmrc", ".ssh/id_ed25519"] {
            assert!(
                rels.contains(&PathBuf::from(rel)),
                "{rel} missing from {rels:?}"
            );
        }

        for file in &out.plant.files {
            let text = fs::read_to_string(&file.path).unwrap();
            let found: HashSet<_> = matcher::find(&text).into_iter().map(|h| h.id).collect();
            let registered: HashSet<_> = file.tokens.iter().map(|t| t.id.clone()).collect();
            assert!(!registered.is_empty(), "{}", file.path.display());
            assert_eq!(found, registered, "{}", file.path.display());
            assert_eq!(file.sha256, sha256_hex(text.as_bytes()));
            let mode = fs::metadata(&file.path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "{}", file.path.display());
        }
        let ssh_mode = fs::metadata(env.work.join(".ssh"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(ssh_mode, 0o700);
    }

    #[test]
    fn values_have_realistic_shapes() {
        let env = env();
        plant(&env.state, &request(&env, &env.work, &all_kinds())).unwrap();
        let creds = fs::read_to_string(env.work.join(".aws/credentials")).unwrap();
        let value = |key: &str| {
            creds
                .lines()
                .find_map(|l| l.strip_prefix(key))
                .map(|v| v.trim_start_matches([' ', '=']).to_string())
                .unwrap()
        };
        let key_id = value("aws_access_key_id");
        assert_eq!(key_id.len(), 20);
        assert!(key_id.starts_with(&format!("AKIA{MARKER}")));
        assert_eq!(value("aws_secret_access_key").len(), 40);

        let npmrc = fs::read_to_string(env.work.join(".npmrc")).unwrap();
        let npm_token = npmrc.trim().rsplit('=').next().unwrap();
        assert!(npm_token.starts_with(&format!("npm_{MARKER}")));
        assert_eq!(npm_token.len(), 4 + 36);

        let key = fs::read_to_string(env.work.join(".ssh/id_ed25519")).unwrap();
        let lines: Vec<_> = key.lines().collect();
        assert_eq!(lines.first(), Some(&"-----BEGIN OPENSSH PRIVATE KEY-----"));
        assert_eq!(lines.last(), Some(&"-----END OPENSSH PRIVATE KEY-----"));
        assert!(lines[1..lines.len() - 1].iter().all(|l| l.len() <= 70));
    }

    #[test]
    fn concurrent_plants_are_all_registered() {
        let env = env();
        let dirs: Vec<PathBuf> = (0..16)
            .map(|i| {
                let d = env.work.join(format!("d{i}"));
                fs::create_dir(&d).unwrap();
                d
            })
            .collect();
        std::thread::scope(|scope| {
            for dir in &dirs {
                let req = request(&env, dir, &[Kind::Env]);
                let state = &env.state;
                scope.spawn(move || plant(state, &req).unwrap());
            }
        });
        assert_eq!(env.state.load_registry().unwrap().plants.len(), dirs.len());
    }

    #[test]
    fn tokens_are_unique_across_plants() {
        let env = env();
        let other = env.work.join("other");
        fs::create_dir(&other).unwrap();
        let a = plant(&env.state, &request(&env, &env.work, &all_kinds())).unwrap();
        let b = plant(&env.state, &request(&env, &other, &all_kinds())).unwrap();
        let ids = |p: &Plant| -> HashSet<String> {
            p.files
                .iter()
                .flat_map(|f| f.tokens.iter().map(|t| t.id.clone()))
                .collect()
        };
        assert!(ids(&a.plant).is_disjoint(&ids(&b.plant)));
        assert_ne!(a.plant.id, b.plant.id);
    }

    #[test]
    fn refuses_the_real_home() {
        let env = env();
        let err = plant(&env.state, &request(&env, &env.home, &all_kinds())).unwrap_err();
        assert!(err.to_string().contains("real home"), "{err}");
        assert!(tree(&env.home).is_empty());
    }

    #[test]
    fn refuses_credential_directories_in_the_real_home() {
        let env = env();
        let aws = env.home.join(".aws");
        fs::create_dir(&aws).unwrap();
        let err = plant(&env.state, &request(&env, &aws, &[Kind::Env])).unwrap_err();
        assert!(err.to_string().contains("credential"), "{err}");
        assert!(tree(&aws).is_empty());
    }

    #[test]
    fn refuses_the_real_home_through_a_symlink() {
        let env = env();
        let link = env.work.join("home-link");
        std::os::unix::fs::symlink(&env.home, &link).unwrap();
        assert!(plant(&env.state, &request(&env, &link, &all_kinds())).is_err());
        assert!(tree(&env.home).is_empty());
    }

    #[test]
    fn never_overwrites_and_writes_nothing_on_conflict() {
        let env = env();
        fs::write(env.work.join(".npmrc"), "real config\n").unwrap();
        let err = plant(&env.state, &request(&env, &env.work, &all_kinds())).unwrap_err();
        assert!(err.to_string().contains("already exists"), "{err}");
        assert_eq!(
            fs::read_to_string(env.work.join(".npmrc")).unwrap(),
            "real config\n"
        );
        assert_eq!(tree(&env.work), vec![env.work.join(".npmrc")]);
        assert!(env.state.load_registry().unwrap().plants.is_empty());
    }

    #[test]
    fn refuses_symlinked_parent_directories() {
        let env = env();
        let real_aws = env.home.join(".aws");
        fs::create_dir(&real_aws).unwrap();
        std::os::unix::fs::symlink(&real_aws, env.work.join(".aws")).unwrap();
        let err = plant(&env.state, &request(&env, &env.work, &[Kind::Aws])).unwrap_err();
        assert!(err.to_string().contains("symlink"), "{err}");
        assert!(tree(&real_aws).is_empty());
    }

    #[test]
    fn refuses_a_dangling_symlink_at_the_file_path() {
        let env = env();
        let target = env.home.join(".npmrc");
        std::os::unix::fs::symlink(&target, env.work.join(".npmrc")).unwrap();
        assert!(plant(&env.state, &request(&env, &env.work, &[Kind::Npm])).is_err());
        assert!(!target.exists());
    }

    #[test]
    fn remove_deletes_files_and_created_dirs_only() {
        let env = env();
        fs::write(env.work.join("keep.txt"), "mine").unwrap();
        let out = plant(&env.state, &request(&env, &env.work, &all_kinds())).unwrap();
        let report = remove(&env.state, &out.plant.id).unwrap();
        assert!(report.left.is_empty(), "{:?}", report.left);
        assert_eq!(tree(&env.work), vec![env.work.join("keep.txt")]);
        assert!(env.state.load_registry().unwrap().plants.is_empty());
    }

    #[test]
    fn remove_keeps_pre_existing_directories() {
        let env = env();
        fs::create_dir(env.work.join(".ssh")).unwrap();
        let out = plant(&env.state, &request(&env, &env.work, &[Kind::Ssh])).unwrap();
        remove(&env.state, &out.plant.id).unwrap();
        assert_eq!(tree(&env.work), vec![env.work.join(".ssh")]);
    }

    #[test]
    fn remove_leaves_modified_files_and_reports_them() {
        let env = env();
        let out = plant(&env.state, &request(&env, &env.work, &[Kind::Aws])).unwrap();
        let creds = env.work.join(".aws/credentials");
        fs::write(&creds, "edited by someone\n").unwrap();
        let report = remove(&env.state, &out.plant.id).unwrap();
        assert!(creds.exists());
        assert!(
            report
                .left
                .iter()
                .any(|(p, why)| p == &creds && why.contains("modified"))
        );
        assert!(report.left.iter().any(|(p, _)| p == &env.work.join(".aws")));
    }

    #[test]
    fn remove_unknown_plant_fails() {
        let env = env();
        assert!(remove(&env.state, "p-nope").is_err());
    }

    #[test]
    fn created_root_is_removed_with_its_contents() {
        let env = env();
        let root = env.work.join("sandbox");
        let req = PlantRequest {
            create_root: true,
            never_index: true,
            ..request(&env, &root, &Profile::Home.kinds())
        };
        let out = plant(&env.state, &req).unwrap();
        assert!(root.join(".metadata_never_index").exists());
        assert!(root.join(".ssh/id_ed25519").exists());
        remove(&env.state, &out.plant.id).unwrap();
        assert!(!root.exists());
    }

    #[test]
    fn create_root_refuses_an_existing_directory() {
        let env = env();
        let req = PlantRequest {
            create_root: true,
            ..request(&env, &env.work, &[Kind::Env])
        };
        assert!(plant(&env.state, &req).is_err());
    }

    #[test]
    fn listen_points_configs_at_the_local_listener() {
        let env = env();
        let req = PlantRequest {
            listen: Some(8899),
            ..request(&env, &env.work, &all_kinds())
        };
        plant(&env.state, &req).unwrap();
        let config = fs::read_to_string(env.work.join(".aws/config")).unwrap();
        assert!(
            config.contains("endpoint_url = http://127.0.0.1:8899"),
            "{config}"
        );
        let npmrc = fs::read_to_string(env.work.join(".npmrc")).unwrap();
        assert!(npmrc.contains("registry=http://127.0.0.1:8899/"), "{npmrc}");
        assert!(npmrc.contains("//127.0.0.1:8899/:_authToken="), "{npmrc}");
        let dotenv = fs::read_to_string(env.work.join(".env")).unwrap();
        assert!(
            dotenv.contains("API_BASE_URL=http://127.0.0.1:8899"),
            "{dotenv}"
        );
    }

    #[test]
    fn planted_files_are_armed_for_read_detection() {
        let env = env();
        let out = plant(&env.state, &request(&env, &env.work, &[Kind::Env])).unwrap();
        let meta = fs::metadata(&out.plant.files[0].path).unwrap();
        assert!(meta.atime() < meta.mtime());
    }

    #[test]
    fn warns_when_dotenv_is_not_git_ignored() {
        let env = env();
        let git = |args: &[&str]| {
            Command::new("git")
                .args(args)
                .current_dir(&env.work)
                .output()
                .unwrap()
        };
        git(&["init", "-q"]);
        let out = plant(&env.state, &request(&env, &env.work, &[Kind::Env])).unwrap();
        assert!(
            out.warnings.iter().any(|w| w.contains("not ignored")),
            "{:?}",
            out.warnings
        );
        remove(&env.state, &out.plant.id).unwrap();

        fs::write(env.work.join(".gitignore"), ".env\n").unwrap();
        let out = plant(&env.state, &request(&env, &env.work, &[Kind::Env])).unwrap();
        assert!(out.warnings.is_empty(), "{:?}", out.warnings);
    }
}
