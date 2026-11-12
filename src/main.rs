use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, ExitCode, Stdio};
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use agent_tripwire::hook::{self, Agent};
use agent_tripwire::listen;
use agent_tripwire::plant::{self, PlantOutcome, PlantRequest, Profile};
use agent_tripwire::scan;
use agent_tripwire::state::{Kind, Registry, State, real_home};
use agent_tripwire::token::random_string;
use agent_tripwire::watch::{Backend, Watcher};

/// Honeytoken credentials that alert when an AI coding agent reads, sends out
/// or uses them.
#[derive(Parser)]
#[command(name = "tripwire", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create a sandbox home directory with planted credentials.
    Sandbox {
        /// Directory to create (default: under the state directory).
        path: Option<PathBuf>,
        /// Point planted configs at a local `tripwire listen` port.
        #[arg(long, value_name = "PORT")]
        listen: Option<u16>,
    },
    /// Plant honeytokens in an existing directory.
    Plant {
        dir: PathBuf,
        /// Set of files to plant; `project` plants `.env`, `home` plants
        /// `.aws/credentials`, `.npmrc` and `.ssh/id_ed25519`.
        #[arg(long, value_enum, default_value = "project")]
        profile: Profile,
        /// Plant these kinds instead of the profile's.
        #[arg(long = "kind", value_enum)]
        kinds: Vec<Kind>,
        #[arg(long, value_name = "PORT")]
        listen: Option<u16>,
    },
    /// List plants, their files and token ids.
    List {
        #[arg(long)]
        json: bool,
    },
    /// Remove planted files (only those unchanged since planting).
    Remove {
        #[arg(required_unless_present = "all")]
        plant_ids: Vec<String>,
        #[arg(long, conflicts_with = "plant_ids")]
        all: bool,
    },
    /// Scan transcripts (JSONL) or text files for planted tokens.
    Scan {
        #[arg(required = true)]
        paths: Vec<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Handle one agent hook event from stdin.
    Hook {
        /// Deny PreToolUse calls that would send a token out.
        #[arg(long)]
        block: bool,
        #[command(subcommand)]
        command: Option<HookCmd>,
    },
    /// Watch planted files (and optionally transcripts) and raise alerts.
    Watch {
        /// Also tail `.jsonl` transcripts under this directory.
        #[arg(long = "transcripts", value_name = "DIR")]
        transcripts: Vec<PathBuf>,
        /// Send a desktop notification for each alert.
        #[arg(long)]
        notify: bool,
        /// Poll interval in milliseconds.
        #[arg(long, default_value_t = 500, value_name = "MS")]
        interval: u64,
    },
    /// Run the local listener that detects planted credentials being used.
    Listen {
        #[arg(long, default_value_t = 8787)]
        port: u16,
    },
    /// Show the alert log.
    Alerts {
        #[arg(long)]
        json: bool,
        /// Only alerts at or after this RFC 3339 time or date prefix.
        #[arg(long)]
        since: Option<String>,
    },
}

#[derive(Subcommand)]
enum HookCmd {
    /// Print the hook settings snippet for an agent.
    Config {
        #[arg(value_enum)]
        agent: Agent,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli.command) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("tripwire: error: {e:#}");
            ExitCode::from(2)
        }
    }
}

fn run(command: Cmd) -> Result<ExitCode> {
    match command {
        Cmd::Sandbox { path, listen } => sandbox(path, listen),
        Cmd::Plant {
            dir,
            profile,
            kinds,
            listen,
        } => {
            let kinds = if kinds.is_empty() {
                profile.kinds()
            } else {
                kinds
            };
            let req = PlantRequest {
                root: dir,
                create_root: false,
                kinds,
                listen,
                real_home: real_home()?,
                never_index: false,
            };
            let outcome = plant::plant(&State::locate()?, &req)?;
            report_plant(&outcome);
            Ok(ExitCode::SUCCESS)
        }
        Cmd::List { json } => list(json),
        Cmd::Remove { plant_ids, all } => remove(plant_ids, all),
        Cmd::Scan { paths, json } => scan_paths(&paths, json),
        Cmd::Hook {
            command: Some(HookCmd::Config { agent }),
            ..
        } => {
            let exe = std::env::current_exe()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| "tripwire".into());
            let target = match agent {
                Agent::Claude => "~/.claude/settings.json (or .claude/settings.json in a project)",
                Agent::Codex => "~/.codex/hooks.json (or .codex/hooks.json in a project)",
            };
            eprintln!("# Merge into {target}:");
            println!("{}", hook::config_snippet(agent, &exe));
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Hook {
            block,
            command: None,
        } => Ok(run_hook(block)),
        Cmd::Watch {
            transcripts,
            notify,
            interval,
        } => watch(transcripts, notify, interval),
        Cmd::Listen { port } => {
            let state = State::locate()?;
            let listener = std::net::TcpListener::bind(("127.0.0.1", port))
                .with_context(|| format!("binding 127.0.0.1:{port}"))?;
            eprintln!("Listening on http://127.0.0.1:{port}. Ctrl-C to stop.");
            listen::serve(listener, &state, |alert| {
                if let Err(e) = state.append_alert(alert) {
                    eprintln!("tripwire listen: {e:#}");
                }
                println!("{}", alert.summary());
            })?;
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Alerts { json, since } => alerts(json, since),
    }
}

fn sandbox(path: Option<PathBuf>, listen: Option<u16>) -> Result<ExitCode> {
    let state = State::locate()?;
    let root = match path {
        Some(path) => path,
        None => state.dir().join("sandboxes").join(format!(
            "sb-{}",
            random_string(b"abcdefghijklmnopqrstuvwxyz234567", 6)
        )),
    };
    let req = PlantRequest {
        root: root.clone(),
        create_root: true,
        kinds: Profile::Home.kinds(),
        listen,
        real_home: real_home()?,
        never_index: true,
    };
    let outcome = plant::plant(&state, &req)?;
    report_plant(&outcome);
    println!();
    println!("Run the agent with this as its home directory:");
    println!("  export HOME={}", outcome.plant.root.display());
    Ok(ExitCode::SUCCESS)
}

fn report_plant(outcome: &PlantOutcome) {
    let plant = &outcome.plant;
    println!("Planted {} in {}", plant.id, plant.root.display());
    for file in &plant.files {
        let rel = file.path.strip_prefix(&plant.root).unwrap_or(&file.path);
        let ids: Vec<_> = file.tokens.iter().map(|t| t.id.as_str()).collect();
        if ids.is_empty() {
            println!("  {}", rel.display());
        } else {
            println!("  {}  tokens {}", rel.display(), ids.join(", "));
        }
    }
    if let Some(port) = plant.listen {
        println!("Configs point at http://127.0.0.1:{port}; run `tripwire listen --port {port}`.");
    }
    println!("Remove with: tripwire remove {}", plant.id);
    for warning in &outcome.warnings {
        eprintln!("tripwire: warning: {warning}");
    }
}

fn list(json: bool) -> Result<ExitCode> {
    let registry = State::locate()?.load_registry()?;
    if json {
        println!("{}", serde_json::to_string_pretty(&registry.plants)?);
        return Ok(ExitCode::SUCCESS);
    }
    if registry.plants.is_empty() {
        println!("No plants.");
    }
    for plant in &registry.plants {
        println!("{}  {}  {}", plant.id, plant.created, plant.root.display());
        for file in &plant.files {
            let tokens: Vec<_> = file
                .tokens
                .iter()
                .map(|t| format!("{} {}", t.id, t.field))
                .collect();
            println!("  {}  {}", file.path.display(), tokens.join(", "));
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn remove(plant_ids: Vec<String>, all: bool) -> Result<ExitCode> {
    let state = State::locate()?;
    let ids = if all {
        state
            .load_registry()?
            .plants
            .into_iter()
            .map(|p| p.id)
            .collect()
    } else {
        plant_ids
    };
    for id in ids {
        let report = plant::remove(&state, &id)?;
        println!("{id}:");
        for path in &report.removed {
            println!("  removed {}", path.display());
        }
        for (path, why) in &report.left {
            println!("  left    {}: {why}", path.display());
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn scan_paths(paths: &[PathBuf], json: bool) -> Result<ExitCode> {
    let registry = State::locate()?.load_registry()?;
    let mut total = 0;
    for path in scan::collect_paths(paths)? {
        for found in scan::scan_file(&path, &registry)? {
            total += 1;
            let f = &found.finding;
            let loc = registry.lookup(&f.id);
            if json {
                let mut value = serde_json::to_value(&found)?;
                value["planted_file"] = serde_json::json!(loc.map(|l| &l.file.path));
                value["field"] = serde_json::json!(loc.map(|l| l.field));
                println!("{value}");
            } else {
                let place = loc
                    .map(|l| format!(" ({} {})", l.file.path.display(), l.field))
                    .unwrap_or_default();
                println!(
                    "{}:{}: {} token {}{place} [{}] at {} — {}",
                    found.path.display(),
                    found.line,
                    f.kind.as_str(),
                    f.id,
                    f.encoding.as_str(),
                    f.location,
                    f.excerpt,
                );
            }
        }
    }
    if !json {
        eprintln!("{total} finding(s)");
    }
    Ok(if total > 0 {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    })
}

/// Never fails the agent: problems are reported on stderr and exit 0.
fn run_hook(block: bool) -> ExitCode {
    let mut input = String::new();
    if let Err(e) = std::io::stdin().read_to_string(&mut input) {
        eprintln!("tripwire hook: cannot read stdin: {e}");
        return ExitCode::SUCCESS;
    }
    let state = match State::locate() {
        Ok(state) => state,
        Err(e) => {
            eprintln!("tripwire hook: {e:#}");
            return ExitCode::SUCCESS;
        }
    };
    let registry = state.load_registry().unwrap_or_else(|e| {
        eprintln!("tripwire hook: {e:#}");
        Registry::default()
    });
    let mut homes: Vec<PathBuf> = std::env::var_os("HOME")
        .map(PathBuf::from)
        .into_iter()
        .collect();
    homes.extend(real_home().ok());

    let outcome = match hook::evaluate(&input, &registry, &homes, block) {
        Ok(outcome) => outcome,
        Err(e) => {
            eprintln!("tripwire hook: ignoring event: {e:#}");
            return ExitCode::SUCCESS;
        }
    };
    for alert in &outcome.alerts {
        if let Err(e) = state.append_alert(alert) {
            eprintln!("tripwire hook: {e:#}");
        }
        eprintln!("tripwire: {}", alert.summary());
    }
    match outcome.deny {
        Some(reason) => {
            eprintln!("{reason}");
            ExitCode::from(2)
        }
        None => ExitCode::SUCCESS,
    }
}

fn watch(transcripts: Vec<PathBuf>, notify: bool, interval: u64) -> Result<ExitCode> {
    let state = State::locate()?;
    let mut watcher = Watcher::new(State::at(state.dir()), transcripts.clone())?;
    let backend = match watcher.backend() {
        Backend::Inotify => "inotify",
        Backend::Atime => "access-time polling",
    };
    eprintln!(
        "Watching {} planted file(s) with {backend}{}. Ctrl-C to stop.",
        watcher.file_count(),
        if transcripts.is_empty() {
            String::new()
        } else {
            format!(" and {} transcript dir(s)", transcripts.len())
        }
    );
    loop {
        for alert in watcher.poll() {
            if let Err(e) = state.append_alert(&alert) {
                eprintln!("tripwire watch: {e:#}");
            }
            let line = alert.summary();
            println!("{line}");
            if notify {
                desktop_notify(&line);
            }
        }
        std::thread::sleep(Duration::from_millis(interval));
    }
}

/// Best effort; a missing notifier is not an error.
fn desktop_notify(message: &str) {
    let result = if cfg!(target_os = "macos") {
        let quoted = message.replace('\\', "\\\\").replace('"', "\\\"");
        Command::new("osascript")
            .arg("-e")
            .arg(format!(
                "display notification \"{quoted}\" with title \"agent-tripwire\""
            ))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
    } else {
        Command::new("notify-send")
            .args(["agent-tripwire", message])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
    };
    if let Ok(mut child) = result {
        std::thread::spawn(move || child.wait());
    }
}

fn alerts(json: bool, since: Option<String>) -> Result<ExitCode> {
    let alerts = State::locate()?.read_alerts()?;
    for alert in alerts
        .iter()
        .filter(|a| since.as_deref().is_none_or(|s| a.time.as_str() >= s))
    {
        if json {
            println!("{}", serde_json::to_string(alert)?);
        } else {
            println!("{}", alert.summary());
        }
    }
    Ok(ExitCode::SUCCESS)
}
