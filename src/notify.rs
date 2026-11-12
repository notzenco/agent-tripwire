//! Best-effort desktop notifications.

use std::process::{Child, Command, Stdio};

/// Starts `osascript` (macOS) or `notify-send` (elsewhere) to show
/// `message`. Returns `None` when no notifier could be started.
pub fn desktop(message: &str) -> Option<Child> {
    let mut command = if cfg!(target_os = "macos") {
        let quoted = message.replace('\\', "\\\\").replace('"', "\\\"");
        let mut c = Command::new("osascript");
        c.arg("-e").arg(format!(
            "display notification \"{quoted}\" with title \"agent-tripwire\""
        ));
        c
    } else {
        let mut c = Command::new("notify-send");
        c.args(["agent-tripwire", message]);
        c
    };
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .ok()
}
