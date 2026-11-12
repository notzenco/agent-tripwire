//! agent-tripwire: honeytoken credentials that alert when an AI coding agent
//! reads, sends out or uses them. See `docs/design.md`.

pub mod hook;
pub mod listen;
pub mod matcher;
pub mod plant;
pub mod scan;
pub mod state;
pub mod token;
pub mod watch;
