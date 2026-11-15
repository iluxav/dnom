//! Who drives an episode (`driver` in the episode record): an AI agent, automation, a person
//! at a terminal of this machine, or someone on another machine.
//!
//! Decided from the process tree alone. A process gets its answer when it starts and passes
//! it to its children, so the label survives a parent that exits:
//! - `agent`: a known agent program (`drivers.agents`), or anything that descends from one.
//! - `remote`: a remote login service (`drivers.remote`, e.g. sshd) and what it starts. Who
//!   is at the other end (a person, a script or an agent) is not visible from here.
//! - `human`: an interactive shell started by a terminal (`drivers.terminals`), and what is
//!   typed in it.
//! - `automation`: started by a scheduler, a service manager or the desktop itself
//!   (`drivers.automation`), or directly by pid 1, with none of the above in between.
//! - `unknown`: the parents were not seen.
//!
//! `agent` and `remote` stick: an agent that opens a terminal, or an SSH session that starts
//! cron, keeps its label. Work that is handed to a scheduler does not: a cron job an agent
//! wrote runs as `automation`.
//!
//! Programs are matched by process name (comm) or executable basename, and any program can
//! pick its own name. The label describes; it proves nothing. It is kept out of what a model
//! sees (`episode::model_view`).

use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Agent,
    Remote,
    Human,
    Automation,
    Unknown,
}

impl Kind {
    pub const NAMES: [&'static str; 5] = ["agent", "remote", "human", "automation", "unknown"];

    pub fn name(self) -> &'static str {
        match self {
            Kind::Agent => "agent",
            Kind::Remote => "remote",
            Kind::Human => "human",
            Kind::Automation => "automation",
            Kind::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Driver {
    pub kind: Kind,
    /// What decided it: a program name, `bash in foot`, or `pid 1`.
    pub by: String,
}

impl Default for Driver {
    fn default() -> Self {
        Self { kind: Kind::Unknown, by: String::new() }
    }
}

impl Driver {
    fn new(kind: Kind, by: impl Into<String>) -> Self {
        Self { kind, by: by.into() }
    }

    /// For a process whose parent is pid 1: a system service.
    pub fn from_init() -> Self {
        Self::new(Kind::Automation, "pid 1")
    }

    pub fn to_json(&self) -> Value {
        if self.by.is_empty() { json!({ "kind": self.kind.name() }) } else { json!({ "kind": self.kind.name(), "by": self.by }) }
    }
}

/// Program names (comm, or the basename of the executable) per kind. A list in dnom.yaml
/// replaces the built-in one.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DriverConfig {
    pub agents: Vec<String>,
    pub remote: Vec<String>,
    pub terminals: Vec<String>,
    pub automation: Vec<String>,
}

impl Default for DriverConfig {
    fn default() -> Self {
        let list = |names: &[&str]| names.iter().map(|n| n.to_string()).collect();
        Self {
            agents: list(&[
                "claude", "codex", "aider", "gemini", "opencode", "goose", "amp", "cursor-agent", "copilot", "crush", "qwen", "openhands",
            ]),
            remote: list(&["sshd", "sshd-session", "dropbear", "mosh-server"]),
            terminals: list(&[
                "foot", "footclient", "alacritty", "kitty", "ghostty", "wezterm-gui", "gnome-terminal-server", "konsole", "xterm",
                "tmux: server", "zellij", "screen", "login", "desl",
            ]),
            automation: list(&[
                "systemd", "init", "cron", "crond", "atd", "anacron", "quickshell", "Hyprland", "start-hyprland", "uwsm",
                "gitlab-runner", "Runner.Worker", "Runner.Listener",
            ]),
        }
    }
}

fn named<'a>(list: &'a [String], comm: &str, exe: &str) -> Option<&'a str> {
    let base = exe.rsplit('/').next().unwrap_or(exe);
    list.iter().map(String::as_str).find(|n| !n.is_empty() && (*n == comm || *n == base))
}

impl DriverConfig {
    /// The driver of a process.
    /// - `inherited`: its parent's driver, or its own from before an exec.
    /// - `interactive_shell`: it is a shell waiting for typed commands.
    /// - `parent`: (comm, exe) of its parent, if still known.
    pub fn of(&self, inherited: &Driver, comm: &str, exe: &str, interactive_shell: bool, parent: Option<(&str, &str)>) -> Driver {
        if let Some(agent) = named(&self.agents, comm, exe) {
            return Driver::new(Kind::Agent, agent);
        }
        if inherited.kind == Kind::Agent {
            return inherited.clone();
        }
        if let Some(service) = named(&self.remote, comm, exe) {
            return Driver::new(Kind::Remote, service);
        }
        if inherited.kind == Kind::Remote {
            return inherited.clone();
        }
        if interactive_shell
            && let Some((parent_comm, parent_exe)) = parent
            && let Some(terminal) = named(&self.terminals, parent_comm, parent_exe)
        {
            return Driver::new(Kind::Human, format!("{comm} in {terminal}"));
        }
        if let Some(starter) = named(&self.automation, comm, exe) {
            return Driver::new(Kind::Automation, starter);
        }
        inherited.clone()
    }

    /// The label of a stored episode record. Records written before the label existed get one
    /// from what they hold: the root, the name of its parent, and the programs in the tree.
    /// Whatever was above that parent is not in the record, so more of these are `unknown`.
    pub fn of_record(&self, episode: &Value) -> Driver {
        if let Some(kind) = episode["driver"]["kind"].as_str()
            && let Some(kind) = [Kind::Agent, Kind::Remote, Kind::Human, Kind::Automation, Kind::Unknown].into_iter().find(|k| k.name() == kind)
        {
            return Driver::new(kind, episode["driver"]["by"].as_str().unwrap_or(""));
        }
        let root = &episode["root"];
        let parent = root["started_by"].as_str().unwrap_or("");
        let exe = root["exe"].as_str().unwrap_or("");
        let above = if parent.is_empty() { Driver::default() } else { self.of(&Driver::default(), parent, "", false, None) };
        let name = exe.rsplit('/').next().unwrap_or(exe);
        let argv: Vec<String> = root["argv"].as_str().unwrap_or("").split_whitespace().map(String::from).collect();
        let interactive = crate::episode::SHELLS.contains(&name) && crate::episode::is_interactive_shell_argv(&argv);
        let mut driver = self.of(&above, name, exe, interactive, (!parent.is_empty()).then_some((parent, "")));
        if driver.kind != Kind::Agent
            && let Some(agent) = episode["tree"]
                .as_array()
                .into_iter()
                .flatten()
                .find_map(|t| named(&self.agents, "", t["exe"].as_str().unwrap_or("")))
        {
            driver = Driver::new(Kind::Agent, agent);
        }
        driver
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kind(d: &Driver) -> &'static str {
        d.kind.name()
    }

    /// Walks a chain of (comm, exe, interactive shell) from the oldest ancestor down.
    fn chain(start: Driver, links: &[(&str, &str, bool)]) -> Driver {
        let c = DriverConfig::default();
        let mut driver = start;
        let mut parent: Option<(&str, &str)> = None;
        for (comm, exe, interactive) in links {
            driver = c.of(&driver, comm, exe, *interactive, parent);
            parent = Some((comm, exe));
        }
        driver
    }

    #[test]
    fn a_command_typed_in_a_terminal_is_human() {
        let d = chain(Driver::default(), &[("systemd", "/usr/lib/systemd/systemd", false), ("foot", "/usr/bin/foot", false), ("bash", "/usr/bin/bash", true), ("make", "/usr/bin/make", false)]);
        assert_eq!((kind(&d), d.by.as_str()), ("human", "bash in foot"));
    }

    #[test]
    fn a_terminal_running_a_program_without_a_shell_is_not_human() {
        // The desktop starts `foot -e screensaver`: nobody types anything.
        let d = chain(Driver::default(), &[("quickshell", "/usr/bin/quickshell", false), ("foot", "/usr/bin/foot", false), ("screensaver", "/usr/bin/screensaver", false)]);
        assert_eq!((kind(&d), d.by.as_str()), ("automation", "quickshell"));
    }

    #[test]
    fn an_agent_and_everything_below_it_is_agent() {
        let links = [("foot", "/usr/bin/foot", false), ("bash", "/usr/bin/bash", true), ("claude", "/home/u/.local/bin/claude", false), ("bash", "/usr/bin/bash", false), ("git", "/usr/bin/git", false)];
        let d = chain(Driver::default(), &links);
        assert_eq!((kind(&d), d.by.as_str()), ("agent", "claude"));
        // It sticks: a terminal, a shell in it, cron or sshd started by the agent stay agent.
        for later in [[("foot", "/usr/bin/foot", false), ("bash", "/usr/bin/bash", true)], [("cron", "/usr/sbin/cron", false), ("sh", "/bin/sh", false)], [("sshd", "/usr/sbin/sshd", false), ("bash", "/usr/bin/bash", true)]] {
            assert_eq!(kind(&chain(d.clone(), &later)), "agent", "{later:?}");
        }
    }

    #[test]
    fn what_sshd_starts_is_remote_even_in_a_terminal_multiplexer() {
        let links = [("systemd", "/usr/lib/systemd/systemd", false), ("sshd", "/usr/sbin/sshd", false), ("sshd-session", "/usr/lib/openssh/sshd-session", false), ("bash", "/usr/bin/bash", true)];
        let d = chain(Driver::default(), &links);
        assert_eq!(kind(&d), "remote");
        let in_tmux = chain(d, &[("tmux: server", "/usr/bin/tmux", false), ("bash", "/usr/bin/bash", true), ("cat", "/usr/bin/cat", false)]);
        assert_eq!(kind(&in_tmux), "remote");
        // An agent started over SSH is an agent.
        assert_eq!(kind(&chain(in_tmux, &[("codex", "/usr/bin/codex", false)])), "agent");
    }

    #[test]
    fn schedulers_and_pid_1_are_automation() {
        let cron = chain(Driver::from_init(), &[("cron", "/usr/sbin/cron", false), ("sh", "/bin/sh", false), ("backup", "/usr/local/bin/backup", false)]);
        assert_eq!((kind(&cron), cron.by.as_str()), ("automation", "cron"));
        let service = chain(Driver::from_init(), &[("bash", "/usr/bin/bash", false)]);
        assert_eq!((kind(&service), service.by.as_str()), ("automation", "pid 1"));
        // A person who starts cron by hand: what cron runs is automation.
        let by_hand = chain(Driver::default(), &[("foot", "/usr/bin/foot", false), ("bash", "/usr/bin/bash", true), ("cron", "/usr/sbin/cron", false), ("sh", "/bin/sh", false)]);
        assert_eq!(kind(&by_hand), "automation");
    }

    #[test]
    fn unseen_parents_are_unknown() {
        assert_eq!(kind(&chain(Driver::default(), &[("bash", "/usr/bin/bash", true), ("make", "/usr/bin/make", false)])), "unknown");
    }

    #[test]
    fn a_stored_record_is_labelled_from_what_it_holds() {
        let c = DriverConfig::default();
        let record = |exe: &str, started_by: &str, tree: Value| json!({ "root": { "exe": exe, "started_by": started_by }, "tree": tree });
        let label = |v: Value| c.of_record(&v).kind.name();
        assert_eq!(label(record("~/.local/share/mise/installs/claude/latest/claude", "desl", json!([]))), "agent");
        assert_eq!(label(record("/usr/bin/gnome-keyring-daemon", "systemd", json!([]))), "automation");
        assert_eq!(label(record("/usr/lib/openssh/sshd-session", "sshd", json!([]))), "remote");
        assert_eq!(label(record("/usr/bin/make", "bash", json!([]))), "unknown", "the terminal above the shell is not in the record");
        assert_eq!(label(record("/usr/bin/bash", "", json!([]))), "unknown");
        assert_eq!(label(record("/usr/bin/bash", "foot", json!([]))), "human", "a shell opened in a terminal");
        assert_eq!(label(record("/usr/bin/make", "bash", json!([{ "exe": "/usr/bin/codex" }]))), "agent", "an agent runs inside it");
        // A record that carries the label is read as it is.
        let mut labelled = record("/usr/bin/make", "bash", json!([]));
        labelled["driver"] = json!({ "kind": "human", "by": "bash in foot" });
        assert_eq!(c.of_record(&labelled), Driver::new(Kind::Human, "bash in foot"));
    }
}
