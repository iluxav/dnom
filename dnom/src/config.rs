//! `dnom.yaml`: ignore rules, episode boundaries, path and redaction rules, and the
//! assessment questions. Policies (SPEC §4.5) will live here later.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, bail};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub paths: crate::paths::PathRules,
    /// Decoy files: hand-placed paths and the kinds dnom generates itself.
    #[serde(default)]
    pub decoys: crate::decoys::DecoyConfig,
    /// Webhook for episodes a policy rule matched.
    #[serde(default)]
    pub notify: crate::notify::NotifyConfig,
    #[serde(default)]
    pub redact: crate::redact::RedactRules,
    /// Context and typed questions sent with each episode; missing parts use the built-ins.
    #[serde(default)]
    pub assessment: crate::questions::AssessmentConfig,
    /// Dry-run rules over model answers and episode facts (SPEC §4.5).
    #[serde(default)]
    pub policies: crate::policy::PolicyConfig,
    /// Backend used when `classify` is run without `--backend`.
    #[serde(default = "crate::backends::default_backend")]
    pub backend: String,
    /// Named model backends (url, model, api_key_env); leave out to use the built-ins.
    #[serde(default = "crate::backends::default_backends")]
    pub backends: std::collections::BTreeMap<String, crate::backends::BackendDef>,
    /// Process trees that are not sent to the model.
    #[serde(default)]
    pub ignore: Vec<IgnoreRule>,
    /// A process whose parent has one of these names (comm or exe basename) starts a new episode.
    #[serde(default = "default_boundaries")]
    pub boundaries: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            paths: Default::default(),
            decoys: Default::default(),
            notify: Default::default(),
            redact: Default::default(),
            assessment: Default::default(),
            policies: Default::default(),
            backend: crate::backends::default_backend(),
            backends: crate::backends::default_backends(),
            ignore: Vec::new(),
            boundaries: default_boundaries(),
        }
    }
}

/// Matches a process when every field that is set matches. The match covers that process
/// and everything it starts afterwards.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IgnoreRule {
    pub name: String,
    /// Exact executable path.
    pub exe: Option<String>,
    /// Executable path prefix, e.g. a plugin's install folder.
    pub exe_prefix: Option<String>,
    /// Exact process name (comm, max 15 chars). Weak: any program can pick its own name.
    pub comm: Option<String>,
    /// Substring of the joined command line.
    pub argv_contains: Option<String>,
}

impl IgnoreRule {
    pub fn matches(&self, exe: &str, comm: &str, argv: &str) -> bool {
        self.exe.as_deref().is_none_or(|e| e == exe)
            && self
                .exe_prefix
                .as_deref()
                .is_none_or(|p| exe.starts_with(p))
            && self.comm.as_deref().is_none_or(|c| c == comm)
            && self
                .argv_contains
                .as_deref()
                .is_none_or(|s| argv.contains(s))
    }

    fn has_matcher(&self) -> bool {
        self.exe.is_some()
            || self.exe_prefix.is_some()
            || self.comm.is_some()
            || self.argv_contains.is_some()
    }
}

fn default_boundaries() -> Vec<String> {
    [
        "systemd",
        "init",
        "sshd",
        "sshd-session",
        "login",
        "cron",
        "crond",
        "tmux: server",
        "zellij",
        "foot",
        "alacritty",
        "kitty",
        "ghostty",
        "wezterm-gui",
        "Hyprland",
        "start-hyprland",
        "uwsm",
        "quickshell",
        "desl",
    ]
    .into_iter()
    .map(String::from)
    .collect()
}

/// Loads `path` if given; otherwise `./dnom.yaml`, then `~/.config/dnom/dnom.yaml`,
/// then built-in defaults. Returns the file actually used.
pub fn load(path: Option<&Path>) -> anyhow::Result<(Config, Option<PathBuf>)> {
    let candidates: Vec<PathBuf> = match path {
        Some(p) => vec![p.to_path_buf()],
        None => {
            let mut c = vec![PathBuf::from("dnom.yaml")];
            if let Some(home) = std::env::var_os("HOME") {
                c.push(Path::new(&home).join(".config/dnom/dnom.yaml"));
            }
            c
        }
    };
    for candidate in &candidates {
        if !candidate.exists() {
            continue;
        }
        let text = std::fs::read_to_string(candidate)
            .with_context(|| format!("read {}", candidate.display()))?;
        let mut config: Config = serde_saphyr::from_str(&text)
            .with_context(|| format!("parse {}", candidate.display()))?;
        config.paths.decoys = config.decoys.paths.clone();
        config.decoys.validate().with_context(|| format!("{}", candidate.display()))?;
        config.notify.validate().with_context(|| format!("{}", candidate.display()))?;
        config
            .paths
            .validate()
            .with_context(|| format!("{}: path rules", candidate.display()))?;
        config
            .redact
            .validate()
            .with_context(|| format!("{}: redaction rules", candidate.display()))?;
        config
            .assessment
            .validate()
            .with_context(|| format!("{}: assessment", candidate.display()))?;
        crate::backends::validate(&config.backend, &config.backends)
            .with_context(|| format!("{}: backends", candidate.display()))?;
        config
            .policies
            .compile(&config.assessment)
            .with_context(|| format!("{}: policies", candidate.display()))?;
        for rule in &config.ignore {
            if !rule.has_matcher() {
                bail!(
                    "{}: ignore rule '{}' needs at least one of exe, exe_prefix, comm, argv_contains",
                    candidate.display(),
                    rule.name
                );
            }
        }
        return Ok((config, Some(candidate.clone())));
    }
    if let Some(p) = path {
        bail!("config file {} not found", p.display());
    }
    Ok((Config::default(), None))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_and_custom_lists() {
        let c: Config = serde_saphyr::from_str("{}").unwrap();
        assert_eq!(
            c.paths.categorize("/etc/shadow", false),
            Some("credentials")
        );
        let c: Config = serde_saphyr::from_str(
            r#"
paths:
  credentials: [/opt/app/session]
  persistence: [/opt/app/startup/]
  system_binaries: [/opt/app/bin/]
  temp: [/scratch/]
redact:
  secret_names: [APP_SESSION]
  secret_name_parts: [PRIVATE]
  secret_flag_words: [session]
  secret_headers: [X-Session]
  token_prefixes: [company_]
"#,
        )
        .unwrap();
        c.paths.validate().unwrap();
        c.redact.validate().unwrap();
        assert_eq!(
            c.paths.categorize("/opt/app/session", false),
            Some("credentials")
        );
        assert_eq!(
            c.paths.categorize("/etc/shadow", false),
            Some("credentials")
        );
        assert_eq!(c.paths.categorize("/opt/app/startup/job", false), None);
        assert_eq!(
            c.paths.categorize("/opt/app/startup/job", true),
            Some("persistence")
        );
        assert_eq!(
            c.paths.categorize("/opt/app/bin/job", true),
            Some("system_binaries")
        );
        assert_eq!(c.paths.categorize("/scratch/x", false), Some("temp"));
        let args = [
            "tool",
            "app_session=example",
            "APP_PRIVATE=example",
            "--session",
            "example",
            "X-Session: example",
            "company_example",
            "--password=example",
            "PATH=/usr/bin",
        ]
        .map(String::from);
        assert_eq!(
            c.redact.redact_argv(&args),
            "tool app_session=[redacted] APP_PRIVATE=[redacted] --session [redacted] X-Session: [redacted] [redacted] --password=[redacted] PATH=/usr/bin"
        );
    }

    #[test]
    fn explicit_replacement_and_validation() {
        let c: Config = serde_saphyr::from_str(
            r#"
paths:
  include_defaults: false
  credentials: [/opt/app/session]
redact:
  include_defaults: false
  secret_names: [APP_SESSION]
"#,
        )
        .unwrap();
        assert_eq!(c.paths.categorize("/etc/shadow", false), None);
        assert_eq!(
            c.paths.categorize("/opt/app/session", false),
            Some("credentials")
        );
        assert_eq!(
            c.redact
                .redact_argv(&["APP_SESSION=example".into(), "TOKEN=example".into()]),
            "APP_SESSION=[redacted] TOKEN=example"
        );
        for yaml in ["paths: {credentials: ['']}", "paths: {temp: ['  ']}"] {
            let c: Config = serde_saphyr::from_str(yaml).unwrap();
            assert!(c.paths.validate().is_err());
        }
        let c: Config = serde_saphyr::from_str("redact: {token_prefixes: ['']}").unwrap();
        assert!(c.redact.validate().is_err());
        assert!(serde_saphyr::from_str::<Config>("redact: {secret_nmaes: []}").is_err());
        assert!(serde_saphyr::from_str::<Config>("paths: {credential: []}").is_err());
        // The shipped config must remain loadable too.
        let c: Config = serde_saphyr::from_str(include_str!("../../dnom.yaml")).unwrap();
        c.paths.validate().unwrap();
        c.redact.validate().unwrap();
        c.assessment.validate().unwrap();
        crate::backends::validate(&c.backend, &c.backends).unwrap();
    }
}
