//! Path classifier (SPEC §4.2): tags file opens with a category.

pub const CREDENTIALS: &str = "credentials";
pub const PERSISTENCE: &str = "persistence";
pub const SYSTEM_BINARIES: &str = "system_binaries";
pub const TEMP: &str = "temp";
/// Files no program has a reason to open (`paths.decoys`). Listed next to a path's normal
/// category, not in place of it.
pub const DECOYS: &str = "decoys";
/// dnom's own config file or its list of generated decoys, opened by another program.
/// Reading them is how an intruder (or a rogue agent) would learn what to avoid.
pub const OWN_CONFIG: &str = "dnom_config";
/// Categories where the open itself is the signal. Kept out of what the model sees.
pub const TRIPWIRES: [&str; 2] = [DECOYS, OWN_CONFIG];

/// Matched anywhere in the path (so `~/...` patterns work for every user).
const CREDENTIAL_PATTERNS: &[&str] = &[
    "/.ssh/id_",
    "/.ssh/identity",
    "/etc/ssh/ssh_host_",
    "/etc/shadow",
    "/etc/gshadow",
    "/.aws/credentials",
    "/.config/gcloud/",
    "/.kube/config",
    "/.docker/config.json",
    "/.netrc",
    "/.git-credentials",
    "/.gnupg/private-keys-v1.d/",
    "/.password-store/",
    "/.local/share/keyrings/",
    "/.config/gh/hosts.yml",
    "/.npmrc",
    "/.pypirc",
    "/.cargo/credentials",
    "/.vault-token",
    // cloud / container credential sources
    "/var/run/secrets/kubernetes.io/serviceaccount/",
    "/run/secrets/kubernetes.io/serviceaccount/",
    "/.config/gcloud/application_default_credentials.json",
    "/.azure/accessTokens.json",
];

/// Write opens only: things that make code run again later.
const PERSISTENCE_PATTERNS: &[&str] = &[
    "/etc/cron",
    "/var/spool/cron/",
    "/etc/systemd/",
    "/usr/lib/systemd/",
    "/.config/systemd/",
    "/.local/share/systemd/",
    "/etc/rc.local",
    "/etc/init.d/",
    "/etc/profile",
    "/etc/bash.bashrc",
    "/.bashrc",
    "/.bash_profile",
    "/.bash_login",
    "/.profile",
    "/.zshrc",
    "/.zprofile",
    "/.zshenv",
    "/.config/fish/",
    "/.config/autostart/",
    "/etc/xdg/autostart/",
    "/etc/ld.so.preload",
    "/.ssh/authorized_keys",
    "/etc/sudoers",
    "/.config/hypr/",
    "/.config/environment.d/",
    "/etc/udev/rules.d/",
    "/etc/modules-load.d/",
];

/// Write opens only, matched as prefixes.
const SYSTEM_BINARY_PREFIXES: &[&str] = &[
    "/usr/bin/",
    "/usr/sbin/",
    "/bin/",
    "/sbin/",
    "/usr/local/bin/",
    "/usr/local/sbin/",
    "/usr/lib/",
    "/lib/",
    "/boot/",
];

const TEMP_PREFIXES: &[&str] = &["/tmp/", "/var/tmp/", "/dev/shm/"];

/// Container runtimes' storage (image layers, container filesystems), matched as prefixes.
/// Writes here are image content, not this machine's files: unpacking an image writes its
/// /etc/shadow, /etc/profile and crontabs. They get no category. Reads keep theirs: the host
/// reading a container's secrets is still credential access.
const CONTAINER_STORAGE_PREFIXES: &[&str] = &[
    "/var/lib/containerd/",
    "/var/lib/rancher/k3s/agent/containerd/",
    "/var/lib/docker/",
    "/var/lib/containers/",
];

/// User entries extend the built-ins unless `include_defaults` is false.
#[derive(Debug, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PathRules {
    pub include_defaults: bool,
    pub credentials: Vec<String>,
    pub persistence: Vec<String>,
    pub system_binaries: Vec<String>,
    pub temp: Vec<String>,
    /// Hand-placed decoys (`decoys.paths` in dnom.yaml, copied here when the config loads):
    /// an absolute path, or a directory (ending in `/`) for everything under it.
    #[serde(skip)]
    pub decoys: Vec<String>,
    /// Decoys dnom generated for this run (exact paths). Set while running.
    #[serde(skip)]
    pub generated: Vec<String>,
    /// Paths of the config file dnom was started with and of its list of generated decoys.
    /// Set at startup, never read from the file, and left empty when the events come from
    /// another machine.
    #[serde(skip)]
    pub own_config: Vec<String>,
}

impl Default for PathRules {
    fn default() -> Self {
        Self {
            include_defaults: true,
            credentials: Vec::new(),
            persistence: Vec::new(),
            system_binaries: Vec::new(),
            temp: Vec::new(),
            decoys: Vec::new(),
            generated: Vec::new(),
            own_config: Vec::new(),
        }
    }
}

impl PathRules {
    pub fn validate(&self) -> anyhow::Result<()> {
        for (name, patterns) in [
            ("credentials", &self.credentials),
            ("persistence", &self.persistence),
            ("system_binaries", &self.system_binaries),
            ("temp", &self.temp),
        ] {
            anyhow::ensure!(
                patterns.iter().all(|p| !p.trim().is_empty()),
                "paths.{name}: empty patterns are not allowed"
            );
        }
        for d in &self.decoys {
            anyhow::ensure!(
                d.starts_with('/') && d.trim() == d && d.len() > 1,
                "decoys.paths: '{d}' must be an absolute path (a file, or a directory ending in /)"
            );
        }
        Ok(())
    }

    /// Any open of a decoy counts, read or write. Exact path, or anything under a listed
    /// directory: decoys must never match by accident.
    pub fn is_decoy(&self, path: &str) -> bool {
        self.generated.iter().any(|g| g == path)
            || self.decoys.iter().any(|d| if d.ends_with('/') { path.starts_with(d.as_str()) } else { path == d })
    }

    /// The tripwire category of a path, if opening it is itself the signal.
    pub fn tripwire(&self, path: &str) -> Option<&'static str> {
        if self.own_config.iter().any(|c| c == path) {
            return Some(OWN_CONFIG);
        }
        self.is_decoy(path).then_some(DECOYS)
    }

    pub fn categorize(&self, path: &str, write: bool) -> Option<&'static str> {
        if write && CONTAINER_STORAGE_PREFIXES.iter().any(|p| path.starts_with(p)) {
            return None;
        }
        let matches = |custom: &[String], defaults: &[&str], prefix: bool| {
            let check = |p: &str| {
                if prefix {
                    path.starts_with(p)
                } else {
                    path.contains(p)
                }
            };
            custom.iter().any(|p| check(p))
                || (self.include_defaults && defaults.iter().any(|p| check(p)))
        };
        if matches(&self.credentials, CREDENTIAL_PATTERNS, false) && !path.ends_with(".pub") {
            return Some(CREDENTIALS);
        }
        if write && matches(&self.persistence, PERSISTENCE_PATTERNS, false) {
            return Some(PERSISTENCE);
        }
        if write && matches(&self.system_binaries, SYSTEM_BINARY_PREFIXES, true) {
            return Some(SYSTEM_BINARIES);
        }
        if matches(&self.temp, TEMP_PREFIXES, true) {
            return Some(TEMP);
        }
        None
    }
}

pub fn is_sensitive(category: &str) -> bool {
    category != TEMP
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn categories() {
        let rules = PathRules::default();
        assert_eq!(
            rules.categorize("/home/a/.ssh/id_ed25519", false),
            Some(CREDENTIALS)
        );
        assert_eq!(rules.categorize("/home/a/.ssh/id_ed25519.pub", false), None);
        assert_eq!(
            rules.categorize("/tmp/x/.ssh/id_rsa", true),
            Some(CREDENTIALS)
        );
        assert_eq!(rules.categorize("/home/a/.bashrc", false), None);
        assert_eq!(rules.categorize("/home/a/.bashrc", true), Some(PERSISTENCE));
        assert_eq!(rules.categorize("/usr/bin/ls", true), Some(SYSTEM_BINARIES));
        assert_eq!(rules.categorize("/usr/bin/ls", false), None);
        assert_eq!(rules.categorize("/tmp/foo", false), Some(TEMP));
        // Read at every login / by systemd: not credentials. environment.d is persistence.
        assert_eq!(rules.categorize("/etc/environment", false), None);
        assert_eq!(
            rules.categorize("/home/a/.config/environment.d/10-path.conf", false),
            None
        );
        assert_eq!(
            rules.categorize("/home/a/.config/environment.d/10-path.conf", true),
            Some(PERSISTENCE)
        );
    }

    #[test]
    fn decoys_match_exactly_or_under_a_directory() {
        let rules = PathRules {
            decoys: vec!["/srv/backup/db-credentials.txt".into(), "/opt/keys-old/".into()],
            ..Default::default()
        };
        rules.validate().unwrap();
        assert!(rules.is_decoy("/srv/backup/db-credentials.txt"));
        assert!(rules.is_decoy("/opt/keys-old/id_rsa"));
        assert!(!rules.is_decoy("/srv/backup/db-credentials.txt.bak"), "no prefix match for files");
        assert!(!rules.is_decoy("/home/a/srv/backup/db-credentials.txt"), "not anywhere in the path");
        assert!(!rules.is_decoy("/opt/keys-old"));
        assert_eq!(rules.tripwire("/opt/keys-old/id_rsa"), Some(DECOYS));
        assert_eq!(rules.tripwire("/etc/dnom/dnom.yaml"), None, "only when dnom runs with that config");
        let rules = PathRules { own_config: vec!["/etc/dnom/dnom.yaml".into()], ..rules };
        assert_eq!(rules.tripwire("/etc/dnom/dnom.yaml"), Some(OWN_CONFIG));
        // A decoy keeps its normal category too.
        assert_eq!(rules.categorize("/opt/keys-old/.ssh/id_rsa", false), Some(CREDENTIALS));
        assert_eq!(rules.categorize("/srv/backup/db-credentials.txt", false), None);
        for bad in ["relative/path", "~/.aws/decoy", "/", " /x"] {
            let rules = PathRules { decoys: vec![bad.into()], ..Default::default() };
            assert!(rules.validate().is_err(), "{bad}");
        }
    }

    /// Seen in the k3s lab run: containerd unpacking an Alpine image writes the image's
    /// /etc/shadow, /etc/profile and crontab into its storage.
    #[test]
    fn container_storage_writes_are_image_content() {
        let rules = PathRules::default();
        let k3s = "/var/lib/rancher/k3s/agent/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/27/fs";
        for p in ["/etc/shadow", "/etc/profile", "/etc/crontabs/root", "/usr/bin/ls"] {
            assert_eq!(rules.categorize(&format!("{k3s}{p}"), true), None, "{p}");
        }
        assert_eq!(rules.categorize("/var/lib/containerd/tmpmounts/containerd-mount1/etc/shadow", true), None);
        assert_eq!(rules.categorize("/var/lib/docker/overlay2/ab12/diff/root/.bashrc", true), None);
        // Reading a container's secrets from the host is still credential access.
        assert_eq!(rules.categorize("/var/lib/docker/overlay2/ab12/merged/etc/shadow", false), Some(CREDENTIALS));
        // The same files outside runtime storage keep their categories.
        assert_eq!(rules.categorize("/etc/shadow", true), Some(CREDENTIALS));
        assert_eq!(rules.categorize("/etc/profile", true), Some(PERSISTENCE));
    }
}
