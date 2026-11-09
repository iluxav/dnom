//! Path classifier (SPEC §4.2): tags file opens with a category.

pub const CREDENTIALS: &str = "credentials";
pub const PERSISTENCE: &str = "persistence";
pub const SYSTEM_BINARIES: &str = "system_binaries";
pub const TEMP: &str = "temp";

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

/// User entries extend the built-ins unless `include_defaults` is false.
#[derive(Debug, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PathRules {
    pub include_defaults: bool,
    pub credentials: Vec<String>,
    pub persistence: Vec<String>,
    pub system_binaries: Vec<String>,
    pub temp: Vec<String>,
}

impl Default for PathRules {
    fn default() -> Self {
        Self {
            include_defaults: true,
            credentials: Vec::new(),
            persistence: Vec::new(),
            system_binaries: Vec::new(),
            temp: Vec::new(),
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
        Ok(())
    }

    pub fn categorize(&self, path: &str, write: bool) -> Option<&'static str> {
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
}
