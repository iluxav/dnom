//! Routine reads (`routine` in dnom.yaml): a daemon reading the files of its own job.
//!
//! sshd reads its host keys and /etc/shadow for every connection, cron reads /etc/shadow for
//! every job. Every server does this all day; on one reachable from the internet, each login
//! attempt would otherwise be a model call.
//!
//! A routine read is still recorded in the episode, but it is not a reason to assess it. It
//! counts again once the episode contacts a new destination. A rule never covers a write, a
//! decoy, a process in a container, or the same file read by another program.
//!
//! Programs are matched by the path they were executed with, so rules belong to programs in
//! places only root can write. A process that controls what a path points to (root, or one in
//! a mount namespace of its own) can pass as that program.

use serde::Deserialize;

struct Builtin {
    exes: &'static [&'static str],
    paths: &'static [&'static str],
}

/// Measured on a public Ubuntu server: 44 login attempts from the internet and 16 cron jobs
/// in 2 h 15 min, each an episode with nothing in it but these reads.
const BUILTINS: &[Builtin] = &[
    // One process per connection: sshd itself, or sshd-session / sshd-auth (OpenSSH 9.8 / 10.0)
    // in the places Debian, Fedora, Arch and upstream install them.
    Builtin {
        exes: &[
            "/usr/sbin/sshd",
            "/usr/bin/sshd",
            "/usr/lib/openssh/sshd-session",
            "/usr/lib/openssh/sshd-auth",
            "/usr/libexec/openssh/sshd-session",
            "/usr/libexec/openssh/sshd-auth",
            "/usr/lib/ssh/sshd-session",
            "/usr/lib/ssh/sshd-auth",
            "/usr/libexec/sshd-session",
            "/usr/libexec/sshd-auth",
        ],
        paths: &["/etc/ssh/ssh_host_*", "/etc/shadow"],
    },
    // cron opens a PAM session for every job it starts.
    Builtin { exes: &["/usr/sbin/cron", "/usr/sbin/crond", "/usr/bin/crond"], paths: &["/etc/shadow"] },
];

/// Places a program can be started from without being installed there.
const UNTRUSTED_EXE_PREFIXES: &[&str] = &["/proc/", "/dev/", "/tmp/", "/var/tmp/", "/home/"];

/// One program and the files that are its own.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutineRead {
    pub name: String,
    /// Exact path of the program, as it is executed.
    pub exe: String,
    /// A file, a directory (ending in `/`) for everything under it, or a prefix ending in `*`.
    pub paths: Vec<String>,
}

/// User rules extend the built-ins unless `include_defaults` is false.
#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RoutineConfig {
    pub include_defaults: bool,
    pub reads: Vec<RoutineRead>,
}

impl Default for RoutineConfig {
    fn default() -> Self {
        Self { include_defaults: true, reads: Vec::new() }
    }
}

impl RoutineConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        for r in &self.reads {
            let name = &r.name;
            anyhow::ensure!(!name.trim().is_empty(), "routine.reads: every rule needs a name");
            anyhow::ensure!(
                r.exe.starts_with('/') && !r.exe.ends_with('/') && !r.exe.contains('*') && !r.exe.contains("/../"),
                "routine.reads '{name}': exe '{}' must be the program's full path",
                r.exe
            );
            anyhow::ensure!(
                !UNTRUSTED_EXE_PREFIXES.iter().any(|p| r.exe.starts_with(p)),
                "routine.reads '{name}': exe '{}' is in a place any user can put a program",
                r.exe
            );
            anyhow::ensure!(!r.paths.is_empty(), "routine.reads '{name}': paths is empty");
            for p in &r.paths {
                let fixed = p.strip_suffix('*').unwrap_or(p);
                anyhow::ensure!(
                    fixed.starts_with('/') && fixed.len() > 1 && !fixed.contains('*') && !fixed.contains("/../") && fixed.trim() == fixed,
                    "routine.reads '{name}': path '{p}' must be an absolute file, a directory ending in /, or a prefix ending in *"
                );
            }
        }
        Ok(())
    }

    /// True if `path` is one of the files `exe` reads as part of its own job.
    pub fn covers(&self, exe: &str, path: &str) -> bool {
        // A path that climbs back out could name any file under a listed directory.
        if path.contains("/../") || path.ends_with("/..") {
            return false;
        }
        self.reads.iter().any(|r| r.exe == exe && r.paths.iter().any(|p| path_matches(p, path)))
            || (self.include_defaults
                && BUILTINS.iter().any(|b| b.exes.contains(&exe) && b.paths.iter().any(|p| path_matches(p, path))))
    }
}

fn path_matches(pattern: &str, path: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix('*') {
        path.starts_with(prefix)
    } else if pattern.ends_with('/') {
        path.starts_with(pattern)
    } else {
        pattern == path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtins_cover_a_daemon_and_its_own_files_only() {
        let r = RoutineConfig::default();
        assert!(r.covers("/usr/sbin/sshd", "/etc/ssh/ssh_host_ed25519_key"));
        assert!(r.covers("/usr/sbin/sshd", "/etc/shadow"));
        assert!(r.covers("/usr/lib/ssh/sshd-session", "/etc/shadow"));
        assert!(r.covers("/usr/sbin/cron", "/etc/shadow"));
        // Another program, another file, a copy of the file elsewhere, a lookalike program.
        assert!(!r.covers("/usr/bin/cat", "/etc/shadow"));
        assert!(!r.covers("/usr/sbin/cron", "/etc/ssh/ssh_host_rsa_key"));
        assert!(!r.covers("/usr/sbin/sshd", "/root/.ssh/id_ed25519"));
        assert!(!r.covers("/usr/sbin/sshd", "/var/lib/docker/overlay2/ab12/merged/etc/shadow"));
        assert!(!r.covers("/tmp/usr/sbin/sshd", "/etc/shadow"));
        assert!(!r.covers("sshd", "/etc/shadow"));
        // systemd's helper is executed through a file descriptor: not a path anyone can trust.
        assert!(!r.covers("/proc/self/fd/9", "/etc/shadow"));

        let off = RoutineConfig { include_defaults: false, reads: Vec::new() };
        assert!(!off.covers("/usr/sbin/sshd", "/etc/shadow"));
    }

    #[test]
    fn custom_rules_and_validation() {
        let r: RoutineConfig = serde_saphyr::from_str(
            r#"
reads:
  - name: deploy-key
    exe: /usr/bin/ssh
    paths: [/var/lib/app/keys/, /etc/app/token, "/srv/app/key_*"]
"#,
        )
        .unwrap();
        r.validate().unwrap();
        assert!(r.covers("/usr/bin/ssh", "/var/lib/app/keys/deploy"));
        assert!(r.covers("/usr/bin/ssh", "/etc/app/token"));
        assert!(r.covers("/usr/bin/ssh", "/srv/app/key_rsa"));
        assert!(!r.covers("/usr/bin/ssh", "/etc/app/token.bak"), "a file matches exactly");
        assert!(!r.covers("/usr/bin/ssh", "/var/lib/app/keys"), "the directory itself is not under it");
        assert!(!r.covers("/usr/bin/ssh", "/var/lib/app/keys/../../../root/.ssh/id_rsa"), "no climbing out");
        assert!(!r.covers("/usr/bin/scp", "/etc/app/token"));
        assert!(r.covers("/usr/sbin/sshd", "/etc/shadow"), "built-ins stay");

        let rule = |exe: &str, paths: &[&str]| RoutineConfig {
            include_defaults: true,
            reads: vec![RoutineRead { name: "x".into(), exe: exe.into(), paths: paths.iter().map(|p| p.to_string()).collect() }],
        };
        for exe in ["ssh", "/usr/bin/", "/usr/bin/*", "/proc/self/fd/9", "/tmp/ssh", "/home/a/bin/ssh", "/usr/bin/../bin/ssh"] {
            assert!(rule(exe, &["/etc/app/token"]).validate().is_err(), "{exe}");
        }
        for path in ["token", "/", "/*", "*", "/etc/*/token", " /etc/app/token", "/etc/app/../shadow"] {
            assert!(rule("/usr/bin/ssh", &[path]).validate().is_err(), "{path}");
        }
        assert!(rule("/usr/bin/ssh", &[]).validate().is_err(), "no paths");
        assert!(serde_saphyr::from_str::<RoutineConfig>("{raeds: []}").is_err());
    }
}
