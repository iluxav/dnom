//! Removes likely secrets from command lines before episodes leave the machine.
//!
//! Best effort, pattern based: catches the common shapes (password/token flags, auth headers,
//! `SECRET_NAME=value`, credentials in URLs, well-known token prefixes). It will miss secrets
//! with no recognisable shape.

pub const MASK: &str = "[redacted]";

/// Flag names (lowercase, without value) whose value is a secret.
const SECRET_FLAG_WORDS: &[&str] = &[
    "password", "passwd", "token", "secret", "api-key", "apikey", "api_key",
];

/// Prefixes of well-known API tokens and keys.
const TOKEN_PREFIXES: &[&str] = &[
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "github_pat_",
    "glpat-",
    "sk-",
    "sk_live_",
    "sk_test_",
    "rk_live_",
    "xoxb-",
    "xoxp-",
    "xapp-",
    "AKIA",
    "ASIA",
    "AIza",
    "ya29.",
    "eyJ",
];

/// Parts of environment-variable names that mark the value as secret.
const SECRET_NAME_PARTS: &[&str] = &[
    "KEY",
    "TOKEN",
    "SECRET",
    "PASS",
    "PWD",
    "AUTH",
    "CREDENTIAL",
];

/// Header names whose value is a secret (curl -H, wget --header).
const SECRET_HEADERS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "x-api-key",
    "cookie",
    "x-auth-token",
];

/// Custom rules extend built-ins by default. Name fragments and headers are
/// case-insensitive; token prefixes are case-sensitive.
#[derive(Debug, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RedactRules {
    pub include_defaults: bool,
    pub secret_flag_words: Vec<String>,
    pub token_prefixes: Vec<String>,
    pub secret_name_parts: Vec<String>,
    pub secret_names: Vec<String>,
    pub secret_headers: Vec<String>,
}

impl Default for RedactRules {
    fn default() -> Self {
        Self {
            include_defaults: true,
            secret_flag_words: Vec::new(),
            token_prefixes: Vec::new(),
            secret_name_parts: Vec::new(),
            secret_names: Vec::new(),
            secret_headers: Vec::new(),
        }
    }
}

impl RedactRules {
    pub fn validate(&self) -> anyhow::Result<()> {
        for (name, patterns) in [
            ("secret_flag_words", &self.secret_flag_words),
            ("token_prefixes", &self.token_prefixes),
            ("secret_name_parts", &self.secret_name_parts),
            ("secret_names", &self.secret_names),
            ("secret_headers", &self.secret_headers),
        ] {
            anyhow::ensure!(
                patterns.iter().all(|p| !p.trim().is_empty()),
                "redact.{name}: empty patterns are not allowed"
            );
        }
        Ok(())
    }

    /// Joins argv into one string with secrets replaced by [`MASK`].
    pub fn redact_argv(&self, argv: &[String]) -> String {
        let program = argv
            .first()
            .map(|a| a.rsplit('/').next().unwrap_or(a).to_string())
            .unwrap_or_default();
        let mut out = Vec::with_capacity(argv.len());
        let mut mask_next = false;
        for arg in argv {
            if mask_next {
                out.push(MASK.to_string());
                mask_next = false;
                continue;
            }
            out.push(self.redact_arg(&program, arg, &mut mask_next));
        }
        out.join(" ")
    }

    fn is_secret_flag(&self, flag: &str) -> bool {
        let flag = flag.trim_start_matches('-').to_ascii_lowercase();
        !flag.is_empty()
            && (self
                .secret_flag_words
                .iter()
                .any(|w| flag.contains(&w.to_ascii_lowercase()))
                || (self.include_defaults && SECRET_FLAG_WORDS.iter().any(|w| flag.contains(w))))
    }

    fn is_secret_name(&self, name: &str) -> bool {
        !name.is_empty()
            && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            && (self
                .secret_names
                .iter()
                .any(|p| name.eq_ignore_ascii_case(p))
                || self
                    .secret_name_parts
                    .iter()
                    .any(|p| name.to_ascii_uppercase().contains(&p.to_ascii_uppercase()))
                || (self.include_defaults
                    && SECRET_NAME_PARTS
                        .iter()
                        .any(|p| name.to_ascii_uppercase().contains(p))))
    }

    fn redact_arg(&self, program: &str, arg: &str, mask_next: &mut bool) -> String {
        // --password=x, --api-key=x, GITHUB_TOKEN=x
        if let Some((name, _)) = arg.split_once('=') {
            if (name.starts_with('-') && self.is_secret_flag(name)) || self.is_secret_name(name) {
                return format!("{name}={MASK}");
            }
        }
        // --password x (value is the next argument)
        if arg.starts_with("--") && self.is_secret_flag(arg) {
            *mask_next = true;
            return arg.to_string();
        }
        // sshpass -p PASSWORD
        if program == "sshpass" && arg == "-p" {
            *mask_next = true;
            return arg.to_string();
        }
        // mysql -pPASSWORD (attached value; plain -p prompts instead)
        if matches!(program, "mysql" | "mariadb" | "mysqldump" | "mysqladmin")
            && arg.starts_with("-p")
            && !arg.starts_with("--")
            && arg.len() > 2
        {
            return format!("-p{MASK}");
        }
        // "Authorization: Bearer x" as a header argument
        if let Some((name, _)) = arg.split_once(':')
            && (self
                .secret_headers
                .iter()
                .any(|p| name.trim().eq_ignore_ascii_case(p))
                || (self.include_defaults
                    && SECRET_HEADERS.contains(&name.trim().to_ascii_lowercase().as_str())))
        {
            return format!("{name}: {MASK}");
        }
        // scheme://user:password@host
        if let Some(scheme_end) = arg.find("://") {
            let rest = &arg[scheme_end + 3..];
            if let Some(at) = rest.find('@') {
                let userinfo = &rest[..at];
                if let Some(colon) = userinfo.find(':')
                    && !userinfo.contains('/')
                {
                    let user = &userinfo[..colon];
                    return format!("{}://{user}:{MASK}@{}", &arg[..scheme_end], &rest[at + 1..]);
                }
            }
        }
        // "... Bearer x" inside a longer argument
        if let Some(pos) = arg.to_ascii_lowercase().find("bearer ") {
            return format!("{}{MASK}", &arg[..pos + "bearer ".len()]);
        }
        // A bare token with a well-known prefix
        if self.token_prefixes.iter().any(|p| arg.starts_with(p))
            || (self.include_defaults
                && arg.len() >= 16
                && TOKEN_PREFIXES.iter().any(|p| arg.starts_with(p)))
        {
            return MASK.to_string();
        }
        arg.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(args: &[&str]) -> String {
        RedactRules::default().redact_argv(&args.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn redacts_common_secret_shapes() {
        assert_eq!(
            r(&["mysql", "-uroot", "-pHunter2", "db"]),
            "mysql -uroot -p[redacted] db"
        );
        assert_eq!(r(&["mkdir", "-pv", "/tmp/x"]), "mkdir -pv /tmp/x");
        assert_eq!(
            r(&[
                "curl",
                "-H",
                "Authorization: Bearer abc.def",
                "https://api.example.com"
            ]),
            "curl -H Authorization: [redacted] https://api.example.com"
        );
        assert_eq!(
            r(&["tool", "--password", "s3cret", "--user", "me"]),
            "tool --password [redacted] --user me"
        );
        assert_eq!(
            r(&["tool", "--api-key=abc123"]),
            "tool --api-key=[redacted]"
        );
        assert_eq!(
            r(&["env", "GITHUB_TOKEN=ghp_x", "PATH=/usr/bin", "make"]),
            "env GITHUB_TOKEN=[redacted] PATH=/usr/bin make"
        );
        assert_eq!(
            r(&["git", "clone", "https://bob:pw123@git.example.com/repo.git"]),
            "git clone https://bob:[redacted]@git.example.com/repo.git"
        );
        assert_eq!(
            r(&[
                "gh",
                "auth",
                "login",
                "--with-token",
                "ghp_abcdefghijklmnop1234"
            ]),
            "gh auth login --with-token [redacted]"
        );
        assert_eq!(
            r(&["aws", "configure", "set", "x", "AKIAABCDEFGHIJKLMNOP"]),
            "aws configure set x [redacted]"
        );
        assert_eq!(
            r(&["sshpass", "-p", "pw", "ssh", "host"]),
            "sshpass -p [redacted] ssh host"
        );
        assert_eq!(r(&["ssh", "-p", "2222", "host"]), "ssh -p 2222 host");
        assert_eq!(r(&["make", "fake-exfil"]), "make fake-exfil");
    }
}
