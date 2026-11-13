//! Model backends (`backends:` in dnom.yaml): where episodes are sent and how to log in.
//!
//! Three API shapes cover the decision-model providers:
//!   systemone  Jev's System One API: Jev, Kev, Laya (laya-serve), Liquid d1, Cloudflare Clef
//!   openai     OpenAI's Decisions API (predicate / choice / score, answers as a list)
//!   ollama     a local chat model emulating typed answers from token probabilities
//!
//! API keys never live in dnom.yaml. A backend names the environment variable that holds
//! its key (`api_key_env`); dnom reads that variable, or the same name from `./.env`.
//! `url` may contain `${NAME}` placeholders (e.g. a Cloudflare account id), resolved the same
//! way.

use std::collections::BTreeMap;

use anyhow::{Context as _, anyhow, ensure};
use serde::Deserialize;

/// Reserved backend name: build episodes, ask no model.
pub const NONE: &str = "none";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BackendType {
    /// System One API (`POST <url>/v1/systemone`): Jev, Kev, Laya, Liquid d1, Clef.
    /// `jev` is accepted as an older name.
    #[serde(alias = "jev")]
    Systemone,
    /// OpenAI Decisions API (`POST <url>/v1/decisions`).
    Openai,
    /// Ollama chat API, answering each question with one token (slow; see SPEC §7).
    Ollama,
}

impl BackendType {
    fn default_path(self) -> &'static str {
        match self {
            BackendType::Systemone => "/v1/systemone",
            BackendType::Openai => "/v1/decisions",
            BackendType::Ollama => "/api/chat",
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackendDef {
    #[serde(rename = "type")]
    pub kind: BackendType,
    /// Base URL, e.g. https://api.typesafe.ai or http://127.0.0.1:11434. May contain
    /// `${NAME}` placeholders, read from the environment or ./.env.
    pub url: String,
    /// Request path appended to `url`. Default: /v1/systemone, /v1/decisions or /api/chat.
    #[serde(default)]
    pub path: Option<String>,
    pub model: String,
    /// Name of the environment variable (or `.env` entry) holding the API key, sent as
    /// `Authorization: Bearer <key>`. Leave out for backends without auth.
    #[serde(default)]
    pub api_key_env: Option<String>,
    /// Request timeout. Default 60 s for jev, 300 s for ollama (first call loads the model).
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

impl BackendDef {
    pub fn timeout_secs(&self) -> u64 {
        self.timeout_secs.unwrap_or(match self.kind {
            BackendType::Systemone | BackendType::Openai => 60,
            BackendType::Ollama => 300,
        })
    }

    /// Full request URL: `url` with placeholders filled in, plus the path.
    pub fn endpoint(&self) -> anyhow::Result<String> {
        let base = expand_vars(&self.url)?;
        let path = self.path.as_deref().unwrap_or(self.kind.default_path());
        Ok(format!("{}{path}", base.trim_end_matches('/')))
    }

    /// Host part of `url` (no scheme, port or path).
    pub fn host(&self) -> &str {
        host_of(&self.url)
    }

    /// True unless the URL points at this machine. Remote backends get the `--only` guard.
    pub fn is_remote(&self) -> bool {
        !is_loopback(self.host())
    }

    /// The API key, if this backend uses one: the named environment variable, else the
    /// same name in `./.env`.
    pub fn api_key(&self) -> anyhow::Result<Option<String>> {
        let Some(var) = &self.api_key_env else { return Ok(None) };
        let key = std::env::var(var)
            .ok()
            .filter(|v| !v.is_empty())
            .or_else(|| dotenv_value(".env", var))
            .ok_or_else(|| anyhow!("no API key: set {var} in the environment or in .env"))?;
        Ok(Some(key))
    }
}

pub fn default_backend() -> String {
    "jev".into()
}

pub fn default_backends() -> BTreeMap<String, BackendDef> {
    BTreeMap::from([
        (
            "jev".to_string(),
            BackendDef {
                kind: BackendType::Systemone,
                url: "https://api.typesafe.ai".into(),
                path: None,
                model: "jev-latest".into(),
                api_key_env: Some("TYPESAFE_API_KEY".into()),
                timeout_secs: None,
            },
        ),
        (
            "local".to_string(),
            BackendDef {
                kind: BackendType::Ollama,
                url: "http://127.0.0.1:11434".into(),
                path: None,
                model: "qwen3.6:27b-q8_0".into(),
                api_key_env: None,
                timeout_secs: None,
            },
        ),
    ])
}

/// Checks `backends:` and that `backend:` (the default) names one of them.
pub fn validate(default: &str, defs: &BTreeMap<String, BackendDef>) -> anyhow::Result<()> {
    ensure!(!defs.is_empty(), "backends needs at least one backend");
    for (name, b) in defs {
        ensure!(
            !name.is_empty()
                && name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-'),
            "backends: name '{name}' must use only a-z, 0-9, _ and -"
        );
        ensure!(name != NONE, "backends: '{NONE}' is reserved for running without a model");
        let at = format!("backends.{name}");
        let scheme_ok = b.url.starts_with("http://") || b.url.starts_with("https://");
        ensure!(scheme_ok && !b.host().is_empty(), "{at}: url must start with http:// or https://");
        ensure!(!b.model.trim().is_empty(), "{at}: model must not be empty");
        if let Some(path) = &b.path {
            ensure!(path.starts_with('/'), "{at}: path must start with /");
        }
        for name in placeholders(&b.url)? {
            ensure!(
                !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'),
                "{at}: url placeholder '${{{name}}}' must be an environment variable name"
            );
        }
        if let Some(var) = &b.api_key_env {
            ensure!(
                !var.is_empty() && var.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'),
                "{at}: api_key_env is the NAME of an environment variable (letters, digits, _), \
                 not the key itself"
            );
            ensure!(
                b.url.starts_with("https://") || !b.is_remote(),
                "{at}: the API key would be sent unencrypted to {}; use https://",
                b.host()
            );
        }
        if let Some(t) = b.timeout_secs {
            ensure!((1..=600).contains(&t), "{at}: timeout_secs must be 1 to 600");
        }
    }
    ensure!(
        default == NONE || defs.contains_key(default),
        "backend: '{default}' is not defined under backends"
    );
    Ok(())
}

/// The backend `--backend <name>` (or the default) refers to; `None` for "none".
pub fn select<'a>(
    defs: &'a BTreeMap<String, BackendDef>,
    default: &str,
    name: Option<&str>,
) -> anyhow::Result<Option<(String, &'a BackendDef)>> {
    let name = name.unwrap_or(default);
    if name == NONE {
        return Ok(None);
    }
    let def = defs.get(name).with_context(|| {
        let known: Vec<&str> = defs.keys().map(String::as_str).collect();
        format!("unknown backend '{name}'; dnom.yaml defines: {}, or use none", known.join(", "))
    })?;
    Ok(Some((name.to_string(), def)))
}

/// Names used as `${NAME}` in `s`.
fn placeholders(s: &str) -> anyhow::Result<Vec<String>> {
    let mut names = Vec::new();
    let mut rest = s;
    while let Some(start) = rest.find("${") {
        let after = &rest[start + 2..];
        let end = after.find('}').ok_or_else(|| anyhow!("unclosed ${{ in '{s}'"))?;
        names.push(after[..end].to_string());
        rest = &after[end + 1..];
    }
    Ok(names)
}

/// Replaces `${NAME}` with the variable from the environment, else from ./.env.
fn expand_vars(s: &str) -> anyhow::Result<String> {
    let mut out = s.to_string();
    for name in placeholders(s)? {
        let value = std::env::var(&name)
            .ok()
            .filter(|v| !v.is_empty())
            .or_else(|| dotenv_value(".env", &name))
            .ok_or_else(|| anyhow!("url uses ${{{name}}}, which is not set (environment or .env)"))?;
        out = out.replace(&format!("${{{name}}}"), &value);
    }
    Ok(out)
}

fn host_of(url: &str) -> &str {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let authority = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    if let Some(v6) = authority.strip_prefix('[') {
        return v6.split(']').next().unwrap_or("");
    }
    authority.split(':').next().unwrap_or("")
}

fn is_loopback(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host == "::1"
        || host.parse::<std::net::Ipv4Addr>().is_ok_and(|ip| ip.is_loopback())
}

/// Reads `KEY=value` (optionally `export KEY="value"`) from a dotenv file without
/// touching the process environment.
pub(crate) fn dotenv_value(path: &str, key: &str) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    text.lines().find_map(|line| {
        let line = line.trim();
        let line = line.strip_prefix("export ").unwrap_or(line);
        let (k, v) = line.split_once('=')?;
        if k.trim() != key {
            return None;
        }
        let v = v.trim().trim_matches(|c| c == '"' || c == '\'');
        (!v.is_empty()).then(|| v.to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn parse(yaml: &str) -> Config {
        serde_saphyr::from_str(yaml).unwrap()
    }

    fn check(c: &Config) -> anyhow::Result<()> {
        validate(&c.backend, &c.backends)
    }

    #[test]
    fn builtins_and_selection() {
        let c = Config::default();
        check(&c).unwrap();
        let (name, jev) = select(&c.backends, &c.backend, None).unwrap().unwrap();
        assert_eq!((name.as_str(), jev.kind, jev.is_remote()), ("jev", BackendType::Systemone, true));
        assert_eq!(jev.endpoint().unwrap(), "https://api.typesafe.ai/v1/systemone");
        let (_, local) = select(&c.backends, &c.backend, Some("local")).unwrap().unwrap();
        assert!(!local.is_remote());
        assert!(select(&c.backends, &c.backend, Some("none")).unwrap().is_none());
        let err = select(&c.backends, &c.backend, Some("nope")).unwrap_err().to_string();
        assert!(err.contains("defines: jev, local"), "{err}");
    }

    #[test]
    fn hosts_and_remoteness() {
        for (url, host, remote) in [
            ("https://api.typesafe.ai", "api.typesafe.ai", true),
            ("http://127.0.0.1:11434/x", "127.0.0.1", false),
            ("http://localhost:8009", "localhost", false),
            ("http://[::1]:8009", "::1", false),
            ("http://10.0.0.5:8009", "10.0.0.5", true),
        ] {
            let b = BackendDef {
                kind: BackendType::Systemone,
                url: url.into(),
                path: None,
                model: "m".into(),
                api_key_env: None,
                timeout_secs: None,
            };
            assert_eq!((b.host(), b.is_remote()), (host, remote), "{url}");
        }
    }

    #[test]
    fn custom_backend_reads_named_key() {
        let c = parse(
            "backend: kev\nbackends:\n  kev: {type: jev, url: 'http://127.0.0.1:8009', model: kev-latest}\n  \
             corp: {type: jev, url: 'https://jev.corp.example', model: jev-latest, api_key_env: DNOM_TEST_CORP_KEY}\n",
        );
        check(&c).unwrap();
        let (_, kev) = select(&c.backends, &c.backend, None).unwrap().unwrap();
        assert_eq!(kev.api_key().unwrap(), None);
        let (_, corp) = select(&c.backends, &c.backend, Some("corp")).unwrap().unwrap();
        // SAFETY: test-only variable name that no other test reads.
        unsafe { std::env::set_var("DNOM_TEST_CORP_KEY", "k-123") };
        assert_eq!(corp.api_key().unwrap().as_deref(), Some("k-123"));
        unsafe { std::env::remove_var("DNOM_TEST_CORP_KEY") };
        assert!(corp.api_key().unwrap_err().to_string().contains("DNOM_TEST_CORP_KEY"));
    }

    #[test]
    fn providers_endpoints_and_placeholders() {
        let c = parse(
            "backend: kev\nbackends:\n  \
             kev: {type: systemone, url: 'http://127.0.0.1:8009', model: kev-4b}\n  \
             liquid: {type: systemone, url: 'https://api.liquid.ai/decisions', model: d1, api_key_env: LIQUID_API_KEY}\n  \
             clef: {type: systemone, url: 'https://api.cloudflare.com/client/v4/accounts/${DNOM_TEST_CF_ACCOUNT}', \
             path: /ai/run/@cf/cloudflare/clef, model: clef, api_key_env: CLOUDFLARE_API_TOKEN}\n  \
             openai: {type: openai, url: 'https://api.openai.com', model: gpt-6-luna, api_key_env: OPENAI_API_KEY}\n  \
             old: {type: jev, url: 'https://api.typesafe.ai', model: jev-latest}\n",
        );
        check(&c).unwrap();
        let ep = |n: &str| c.backends[n].endpoint();
        assert_eq!(ep("kev").unwrap(), "http://127.0.0.1:8009/v1/systemone");
        assert_eq!(ep("liquid").unwrap(), "https://api.liquid.ai/decisions/v1/systemone");
        assert_eq!(ep("openai").unwrap(), "https://api.openai.com/v1/decisions");
        assert_eq!(c.backends["old"].kind, BackendType::Systemone);
        // Placeholder not set: a clear error naming it.
        assert!(ep("clef").unwrap_err().to_string().contains("DNOM_TEST_CF_ACCOUNT"));
        // SAFETY: test-only variable name that no other test reads.
        unsafe { std::env::set_var("DNOM_TEST_CF_ACCOUNT", "abc123") };
        assert_eq!(
            ep("clef").unwrap(),
            "https://api.cloudflare.com/client/v4/accounts/abc123/ai/run/@cf/cloudflare/clef"
        );
        unsafe { std::env::remove_var("DNOM_TEST_CF_ACCOUNT") };
        // The placeholder is in the path part, so the host is still known for the guard.
        assert!(c.backends["clef"].is_remote());
    }

    #[test]
    fn rejects_bad_backends() {
        let bad = [
            ("backends:\n  jev: {type: jev, url: 'api.example', model: m}", "http:// or https://"),
            ("backends:\n  jev: {type: jev, url: 'https://a.example', model: ' '}", "model must not be empty"),
            (
                "backends:\n  jev: {type: jev, url: 'https://a.example', model: m, api_key_env: 'sk-abc.def'}",
                "NAME of an environment variable",
            ),
            ("backends:\n  jev: {type: jev, url: 'http://a.example', model: m, api_key_env: KEY}", "unencrypted"),
            ("backend: none\nbackends:\n  none: {type: jev, url: 'https://a.example', model: m}", "reserved"),
            ("backend: missing", "not defined"),
            ("backends:\n  jev: {type: jev, url: 'https://a.example', model: m, timeout_secs: 0}", "1 to 600"),
            ("backends:\n  jev: {type: jev, url: 'https://a.example', model: m, path: v1/x}", "must start with /"),
            ("backends:\n  jev: {type: jev, url: 'https://a.example/${bad-name}', model: m}", "environment variable name"),
        ];
        for (yaml, want) in bad {
            let err = check(&parse(yaml)).unwrap_err().to_string();
            assert!(err.contains(want), "{yaml:?}: got {err:?}, want {want:?}");
        }
        // Plain http to this machine with a key is fine: nothing crosses the network.
        check(&parse("backends:\n  jev: {type: jev, url: 'http://127.0.0.1:8009', model: m, api_key_env: KEY}"))
            .unwrap();
        // A literal key field is not accepted.
        assert!(
            serde_saphyr::from_str::<Config>(
                "backends:\n  jev: {type: jev, url: 'https://a.example', model: m, api_key: abc}"
            )
            .is_err()
        );
    }
}
