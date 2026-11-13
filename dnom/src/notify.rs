//! Webhook alerts (`notify:` in dnom.yaml): each episode a policy rule matched is POSTed as
//! JSON to one URL, for whatever turns alerts into messages (a chat bot, an incident tool).
//!
//! - One alert when a rule first matches an episode; another only if the episode later
//!   matches rules it had not matched before (`event: threat_update`).
//! - The token comes from an environment variable (or ./.env), never from dnom.yaml, and is
//!   sent as `Authorization: Bearer <token>`.
//! - A failed send is retried on later ticks and then given up; it never stops dnom, and the
//!   alert is in the log (`dnom audit`) either way.
//! - Notifying is all dnom does. What the receiver does with an alert is its business.
//!
//! Receivers: command lines and file names in the payload come from the processes being
//! reported, so treat every text field as untrusted (no markup, no shell).

use std::{
    collections::{BTreeMap, BTreeSet, HashMap, VecDeque},
    time::Duration,
};

use anyhow::{Context as _, bail};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::audit;

/// Attempts per alert before it is given up, and how many may wait at once.
const MAX_ATTEMPTS: u32 = 5;
const MAX_PENDING: usize = 100;

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NotifyConfig {
    /// Where to POST alerts; empty: off.
    pub url: String,
    /// NAME of the environment variable (or ./.env entry) holding the shared token.
    pub token_env: String,
    /// How this dnom calls the machine it watches (default: this machine's hostname).
    pub name: String,
    pub timeout_ms: u64,
}

impl Default for NotifyConfig {
    fn default() -> Self {
        Self { url: String::new(), token_env: String::new(), name: String::new(), timeout_ms: 3000 }
    }
}

impl NotifyConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        if !self.url.is_empty() && !self.url.starts_with("http://") && !self.url.starts_with("https://") {
            bail!("notify.url: '{}' must start with http:// or https://", self.url);
        }
        Ok(())
    }
}

type Send = Box<dyn FnMut(&Value) -> anyhow::Result<()>>;

pub struct Notifier {
    name: String,
    send: Send,
    /// Alerts not delivered yet, with the attempts made.
    pending: VecDeque<(Value, u32)>,
    /// Rules already reported per episode.
    reported: HashMap<String, BTreeSet<String>>,
}

impl Notifier {
    /// None when no URL is configured. `remote` : the events come from another machine, so
    /// this machine's hostname would name the wrong one.
    pub fn from_config(config: &NotifyConfig, remote: bool) -> anyhow::Result<Option<Self>> {
        if config.url.is_empty() {
            return Ok(None);
        }
        let token = match config.token_env.as_str() {
            "" => None,
            var => Some(
                std::env::var(var)
                    .ok()
                    .filter(|v| !v.is_empty())
                    .or_else(|| crate::backends::dotenv_value(".env", var))
                    .with_context(|| format!("notify.token_env: {var} is not set (environment or .env)"))?,
            ),
        };
        let name = match (config.name.as_str(), remote) {
            ("", true) => "remote".to_string(),
            ("", false) => std::fs::read_to_string("/proc/sys/kernel/hostname").map(|h| h.trim().to_string()).unwrap_or_default(),
            (name, _) => name.to_string(),
        };
        let local = ["http://127.0.0.1", "http://localhost", "http://[::1]"].iter().any(|l| config.url.starts_with(l));
        let warning = match (&token, config.url.starts_with("https://") || local) {
            (None, _) => "; no token: anything that can reach the URL can post alerts there",
            (Some(_), false) => "; plain http: the token and the alerts travel unencrypted",
            _ => "",
        };
        eprintln!("dnom classify: alerts for matched rules go to {} as '{name}'{warning}", config.url);

        let agent: ureq::Agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .timeout_global(Some(Duration::from_millis(config.timeout_ms.max(100))))
            .build()
            .into();
        let url = config.url.clone();
        let send: Send = Box::new(move |body| {
            let mut request = agent.post(&url);
            if let Some(token) = &token {
                request = request.header("Authorization", format!("Bearer {token}"));
            }
            let response = request.send_json(body).with_context(|| format!("POST {url}"))?;
            if !response.status().is_success() {
                bail!("POST {url}: HTTP {}", response.status());
            }
            Ok(())
        });
        Ok(Some(Self::new(name, send)))
    }

    fn new(name: String, send: Send) -> Self {
        Self { name, send, pending: VecDeque::new(), reported: HashMap::new() }
    }

    /// Queues an alert if this assessment matched rules not reported for its episode yet.
    pub fn offer(&mut self, record: &Value) {
        let Some(new_rules) = audit::newly_matched(&mut self.reported, record) else { return };
        if self.pending.len() >= MAX_PENDING {
            let dropped = self.pending.pop_front().map(|(p, _)| p["episode_id"].as_str().unwrap_or("?").to_string());
            eprintln!("dnom classify: too many undelivered alerts; dropped the oldest ({})", dropped.unwrap_or_default());
        }
        self.pending.push_back((payload(record, &new_rules, &self.name), 0));
    }

    /// Tries to deliver what is waiting. Stops at the first failure, so alerts stay in order.
    pub fn flush(&mut self) {
        while let Some((body, attempts)) = self.pending.front_mut() {
            match (self.send)(body) {
                Ok(()) => {
                    self.pending.pop_front();
                }
                Err(e) => {
                    *attempts += 1;
                    let episode = body["episode_id"].as_str().unwrap_or("?").to_string();
                    if *attempts >= MAX_ATTEMPTS {
                        eprintln!("dnom classify: alert for {episode} not delivered after {MAX_ATTEMPTS} tries, giving up: {e:#}");
                        self.pending.pop_front();
                        continue;
                    }
                    if *attempts == 1 {
                        eprintln!("dnom classify: alert for {episode} not delivered, will retry: {e:#}");
                    }
                    return;
                }
            }
        }
    }

    pub fn waiting(&self) -> usize {
        self.pending.len()
    }
}

/// The alert as the receiver gets it. Flat fields first (easy to template or to pass on as
/// environment variables), then the readable report and the full episode.
pub fn payload(record: &Value, new_rules: &[String], name: &str) -> Value {
    let ep = &record["episode"];
    let rules = audit::rules_of(record);
    let actions: BTreeSet<&str> =
        record["policy"].as_array().into_iter().flatten().flat_map(|p| p["actions"].as_array().into_iter().flatten()).filter_map(|a| a.as_str()).collect();
    let answers: BTreeMap<&str, Value> = record["answers"]
        .as_object()
        .into_iter()
        .flatten()
        .filter_map(|(id, a)| Some((id.as_str(), ["noul", "choice", "score"].iter().find_map(|k| a.get(*k))?.clone())))
        .collect();
    let command = ep["root"]["argv"].as_str().filter(|a| !a.is_empty()).or(ep["root"]["exe"].as_str()).unwrap_or("");
    let container = |key: &str| ep["container"][key].as_str().unwrap_or("");
    let place = match (container("pod"), container("namespace"), container("name")) {
        ("", _, "") => String::new(),
        ("", _, name) => format!(" in container {name}"),
        (pod, ns, _) => format!(" in pod {pod} ({ns})"),
    };
    json!({
        "source": "dnom",
        "version": 1,
        "event": if new_rules.len() < rules.len() { "threat_update" } else { "threat" },
        "ts": record["ts"],
        "host": name,
        "episode_id": record["episode_id"],
        "summary": format!("{}: {command}{place}", rules.join(", ")),
        "rules": rules,
        "new_rules": new_rules,
        // What the rules WOULD do. dnom is dry run: nothing was done.
        "actions": actions,
        "dry_run": true,
        "command": command,
        "exe": ep["root"]["exe"],
        "uid": ep["root"]["uid"],
        // The root process. It may be gone, and its pid reused, by the time anyone acts.
        "pid": ep["tree"][0]["pid"],
        "started": ep["window"]["start"],
        "ended": ep["window"]["end"],
        "pod": container("pod"),
        "namespace": container("namespace"),
        "container": container("name"),
        "image": container("image"),
        "answers": answers,
        "report": audit::render(record, &audit::Paint::plain()),
        "episode": ep,
    })
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, rc::Rc};

    use super::*;

    fn record(id: &str, rules: &[&str]) -> Value {
        json!({
            "ts": "2026-11-11T10:00:00Z",
            "episode_id": id,
            "backend": "jev",
            "model": "jev-1",
            "latency_ms": 135,
            "answers": {
                "credential_access": { "type": "noul", "noul": 0.97 },
                "response": { "type": "choice", "choice": "contain", "confidence": 0.5, "probabilities": {} },
            },
            "policy": rules.iter().map(|r| json!({ "rule": r, "actions": ["alert", "kill_tree"], "dry_run": true, "protected": false, "values": {} })).collect::<Vec<_>>(),
            "episode": {
                "window": { "start": "2026-11-11T09:59:58Z", "end": "2026-11-11T10:00:00Z" },
                "root": { "exe": "/bin/busybox", "argv": "sh -c cat /etc/shadow", "uid": 0, "started_by": "" },
                "container": { "name": "web", "image": "alpine:3.20", "pod": "web", "namespace": "prod" },
                "tree": [{ "pid": 4242, "ppid": 1, "ts_ms": 1, "exe": "/bin/busybox", "argv": "sh -c cat /etc/shadow", "parent": "" }],
                "trail": [{ "ts_ms": 2, "pid": 4242, "event": "open", "path": "/opt/keys-old/id_rsa", "category": "decoys", "write": false }],
                "files": { "decoys": ["/opt/keys-old/id_rsa"] },
                "network": [],
                "flags": [],
            },
        })
    }

    /// A notifier whose "network" is a list: `up` decides whether a send succeeds.
    fn fake() -> (Notifier, Rc<RefCell<Vec<Value>>>, Rc<RefCell<bool>>) {
        let (sent, up) = (Rc::new(RefCell::new(Vec::new())), Rc::new(RefCell::new(true)));
        let (s, u) = (sent.clone(), up.clone());
        let send: Send = Box::new(move |body| {
            if !*u.borrow() {
                bail!("connection refused");
            }
            s.borrow_mut().push(body.clone());
            Ok(())
        });
        (Notifier::new("node-1".into(), send), sent, up)
    }

    #[test]
    fn payload_has_flat_fields_the_report_and_the_episode() {
        let p = payload(&record("ep-1-a", &["decoy-touched", "credential-theft"]), &["decoy-touched".into(), "credential-theft".into()], "node-1");
        assert_eq!(p["source"], "dnom");
        assert_eq!(p["event"], "threat");
        assert_eq!(p["host"], "node-1");
        assert_eq!(p["summary"], "decoy-touched, credential-theft: sh -c cat /etc/shadow in pod web (prod)");
        assert_eq!(p["rules"], json!(["decoy-touched", "credential-theft"]));
        assert_eq!(p["actions"], json!(["alert", "kill_tree"]));
        assert_eq!(p["dry_run"], true);
        assert_eq!((p["pid"].as_u64(), p["uid"].as_u64()), (Some(4242), Some(0)));
        assert_eq!((p["pod"].as_str(), p["namespace"].as_str(), p["image"].as_str()), (Some("web"), Some("prod"), Some("alpine:3.20")));
        assert_eq!(p["answers"], json!({ "credential_access": 0.97, "response": "contain" }));
        let report = p["report"].as_str().unwrap();
        assert!(report.contains("THREAT · 2 rules matched") && report.contains("[DECOY]") && !report.contains('\x1b'), "{report}");
        assert_eq!(p["episode"]["files"]["decoys"], json!(["/opt/keys-old/id_rsa"]));

        // A host episode has empty container fields, and no "in pod" in the summary.
        let mut host = record("ep-2-b", &["decoy-touched"]);
        host["episode"].as_object_mut().unwrap().remove("container");
        let p = payload(&host, &["decoy-touched".into()], "node-1");
        assert_eq!((p["pod"].as_str(), p["summary"].as_str()), (Some(""), Some("decoy-touched: sh -c cat /etc/shadow")));
    }

    #[test]
    fn one_alert_per_newly_matched_rule_set() {
        let (mut n, sent, _) = fake();
        n.offer(&record("ep-1-a", &[]));
        n.offer(&record("ep-1-a", &["decoy-touched"]));
        n.offer(&record("ep-1-a", &["decoy-touched"])); // reassessed, nothing new
        n.offer(&record("ep-1-a", &["decoy-touched", "exfiltration"]));
        n.offer(&record("ep-2-b", &["decoy-touched"]));
        n.flush();
        let got: Vec<(String, String, Value)> =
            sent.borrow().iter().map(|p| (p["episode_id"].as_str().unwrap().into(), p["event"].as_str().unwrap().into(), p["new_rules"].clone())).collect();
        assert_eq!(
            got,
            [
                ("ep-1-a".into(), "threat".into(), json!(["decoy-touched"])),
                ("ep-1-a".into(), "threat_update".into(), json!(["exfiltration"])),
                ("ep-2-b".into(), "threat".into(), json!(["decoy-touched"])),
            ]
        );
    }

    #[test]
    fn failed_sends_are_retried_in_order_then_given_up() {
        let (mut n, sent, up) = fake();
        *up.borrow_mut() = false;
        n.offer(&record("ep-1-a", &["decoy-touched"]));
        n.offer(&record("ep-2-b", &["decoy-touched"]));
        n.flush();
        n.flush();
        assert_eq!((n.waiting(), sent.borrow().len()), (2, 0), "both wait while the receiver is down");

        *up.borrow_mut() = true;
        n.flush();
        assert_eq!(sent.borrow().iter().map(|p| p["episode_id"].as_str().unwrap().to_string()).collect::<Vec<_>>(), ["ep-1-a", "ep-2-b"]);
        assert_eq!(n.waiting(), 0);

        // Down for good: an alert is dropped after MAX_ATTEMPTS tries, and dnom carries on.
        *up.borrow_mut() = false;
        n.offer(&record("ep-3-c", &["decoy-touched"]));
        for _ in 0..MAX_ATTEMPTS {
            n.flush();
        }
        assert_eq!(n.waiting(), 0);
    }

    #[test]
    fn config_checks_the_url() {
        let config = |url: &str| NotifyConfig { url: url.into(), ..Default::default() };
        assert!(config("").validate().is_ok() && config("https://ops.example/events/dnom").validate().is_ok());
        assert!(config("ops.example/events").validate().is_err() && config("file:///tmp/x").validate().is_err());
        assert!(Notifier::from_config(&config(""), false).unwrap().is_none(), "no URL: off");
        let missing = NotifyConfig { url: "http://127.0.0.1:9/x".into(), token_env: "DNOM_TEST_TOKEN_THAT_IS_NOT_SET".into(), ..Default::default() };
        assert!(Notifier::from_config(&missing, false).is_err(), "a named token that isn't set is an error, not a silent no-auth");
    }
}
