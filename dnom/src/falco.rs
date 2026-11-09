//! `classify --source falco`: reads Falco's JSON output and turns alerts from the dnom
//! catch-all rules (integrations/falco/dnom-catchall.yaml) into dnom events.
//!
//! Falco reports each program start with its parent pid, so the adapter adds a fork event
//! (parent -> child) in front of every exec; that is all the process tree needs.

use anyhow::{Context as _, anyhow};
use serde_json::Value;

use crate::event::{Container, Data, Event};

/// Events from one line of Falco output. Empty for valid Falco JSON this adapter doesn't
/// use (alerts from other rules, exits of non-leader threads).
pub fn parse_line(line: &str) -> anyhow::Result<Vec<Event>> {
    let v: Value = serde_json::from_str(line).context("not JSON")?;
    let rule = v["rule"].as_str().ok_or_else(|| anyhow!("no rule field: not Falco output"))?;
    let f = &v["output_fields"];
    if !rule.starts_with("dnom_") {
        return Ok(Vec::new());
    }
    let pid = num(f, "proc.pid")? as u32;
    let tid = num(f, "thread.tid").map(|t| t as u32).unwrap_or(pid);
    let base = Event {
        ts_ms: timestamp_ms(&v, f)?,
        pid,
        tid,
        uid: num(f, "user.uid").unwrap_or(u32::MAX as u64) as u32,
        comm: text(f, "proc.name"),
        cgroup: 0,
        container: container_of(f),
        data: Data::Exit {},
    };
    let event = |data: Data| Event { data, ..base.clone() };
    Ok(match rule {
        "dnom_exec" => {
            let mut argv = vec![base.comm.clone()];
            argv.extend(text(f, "proc.args").split_whitespace().map(String::from));
            let exec = event(Data::Exec { exe: text(f, "proc.exepath"), argv });
            match num(f, "proc.ppid") {
                Ok(ppid) if ppid > 0 && ppid as u32 != pid => {
                    let fork = Event {
                        pid: ppid as u32,
                        tid: ppid as u32,
                        comm: String::new(),
                        // The parent may be outside the container (runc, containerd-shim).
                        container: None,
                        data: Data::Fork { child: pid },
                        ..base.clone()
                    };
                    vec![fork, exec]
                }
                _ => vec![exec],
            }
        }
        "dnom_open" => {
            let path = text(f, "fd.name");
            if path.is_empty() {
                return Ok(Vec::new());
            }
            let write = flag(f, "evt.is_open_write");
            vec![event(Data::Open { path, flags: if write { 1 } else { 0 }, write })]
        }
        "dnom_connect" => {
            let ip = text(f, "fd.sip");
            // Successful or in-progress connects fill fd.sip; failed ones only evt.arg.addr.
            let dest = if !ip.is_empty() {
                let port = num(f, "fd.sport").unwrap_or(0);
                Some(if ip.contains(':') { format!("[{ip}]:{port}") } else { format!("{ip}:{port}") })
            } else {
                dest_from_addr(&text(f, "evt.arg.addr"))
            };
            let Some(dest) = dest else { return Ok(Vec::new()) };
            let op = if text(f, "evt.type") == "connect" { "connect" } else { "sendto" };
            vec![event(Data::Net { op: op.into(), dest })]
        }
        // procexit fires per thread; only the thread-group leader's exit ends the process.
        "dnom_exit" if tid == pid => vec![event(Data::Exit {})],
        _ => Vec::new(),
    })
}

/// `ip:port` from Falco's connect `addr` argument (`203.0.113.7:80`, IPv6 `::1:8080` or
/// `[::1]:8080`), in dnom's form (`[ip]:port` for IPv6). None for anything else (a Unix socket
/// path, `<NA>`).
fn dest_from_addr(addr: &str) -> Option<String> {
    let (host, port) = addr.rsplit_once(':')?;
    let port: u16 = port.parse().ok()?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let ip: std::net::IpAddr = host.parse().ok()?;
    Some(match ip {
        std::net::IpAddr::V4(v4) => format!("{v4}:{port}"),
        std::net::IpAddr::V6(v6) => format!("[{v6}]:{port}"),
    })
}

/// Container and Kubernetes context Falco attaches to each event (its default config appends
/// these fields to every rule's output). `container.id` is "host" for processes on the host.
fn container_of(f: &Value) -> Option<Container> {
    let id = text(f, "container.id");
    if id.is_empty() || id == "host" {
        return None;
    }
    let some = |s: String| (!s.is_empty()).then_some(s);
    let repo = text(f, "container.image.repository");
    let tag = text(f, "container.image.tag");
    let image = match (repo.is_empty(), tag.is_empty()) {
        (true, _) => None,
        (false, true) => Some(repo),
        (false, false) => Some(format!("{repo}:{tag}")),
    };
    Some(Container {
        id,
        name: some(text(f, "container.name")),
        image,
        pod: some(text(f, "k8s.pod.name")),
        namespace: some(text(f, "k8s.ns.name")),
    })
}

/// Falco prints numeric fields as JSON numbers; accept numeric strings too.
fn num(f: &Value, field: &str) -> anyhow::Result<u64> {
    match &f[field] {
        Value::Number(n) => n.as_u64(),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
    .ok_or_else(|| anyhow!("missing or non-numeric {field}"))
}

/// String field, with Falco's "<NA>" / null treated as empty.
fn text(f: &Value, field: &str) -> String {
    match &f[field] {
        Value::String(s) if s != "<NA>" => s.clone(),
        Value::Number(n) => n.to_string(),
        _ => String::new(),
    }
}

fn flag(f: &Value, field: &str) -> bool {
    match &f[field] {
        Value::Bool(b) => *b,
        Value::String(s) => s == "true",
        _ => false,
    }
}

/// `evt.rawtime` (nanoseconds) if the rule printed it, else the alert's `time`.
fn timestamp_ms(v: &Value, f: &Value) -> anyhow::Result<u64> {
    if let Ok(ns) = num(f, "evt.rawtime") {
        return Ok(ns / 1_000_000);
    }
    let time = v["time"].as_str().ok_or_else(|| anyhow!("no evt.rawtime or time"))?;
    let t = humantime::parse_rfc3339(time).with_context(|| format!("bad time {time}"))?;
    Ok(t.duration_since(std::time::UNIX_EPOCH)?.as_millis() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(rule: &str, fields: Value) -> String {
        serde_json::json!({
            "hostname": "h", "output": "dnom ...", "priority": "Debug", "rule": rule,
            "source": "syscall", "tags": ["dnom"], "time": "2026-11-08T20:00:00.123456789Z",
            "output_fields": fields,
        })
        .to_string()
    }

    #[test]
    fn failed_connect_uses_the_addr_argument() {
        // Shape from Falco 0.45: busybox wget timing out (ERESTARTSYS), fd.sip empty.
        let evs = parse_line(&line(
            "dnom_connect",
            serde_json::json!({
                "evt.rawtime": 1u64, "proc.pid": 9, "thread.tid": 9, "user.uid": 0, "proc.name": "wget",
                "evt.type": "connect", "fd.sip": null, "fd.sport": null, "evt.arg.addr": "203.0.113.7:80",
            }),
        ))
        .unwrap();
        assert!(matches!(&evs[0].data, Data::Net { op, dest } if op == "connect" && dest == "203.0.113.7:80"));
        for (addr, want) in [("::1:8080", Some("[::1]:8080")), ("[::1]:8080", Some("[::1]:8080")),
                             ("/run/x.sock", None), ("<NA>", None), ("", None)] {
            assert_eq!(dest_from_addr(addr).as_deref(), want, "{addr}");
        }
    }

    #[test]
    fn container_and_pod_context() {
        let exec = |extra: Value| {
            let mut f = serde_json::json!({
                "evt.rawtime": 1u64, "proc.pid": 7, "proc.ppid": 6, "user.uid": 0, "proc.name": "sh",
                "proc.exepath": "/bin/sh", "proc.args": "",
            });
            f.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
            parse_line(&line("dnom_exec", f)).unwrap()
        };
        // Kubernetes pod (shape from Falco 0.45 output; k8s fields are null outside a pod).
        let evs = exec(serde_json::json!({
            "container.id": "3f2a9c1b7e01", "container.name": "web", "container.image.repository": "nginx",
            "container.image.tag": "1.27", "k8s.pod.name": "web-7f9c", "k8s.ns.name": "prod",
        }));
        assert_eq!(evs[0].container, None, "the synthesized fork's parent may be outside the container");
        assert_eq!(
            evs[1].container,
            Some(Container {
                id: "3f2a9c1b7e01".into(),
                name: Some("web".into()),
                image: Some("nginx:1.27".into()),
                pod: Some("web-7f9c".into()),
                namespace: Some("prod".into()),
            })
        );
        // Plain Docker: no pod.
        let evs = exec(serde_json::json!({
            "container.id": "aa11", "container.name": "db", "container.image.repository": "postgres",
            "container.image.tag": "", "k8s.pod.name": null, "k8s.ns.name": null,
        }));
        let c = evs[1].container.as_ref().unwrap();
        assert_eq!((c.image.as_deref(), c.pod.as_deref()), (Some("postgres"), None));
        // Host process.
        let evs = exec(serde_json::json!({ "container.id": "host", "container.name": "host" }));
        assert_eq!(evs[1].container, None);
    }

    #[test]
    fn exec_becomes_fork_plus_exec() {
        let evs = parse_line(&line(
            "dnom_exec",
            serde_json::json!({
                "evt.rawtime": 1_794_000_000_123_456_789u64, "proc.pid": 4242, "thread.tid": 4242,
                "proc.ppid": 100, "user.uid": 1000, "proc.name": "curl",
                "proc.exepath": "/usr/bin/curl", "proc.args": "-s https://example.com",
            }),
        ))
        .unwrap();
        assert_eq!(evs.len(), 2);
        assert!(matches!(evs[0].data, Data::Fork { child: 4242 }) && evs[0].pid == 100);
        let Data::Exec { exe, argv } = &evs[1].data else { panic!("not exec") };
        assert_eq!(exe, "/usr/bin/curl");
        assert_eq!(argv, &["curl", "-s", "https://example.com"]);
        assert_eq!((evs[1].pid, evs[1].uid, evs[1].ts_ms), (4242, 1000, 1_794_000_000_123));
    }

    #[test]
    fn open_connect_exit() {
        let open = parse_line(&line(
            "dnom_open",
            serde_json::json!({"evt.rawtime": 1_000_000u64, "proc.pid": 7, "thread.tid": 8, "user.uid": 1000,
                "proc.name": "cat", "fd.name": "/home/a/.ssh/id_ed25519", "evt.is_open_write": false}),
        ))
        .unwrap();
        assert!(matches!(&open[0].data, Data::Open { path, write: false, .. } if path == "/home/a/.ssh/id_ed25519"));

        let net = parse_line(&line(
            "dnom_connect",
            serde_json::json!({"proc.pid": 7, "proc.name": "curl", "evt.type": "connect",
                "fd.sip": "2001:db8::1", "fd.sport": 443}),
        ))
        .unwrap();
        assert!(matches!(&net[0].data, Data::Net { op, dest } if op == "connect" && dest == "[2001:db8::1]:443"));
        // No evt.rawtime: falls back to the alert's time.
        assert_eq!(net[0].ts_ms, 1_794_168_000_123);

        let thread_exit = serde_json::json!({"proc.pid": 7, "thread.tid": 9, "proc.name": "x"});
        assert!(parse_line(&line("dnom_exit", thread_exit)).unwrap().is_empty());
        let leader_exit = serde_json::json!({"proc.pid": 7, "thread.tid": 7, "proc.name": "x"});
        assert!(matches!(parse_line(&line("dnom_exit", leader_exit)).unwrap()[0].data, Data::Exit {}));
    }

    #[test]
    fn other_rules_and_garbage() {
        let other = line("Terminal shell in container", serde_json::json!({"proc.pid": 1}));
        assert!(parse_line(&other).unwrap().is_empty());
        assert!(parse_line("Fri Nov  8 20:00:00 2026: Falco version: 0.45.2").is_err());
        assert!(parse_line(r#"{"not":"falco"}"#).is_err());
    }
}
