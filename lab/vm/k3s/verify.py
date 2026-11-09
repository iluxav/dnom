"""Checks the results of lab/vm/k3s/run.sh and writes report.json.

Usage: verify.py RESULTS_DIR
Exit 1 if any check fails. The Jev check is skipped (not failed) when Jev wasn't run.
"""
import collections
import datetime
import json
import sys
from pathlib import Path

results = Path(sys.argv[1])
checks = []


def read_jsonl(path):
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def check(name, ok, evidence=None):
    checks.append({"name": name, "status": "PASS" if ok else "FAIL", "evidence": evidence})


def skip(name, why):
    checks.append({"name": name, "status": "SKIP", "evidence": why})


def in_pod(r, pod, ns):
    c = r["episode"].get("container") or {}
    return c.get("pod") == pod and c.get("namespace") == ns


def rules(r):
    return {p["rule"] for p in r["policy"]}


def web_episode(episodes, ns):
    """The web pod's episode: its own process tree, rooted at the container's sh."""
    return [r for r in episodes if in_pod(r, "web", ns) and "203.0.113.7" in r["episode"]["root"]["argv"]]


# --- the cluster and Falco ---------------------------------------------------------------------
node = (results / "node.txt").read_text().splitlines()
check("k3s node up and Ready", len(node) >= 2 and " Ready " in node[1], node)

pods = json.loads((results / "pods.json").read_text())["items"]
falco_pods = [p for p in pods if p["metadata"]["namespace"] == "dnom-falco"]
check("Falco runs as a DaemonSet pod on the node",
      len(falco_pods) == 1 and falco_pods[0]["metadata"]["ownerReferences"][0]["kind"] == "DaemonSet"
      and falco_pods[0]["status"]["phase"] == "Running",
      [p["metadata"]["name"] for p in falco_pods])

alerts = read_jsonl(results / "falco.json")
fields = [a.get("output_fields", {}) for a in alerts]
seen = {(f.get("k8s.ns.name"), f.get("k8s.pod.name")) for f in fields}
want = {("dnom-test", "web"), ("dnom-test", "db"), ("dnom-other", "web")}
check("Falco alerts carry pod and namespace for the test pods (from the k3s containerd socket)",
      want <= seen, {"alerts": len(alerts), "pods_seen": sorted(f"{ns}/{p}" for ns, p in seen if ns and ns != "<NA>")})

# --- episodes (no model) -----------------------------------------------------------------------
episodes = read_jsonl(results / "episodes-none.jsonl")
web = web_episode(episodes, "dnom-test")
w = web[0]["episode"] if len(web) == 1 else {}
check("web pod (dnom-test) is one episode, labelled with pod, namespace and image",
      len(web) == 1 and w["container"] == {"name": "web", "image": "alpine:3.20", "pod": "web", "namespace": "dnom-test"},
      w.get("container") if web else {"episodes": len(web)})
check("web pod episode has the /etc/shadow read and the connection attempt",
      len(web) == 1 and "/etc/shadow" in w["files"].get("credentials", [])
      and any(n["dest"] == "203.0.113.7:80" for n in w["network"]),
      {"credentials": w.get("files", {}).get("credentials"), "network": [n["dest"] for n in w.get("network", [])]})

execd = [r for r in episodes if in_pod(r, "db", "dnom-test") and r["episode"]["root"]["argv"] == "cat /etc/shadow"]
check("`kubectl exec` into the db pod is its own episode, labelled with the pod",
      len(execd) == 1, [r["episode"]["root"] for r in execd] or {"db_episodes": sum(in_pod(r, "db", "dnom-test") for r in episodes)})

other = web_episode(episodes, "dnom-other")
check("the same pod in namespace dnom-other is labelled dnom-other", len(other) == 1,
      other[0]["episode"]["container"] if other else None)

# Pod sandboxes (/pause, one per pod) are the exception: Falco has no metadata for them.
labelled = [r["episode"]["container"] for r in episodes
            if "container" in r["episode"] and r["episode"]["root"]["exe"] != "/pause"]
check("every container episode names its pod and namespace (none left with only an id)",
      labelled and all(c.get("pod") and c.get("namespace") for c in labelled),
      {"container_episodes": len(labelled), "incomplete": [c for c in labelled if not (c.get("pod") and c.get("namespace"))][:5]})

# --- policies ----------------------------------------------------------------------------------
scoped = "k8s-test-namespace-credentials"
check("namespace-scoped rule matches the web pod and the exec in dnom-test",
      len(web) == 1 and len(execd) == 1 and scoped in rules(web[0]) and scoped in rules(execd[0]))
check("namespace-scoped rule does not match the same activity in dnom-other",
      len(other) == 1 and scoped not in rules(other[0]), sorted(rules(other[0])) if other else None)
# The baseline is per node: whichever web pod connects first makes 203.0.113.7 known, so the
# model-free rule matches that pod only.
first = [r for r in web + other if any(n["dest"] == "203.0.113.7:80" and n["new_destination"] for n in r["episode"]["network"])]
check("destination baseline is per node: only the first web pod's connection counts as new",
      len(web) == 1 and len(other) == 1 and len(first) == 1 and "credentials-then-new-destination" in rules(first[0]),
      [r["episode"]["container"]["namespace"] for r in first])
host = [r for r in episodes if "container" not in r["episode"] and scoped in rules(r)]
check("namespace-scoped rule matches no host episode", not host, [r["episode"]["root"]["argv"] for r in host][:3])
all_policy = [p for r in episodes for p in r["policy"]]
check("every reported action is dry run", all(p["dry_run"] for p in all_policy), {"matches": len(all_policy)})

# --- Jev ---------------------------------------------------------------------------------------
jev_file = results / "episodes-jev.jsonl"
if jev_file.exists():
    jev = web_episode(read_jsonl(jev_file), "dnom-test")
    a = jev[0].get("answers", {}) if jev else {}
    check("Jev assessed the web pod episode (pod context included)", bool(a),
          {"credential_access": a.get("credential_access", {}).get("noul"),
           "exfiltration": a.get("exfiltration", {}).get("noul"),
           "rules": sorted(rules(jev[0])) if jev else None, "latency_ms": jev[0].get("latency_ms") if jev else None})
else:
    skip("Jev assessed the web pod episode (pod context included)", "Jev not run (no key or K3S_JEV=0)")

# --- report ------------------------------------------------------------------------------------
counts = collections.Counter(c["status"] for c in checks)
report = {
    "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "commit": (results / "commit.txt").read_text().split(),
    "vm_kernel": (results / "kernel.txt").read_text().strip(),
    "k3s": node[0] if node else None,
    "falco_alerts": len(alerts),
    "alerts_by_rule": dict(collections.Counter(a.get("rule") for a in alerts)),
    "episodes": len(episodes),
    # Rule matches outside the test pods: candidate false alarms, for reading, not checked.
    "other_matches": [
        {"rules": sorted(rules(r)), "root": r["episode"]["root"]["argv"][:120], "container": r["episode"].get("container"),
         "credentials": r["episode"]["files"].get("credentials"), "network": [n["dest"] for n in r["episode"]["network"]]}
        for r in episodes if r["policy"] and not any(r is x for x in web + other + execd)
    ],
    "summary": dict(counts),
    "checks": checks,
    "notes": [
        "Policies are dry run: actions are reported, never executed.",
        "Test pods read their own /etc/shadow (Alpine) and try TEST-NET-3 (203.0.113.7); nothing is sent.",
        "Jev results are single samples, not a benchmark.",
    ],
}
(results / "report.json").write_text(json.dumps(report, indent=2) + "\n")
for c in checks:
    print(f"{c['status']}: {c['name']}")
print(f"{counts.get('PASS', 0)} passed, {counts.get('FAIL', 0)} failed, {counts.get('SKIP', 0)} skipped  "
      f"(report: {results / 'report.json'})")
sys.exit(1 if counts.get("FAIL") else 0)
