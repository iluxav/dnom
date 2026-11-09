"""Checks the results of lab/vm/e2e/run.sh and writes report.json.

Usage: verify.py RESULTS_DIR VM_DIR ROUNDS
Exit 1 if any check fails. Jev checks are skipped (not failed) when Jev wasn't run.
"""
import collections
import datetime
import json
import re
import sys
from pathlib import Path

results = Path(sys.argv[1])
vmdir = sys.argv[2].rstrip("/")
rounds = int(sys.argv[3])
checks = []


def read_jsonl(path):
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def check(name, ok, evidence=None):
    checks.append({"name": name, "status": "PASS" if ok else "FAIL", "evidence": evidence})


def skip(name, why):
    checks.append({"name": name, "status": "SKIP", "evidence": why})


def burst_execs(events):
    return [e for e in events if e["kind"] == "exec" and any(a.startswith("dnom-burst-") for a in e["argv"])]


# --- unit tests (inside the VM) ---------------------------------------------------------------
unit_log = (results / "unit-tests.log").read_text()
m = re.search(r"test result: (\w+)\. (\d+) passed; (\d+) failed", unit_log)
unit_passed = int(m.group(2)) if m else 0
check("unit tests pass inside the VM", m is not None and m.group(1) == "ok" and m.group(3) == "0" and unit_passed > 0,
      {"passed": unit_passed})

# --- every round: completeness and clean shutdown ----------------------------------------------
for n in range(1, rounds + 1):
    d = results / f"round{n}"
    events = read_jsonl(d / "events.jsonl")
    log = (d / "collector.log").read_text()
    burst = burst_execs(events)
    check(f"round {n}: 200 distinct commands captured with arguments",
          {e["argv"][-1] for e in burst} == {f"dnom-burst-{i}" for i in range(1, 201)} and len(burst) == 200,
          {"captured": len(burst)})
    stopped = re.search(r"stopped\. (\d+) events emitted \((\d+) from the startup snapshot\), (\d+) dropped", log)
    check(f"round {n}: clean shutdown, 0 dropped, every emitted event reached the output",
          stopped is not None and stopped.group(3) == "0" and int(stopped.group(1)) == len(events),
          {"collector": stopped.group(0) if stopped else log.strip()[-200:], "lines": len(events)})

# --- round 1: sensors -------------------------------------------------------------------------
d1 = results / "round1"
events = read_jsonl(d1 / "events.jsonl")
log = (d1 / "collector.log").read_text()
check("sensors attached", re.search(r"\d+ sensors attached", log) is not None, log.splitlines()[0] if log else "")
burst = burst_execs(events)
forked = {e["child"] for e in events if e["kind"] == "fork"}
exited = {e["pid"] for e in events if e["kind"] == "exit"}
check("fork and exit recorded for every burst command", burst and all(e["pid"] in forked and e["pid"] in exited for e in burst))
opens = [e for e in events if e["kind"] == "open"]
ordinary = f"{vmdir}/ordinary.txt"
check("ordinary file write and read captured",
      all(any(e["path"] == ordinary and e["write"] == w for e in opens) for w in (True, False)), ordinary)
missing = f"{vmdir}/does-not-exist.txt"
tried = any(e["kind"] == "exec" and missing in e["argv"] for e in events)
check("failed open is not reported", tried and not any(e["path"] == missing for e in opens),
      "cat of a missing file ran; no open event for it")
benign_info = json.loads((d1 / "benign-result.json").read_text())
check("relative path resolved to absolute", any(e["pid"] == benign_info["pid"] and e["path"] == ordinary for e in opens),
      "python3 opened 'ordinary.txt' after chdir")
check("decoy credential read captured",
      any(e["comm"] == "cat" and e["path"].endswith("/.ssh/id_ed25519") and not e["write"] for e in opens),
      "decoy file in /tmp/dnom-test.*")
check("decoy persistence write captured",
      any(e["path"].endswith("/.config/systemd/user/updater.service") and e["write"] for e in opens),
      "decoy file in /tmp; nothing installed")
check("connection attempt to the test address captured",
      any(e["kind"] == "net" and e["dest"] == "203.0.113.7:443" and e["comm"] == "curl" for e in events),
      "TEST-NET-3, not routed; attempt only")

# --- round 1: episodes and policies (no model) --------------------------------------------------
episodes = read_jsonl(results / "episodes-none.jsonl")
sim = [r for r in episodes if r["episode"]["root"]["argv"].endswith("/fake-exfil.sh")]
check("simulation is one process-tree episode",
      len(sim) == 1 and {"cat", "base64", "curl"} <= {Path(p.get("exe", "")).name for p in sim[0]["episode"]["tree"]},
      {"episodes": len(sim)})
check("model-free rule matches the simulation",
      len(sim) == 1 and any(p["rule"] == "credentials-then-new-destination" for p in sim[0]["policy"]))
benign = [r for r in episodes if r["episode"]["root"]["argv"].endswith("/benign.sh")]
loopback = f"127.0.0.1:{benign_info['loopback_port']}"
check("benign workload: loopback recorded, not new, no rule matches",
      len(benign) == 1 and not benign[0]["policy"]
      and any(n["dest"] == loopback and not n["new_destination"] for n in benign[0]["episode"]["network"]),
      loopback)
all_policy = [p for r in episodes for p in r["policy"]]
check("every reported action is dry run", all(p["dry_run"] for p in all_policy), {"matches": len(all_policy)})

# --- round 1: Jev ------------------------------------------------------------------------------
jev_file, jev_benign_file = results / "episodes-jev.jsonl", results / "episodes-jev-benign.jsonl"
if jev_file.exists() and jev_benign_file.exists():
    jev = read_jsonl(jev_file)
    expected = {"credentials-then-new-destination", "credential-theft", "exfiltration", "persistence"}
    got = {p["rule"] for r in jev for p in r["policy"]}
    check("Jev: simulation matches the four expected rules", len(jev) == 1 and expected <= got,
          {"rules": sorted(got), "latency_ms": [r.get("latency_ms") for r in jev]})
    jb = read_jsonl(jev_benign_file)
    # Only "no rule matches" is asserted: Jev's response choice for benign activity can be a
    # near tie (ignore 0.44 vs watch 0.43 in one run), so asserting it would be flaky.
    check("Jev: benign workload matches no rule", len(jb) == 1 and not jb[0]["policy"],
          {"response": jb[0]["answers"]["response"]["probabilities"] if jb else None,
           "latency_ms": [r.get("latency_ms") for r in jb]})
else:
    skip("Jev: simulation matches the four expected rules", "Jev not run (no key or E2E_JEV=0)")
    skip("Jev: benign workload matches no rule", "Jev not run (no key or E2E_JEV=0)")

# --- replays inside the VM ---------------------------------------------------------------------
for fx in ("exfil", "lateral"):
    recs = read_jsonl(results / f"replay-{fx}.jsonl")
    check(f"replay fake-{fx} (synthetic) matches the model-free rule",
          any(p["rule"] == "credentials-then-new-destination" for r in recs for p in r["policy"]))

# --- report ------------------------------------------------------------------------------------
counts = collections.Counter(c["status"] for c in checks)
report = {
    "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "commit": (results / "commit.txt").read_text().split(),
    "vm_kernel": (results / "kernel.txt").read_text().strip(),
    "rounds": rounds,
    "unit_tests_passed": unit_passed,
    "round1_events": dict(collections.Counter(e["kind"] for e in events)),
    "summary": dict(counts),
    "checks": checks,
    "notes": [
        "Policies are dry run: kill_tree / block_net are reported, never executed.",
        "fake-exfil uses a decoy key in /tmp and TEST-NET-3 (203.0.113.7); nothing is sent.",
        "Jev results are single samples, not a benchmark.",
    ],
}
(results / "report.json").write_text(json.dumps(report, indent=2) + "\n")
for c in checks:
    print(f"{c['status']}: {c['name']}")
print(f"{counts.get('PASS', 0)} passed, {counts.get('FAIL', 0)} failed, {counts.get('SKIP', 0)} skipped  "
      f"(report: {results / 'report.json'})")
sys.exit(1 if counts.get("FAIL") else 0)
