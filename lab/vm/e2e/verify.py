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


def latest(records):
    """classify reassesses an episode when it changes, so one episode can have several
    records; the last is the whole episode."""
    return list({r["episode"]["episode_id"]: r for r in records}.values())


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
    check(f"round {n}: events still delivered after 8 s without workload",
          any(e["kind"] == "exec" and "dnom-after-idle" in e["argv"] for e in events))
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
noise = [e for e in opens if e["path"].startswith(("/proc/", "/sys/"))]
check("no /proc or /sys opens reported (incl. relative to a directory handle, as procps does)",
      not noise, {"noise_opens": len(noise), "by": sorted({e["comm"] for e in noise})[:5]})
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

live_execs = [e for e in events if e["kind"] == "exec" and e.get("cgroup") != 0]
incomplete = [e for e in live_execs if not e["argv"] or "" in e["argv"]]
check("every command arrives with complete arguments",
      live_execs and not incomplete,
      {"execs": len(live_execs), "incomplete": [[e["exe"], e["argv"]] for e in incomplete[:5]]})
chkpwd = [e["argv"] for e in live_execs if e["exe"].endswith("/unix_chkpwd")]
if chkpwd:
    check("unix_chkpwd (literals not yet paged in at execve entry) has its arguments",
          all(len(a) >= 3 and all(a) for a in chkpwd), chkpwd[:2])
else:
    skip("unix_chkpwd (literals not yet paged in at execve entry) has its arguments", "no SSH login seen")

# --- round 1: syscall coverage ------------------------------------------------------------------
sc = json.loads((d1 / "syscalls-result.json").read_text())
for name in ("open", "creat", "openat2"):
    check(f"{name}() captured as a write", any(e["path"] == sc["files"][name] and e["write"] for e in opens), sc["files"][name])
check("execveat() captured with its arguments",
      any(e["kind"] == "exec" and "dnom-execveat" in e["argv"] for e in events))
udp = f"127.0.0.1:{sc['udp_port']}"
check("UDP sendto() with a destination captured",
      any(e["kind"] == "net" and e["op"] == "sendto" and e["dest"] == udp and e["pid"] == sc["pid"] for e in events), udp)
v6 = f"[::1]:{sc['v6_port']}"
check("IPv6 connect() captured",
      any(e["kind"] == "net" and e["op"] == "connect" and e["dest"] == v6 and e["pid"] == sc["pid"] for e in events), v6)

# --- round 1: episodes and policies (no model) --------------------------------------------------
records = read_jsonl(results / "episodes-none.jsonl")
episodes = latest(records)
sim = [r for r in episodes if r["episode"]["root"]["argv"].endswith("/fake-exfil.sh")]
check("simulation is one process-tree episode",
      len(sim) == 1 and {"cat", "base64", "curl"} <= {Path(p.get("exe", "")).name for p in sim[0]["episode"]["tree"]},
      {"episodes": len(sim)})
check("model-free rule matches the simulation",
      len(sim) == 1 and any(p["rule"] == "credentials-then-new-destination" for p in sim[0]["policy"]))
benign = [r for r in episodes if r["episode"]["root"]["argv"].endswith("/benign.sh")]
loopback = f"127.0.0.1:{benign_info['loopback_port']}"
check("benign workload: loopback recorded, not new, no rule matches",
      len(benign) == 1 and not any(r["policy"] for r in records if r["episode"]["root"]["argv"].endswith("/benign.sh"))
      and any(n["dest"] == loopback and not n["new_destination"] for n in benign[0]["episode"]["network"]),
      loopback)
all_policy = [p for r in records for p in r["policy"]]
check("every reported action is dry run", all(p["dry_run"] for p in all_policy), {"matches": len(all_policy)})

# --- round 1: decoy file -----------------------------------------------------------------------
decoy_path = f"{vmdir}/decoy/backup-credentials.txt"
touched = [r for r in episodes if "decoy-touched" in {p["rule"] for p in r["policy"]}]
dec = touched[0] if touched else None
check("reading the decoy file matches decoy-touched, and nothing else would have caught it",
      len(touched) == 1 and dec["episode"]["files"].get("decoys") == [decoy_path]
      and "credentials" not in dec["episode"]["files"] and {p["rule"] for p in dec["policy"]} == {"decoy-touched"},
      {"episodes": [r["episode"]["root"]["argv"] for r in touched], "files": dec["episode"]["files"] if dec else None})

# --- round 1: decoy addresses (probe.sh) -------------------------------------------------------
probes = [r for r in episodes if r["episode"]["root"]["argv"].endswith("/probe.sh")]
probe = probes[0] if len(probes) == 1 else {"episode": {}, "policy": []}
hits = probe["episode"].get("decoy_destinations", [])
check("decoy addresses: a refused port on this machine and an unused address match decoy-contacted",
      len(probes) == 1 and "127.0.0.1:6379" in hits and "198.51.100.77:22" in hits
      and "decoy-contacted" in {p["rule"] for p in probe["policy"]}, hits)
check("decoy addresses: a ping to a decoy address is seen",
      any(h.startswith("198.51.100.78:") for h in hits), hits)
check("decoy addresses: another port on this machine is recorded and is not a decoy",
      any(n["dest"] == "127.0.0.1:6380" for n in probe["episode"].get("network", [])) and "127.0.0.1:6380" not in hits,
      [n["dest"] for n in probe["episode"].get("network", [])])
others = [r["episode"]["root"]["argv"] for r in records
          if r["episode"].get("decoy_destinations") and not r["episode"]["root"]["argv"].endswith("/probe.sh")]
check("decoy addresses: no other episode reached one", not others, others[:3])

# --- round 1: audit trail, `dnom audit`, `dnom monitor` ----------------------------------------
sim_ep = sim[0]["episode"] if len(sim) == 1 else {"tree": [], "trail": []}
root_pid = sim_ep["tree"][0]["pid"] if sim_ep["tree"] else None
pids = {n["pid"]: n for n in sim_ep["tree"] if "pid" in n}
by = lambda step: Path(pids.get(step["pid"], {}).get("exe", "")).name
steps = [(by(t), t["event"], t.get("path", t.get("dest", ""))) for t in sim_ep.get("trail", [])]
check("audit trail: the simulation's steps name the process that did each one, in order",
      any(st[0] == "cat" and st[1] == "open" and st[2].endswith("/.ssh/id_ed25519") for st in steps)
      and ("curl", "net", "203.0.113.7:443") in steps
      and [t["ts_ms"] for t in sim_ep["trail"]] == sorted(t["ts_ms"] for t in sim_ep["trail"])
      # Every process but the root has its parent in the tree (the root's parent is sshd).
      and all(n.get("ppid") in pids for n in sim_ep["tree"] if n.get("pid") not in (None, root_pid)),
      steps[:6])
threat_ids = {r["episode"]["episode_id"] for r in records if r["policy"]}
audit_list = (results / "audit-list.txt").read_text()
audit_decoy = (results / "audit-decoy.txt").read_text()
check("`dnom audit` lists the matched episodes and shows the decoy episode with its tree",
      threat_ids and all(f"{i}  THREAT" in re.sub(r" +", "  ", audit_list) for i in threat_ids)
      and "THREAT · 1 rule matched (dry run)" in audit_decoy and "[DECOY]" in audit_decoy
      and f"read {decoy_path}" in audit_decoy and "What happened" in audit_decoy,
      audit_decoy.splitlines()[:12])
monitor = (results / "monitor.txt").read_text()
reported = set(re.findall(r"^(ep-\d+-[0-9a-f]+)  THREAT", monitor, re.M))
check("`dnom monitor` reported every matched episode live, and only those",
      threat_ids and reported == threat_ids, {"reported": sorted(reported), "expected": sorted(threat_ids)})

# --- round 1: Jev ------------------------------------------------------------------------------
jev_file, jev_benign_file = results / "episodes-jev.jsonl", results / "episodes-jev-benign.jsonl"
if jev_file.exists() and jev_benign_file.exists():
    jev = latest(read_jsonl(jev_file))
    expected = {"credentials-then-new-destination", "credential-theft", "exfiltration", "persistence"}
    got = {p["rule"] for r in jev for p in r["policy"]}
    check("Jev: simulation matches the four expected rules", len(jev) == 1 and expected <= got,
          {"rules": sorted(got), "latency_ms": [r.get("latency_ms") for r in jev]})
    audit_jev = (results / "audit-jev.txt").read_text()
    check("`dnom audit` shows the model's answers for the simulation",
          "credential_access" in audit_jev and "█" in audit_jev and "fake-exfil.sh" in audit_jev,
          [line for line in audit_jev.splitlines() if "credential_access" in line or "jev" in line][:3])
    jb_all = read_jsonl(jev_benign_file)
    jb = latest(jb_all)
    # Only "no rule matches" is asserted: Jev's response choice for benign activity can be a
    # near tie (ignore 0.44 vs watch 0.43 in one run), so asserting it would be flaky.
    check("Jev: benign workload matches no rule", len(jb) == 1 and not any(r["policy"] for r in jb_all),
          {"response": jb[0]["answers"]["response"]["probabilities"] if jb else None,
           "latency_ms": [r.get("latency_ms") for r in jb]})
else:
    skip("Jev: simulation matches the four expected rules", "Jev not run (no key or E2E_JEV=0)")
    skip("Jev: benign workload matches no rule", "Jev not run (no key or E2E_JEV=0)")
    skip("`dnom audit` shows the model's answers for the simulation", "Jev not run (no key or E2E_JEV=0)")

# --- replays inside the VM ---------------------------------------------------------------------
for fx in ("exfil", "lateral"):
    recs = read_jsonl(results / f"replay-{fx}.jsonl")
    check(f"replay fake-{fx} (synthetic) matches the model-free rule",
          any(p["rule"] == "credentials-then-new-destination" for r in recs for p in r["policy"]))

# --- live run inside the VM: generated decoys ---------------------------------------------------
live_log = (results / "live-classify.log").read_text()
try:
    planted = json.loads((results / "live-decoys.json").read_text())["files"]
except (ValueError, KeyError):
    planted = []
check("live: one decoy generated per kind, in the lab user's home",
      [f["kind"] for f in planted] == ["ssh", "aws", "env"] and "decoys planted: 3 (ssh, aws, env)" in live_log
      and all(f["path"].startswith("/home/lab/") for f in planted),
      [f["path"] for f in planted])
live = latest(read_jsonl(results / "live-episodes.jsonl"))
rules_of = lambda r: {p["rule"] for p in r["policy"]}
# Episodes show the home folder as ~.
short = lambda path: path.replace("/home/lab/", "~/", 1)
touched = sorted([r["episode"]["root"]["argv"], r["episode"]["files"].get("decoys", [])] for r in live if "decoy-touched" in rules_of(r))
check("live: reading each generated decoy matches decoy-touched, and nothing else touched one",
      planted and touched == sorted([f"cat {short(f['path'])}", [short(f["path"])]] for f in planted), touched)
list_path = f"{vmdir}/live/state/decoys.json"
readers = [r["episode"]["root"]["argv"] for r in live if r["episode"]["files"].get("dnom_config") == [list_path] and "config-touched" in rules_of(r)]
check("live: reading dnom's list of decoys is reported (config-touched)", readers == [f"cat {list_path}"], readers)
leftovers = (results / "live-leftovers.txt").read_text().split()
check("live: after dnom stops, every generated file and the list are gone, and the home folder is as before",
      planted and not leftovers and "removed 3 generated decoys" in live_log
      and (results / "live-home-before.txt").read_text() == (results / "live-home-after.txt").read_text(),
      {"leftovers": leftovers, "log": [line for line in live_log.splitlines() if "decoys" in line]})

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
