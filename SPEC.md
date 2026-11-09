# dnom — Specification v0.1 (lab)

Status: draft · 2026-11-08

## 1. Goal

dnom is a single-binary Linux host monitor:

1. **eBPF sensors** record process, file and network activity.
2. A **chain builder** groups that activity into *episodes* (what a process tree did over time).
3. Every few seconds, an **assessor** (a local model or Jev) answers a fixed set of typed questions about each changed episode.
4. **User-written policies** turn those answers into alerts or containment actions.

The model is never on the hot path. Instant blocking comes only from static eBPF rules.

**Phase 0 is a lab:** learn what eBPF actually shows on a Linux server, inside a disposable VM, before writing dnom code.

## 2. Non-goals for v0.1

- No model call per event.
- No fleet management, web UI or multi-host features.
- Linux only.
- No running on the host desktop until the lab shows it is safe.

## 3. Architecture

```
 kernel                    dnom run (root)                 dnom analyzer (unprivileged, sandboxed)
 ──────                    ───────────────                 ───────────────────────────────────────
 eBPF hooks ──ring buf──▶  sensor ──raw records──────────▶ chain builder ──episodes every N s──▶ assessor
     ▲                                                                                              │
     │                                                                                           answers
     │                                                                                              ▼
 BPF LSM deny rules ◀───── enforcer ◀──── validated actions ◀─────────────────────────────── policy engine
```

- **Hot path:** BPF LSM deny rules, loaded at start and on policy reload. They decide in the kernel, with no model involved.
- **Everything else is asynchronous.** A slow or offline model delays assessments; it never blocks the system.

## 4. Components

### 4.1 Sensors (eBPF, Rust + aya)

| Event | Hook | Key fields |
|---|---|---|
| Program launch | `sched:sched_process_exec`; LSM `bprm_check_security` to block | pid, ppid, uid, exe, argv (capped), cgroup |
| Fork / exit | `sched:sched_process_fork`, `sched:sched_process_exit` | lineage |
| File open | LSM `file_open` | pid, path, read/write flags |
| Outbound connection | LSM `socket_connect` | pid, destination address, port, protocol |
| Privilege change | kprobe `commit_creds` | uid before/after |

Later: eBPF program loads, kernel module loads, `ptrace`, namespace changes (container escapes), DNS.

- Filter noise in the kernel (for example, opens under `/proc`, `/sys` and shared libraries), unless the path is classed as sensitive.
- Count ring-buffer drops and report them. A drop is a blind spot.

### 4.2 Chain builder

- Groups events into episodes by process tree root (session leader or service cgroup).
- An episode stays open while active and closes after an idle timeout (default 60 s), with a maximum lifetime.
- Every `assess_interval` (default 5 s), it emits only episodes that changed since the last tick.
- A path classifier tags files: `credentials`, `persistence`, `system_binaries`, `user_data`, `temp`.
- Local baseline flags: `new_exe` (first run on this machine), `new_destination` (first connection from this exe to this destination).

### 4.3 Fast rules (hot path)

- Static allow/deny lists compiled into BPF maps. Examples: deny reads of `/etc/shadow` or `~/.ssh/id_*` by programs not on the allowlist; deny kernel module loads except by allowlisted tools.
- Each rule runs in a mode: `observe` (log "would block") or `enforce`.
- **Default: every rule starts in `observe`.**

### 4.4 Assessor (off the hot path)

- **Input:** episode JSON (§5). **Output:** answers to the fixed questions (§6).
- Assesses only episodes that changed *and* pass a cheap pre-filter: a sensitive file category, a baseline flag, or a rule hit.
- Budget: at most 20 episodes per tick by default. Overflow is queued by priority, never dropped silently.
- Two backends behind one interface: `local` and `jev` (§7).
- Every answer is logged with the episode hash, backend and model version. These logs become labeled data later.

### 4.5 Policy engine

- YAML rules evaluated after each assessment. Conditions can use question answers and episode fields.
- Actions: `alert`, `kill_tree`, `block_net`, `quarantine_exe`, `isolate_host` (lab only).
- Safety:
  - global `dry_run: true` by default;
  - a protected-process list (sshd, systemd, dnom itself);
  - a rate limit per action;
  - every action records the rule, the answers and the episode.

```yaml
dry_run: true
rules:
  - name: contain-credential-theft
    when: credential_access >= 0.85 and exfiltration >= 0.6
    actions: [kill_tree, block_net, alert]
  - name: flag-persistence
    when: persistence >= 0.7
    actions: [alert]
```

### 4.6 Privilege split

One binary with two roles:

- `dnom run` (root): runs the sensors and the enforcer.
- `dnom analyzer` (unprivileged user, Landlock + seccomp, network limited to the model endpoint): runs the chain builder, assessor and policy engine.

Attacker-controlled strings (paths, argv) are parsed only in the analyzer. The root process receives only fixed-format, validated actions.

## 5. Episode format (example)

```json
{
  "episode_id": "ep-7f3a",
  "window": { "start": "2026-11-08T14:02:11Z", "end": "2026-11-08T14:02:16Z" },
  "root": { "exe": "/usr/bin/npm", "argv": "npm install some-package", "uid": 1000 },
  "tree": [
    { "exe": "/usr/bin/node", "parent": "npm" },
    { "exe": "/usr/bin/sh", "parent": "node", "argv": "sh -c curl -d @- https://..." }
  ],
  "files": { "credentials": ["~/.ssh/id_ed25519"], "persistence": [] },
  "network": [{ "dest": "203.0.113.7:443", "new_destination": true }],
  "flags": ["new_exe", "shell_from_package_manager"],
  "rule_hits": ["observe:ssh-key-read"]
}
```

Input hygiene: argv capped at 256 characters, strings normalized, and never any file contents.

## 6. Fixed questions (v0.1)

These use Jev's question types, so both backends answer in the same shape. `noul` means "probability that this statement is true" (0–1).

| id | type | Question |
|---|---|---|
| `credential_access` | noul | This activity reads or collects credentials, keys or tokens. |
| `persistence` | noul | This activity makes something run again later (startup, cron, services, shell profiles). |
| `exfiltration` | noul | This activity sends local data to an external destination. |
| `lateral_movement` | noul | This activity tries to reach or log into other machines. |
| `fits_baseline` | noul | This activity is normal for this machine and this program. |
| `response` | choice | `ignore` / `watch` / `alert` / `contain` |

## 7. Model backends

| | `local` (default) | `jev` (comparison) |
|---|---|---|
| Runs on | Ollama on this machine, pinned to the Quadro RTX 8000 (48 GB) | TypeSafe API |
| Data leaves the machine | No | Yes, so lab VM data only |
| Model | Start with the installed `qwen3.6:27b-q8_0` (29 GB); compare with a ~8B model | `jev-latest`, pinned to a version |
| How probabilities are produced | Single-token answer (`yes`/`no` or an option letter); read `top_logprobs` at that token; thinking off | Native `noul` / `choice` with confidence |
| Secret / config | endpoint, model, GPU pin | API key from env `DNOM_JEV_API_KEY`, never in files |

- **GPU pin:** the RTX 4070 Ti SUPER drives the display. Run Ollama with `CUDA_VISIBLE_DEVICES=GPU-e7eee5ae-f5d0-27fa-fbf6-d0ae49ed4332` (the RTX 8000's UUID) so assessments don't compete with the desktop.
- **Prompt order:** episode first, question last, so Ollama reuses the cached prompt prefix across all six questions.
- **Calibration:** raw model probabilities are not calibrated. Calibrate per backend (milestone 5) before any policy runs outside `dry_run`.
- **To verify in milestone 3:** that Ollama returns `top_logprobs` together with constrained output on this version; and Jev's endpoint, request format and cost (from TypeSafe's Quick Start docs).

## 8. Lab (Phase 0)

**Why a VM, not Docker:** containers share the host kernel. eBPF loaded from a container runs in the host kernel, so a bad BPF LSM rule or an attack simulation would hit your desktop. A VM has its own kernel and can be snapshotted and reset. Docker runs *inside* the VM to generate realistic background activity (nginx, postgres, cron jobs).

**Host setup**

```
sudo pacman -S qemu-full libisoburn
```

**Guest**

- Ubuntu Server 26.04 cloud image (~820 MB), set up with cloud-init.
- 4 vCPU, 8 GB RAM, 40 GB qcow2 disk, KVM acceleration.
- QEMU user networking, with SSH forwarded to host port 2222.
- The host's Ollama (`127.0.0.1:11434`) is reachable from the guest at `10.0.2.2:11434`, without exposing it to the LAN.
- Packages: bpftrace, bpftool (linux-tools), docker, build tools.
- Check `/sys/kernel/security/lsm`. If `bpf` is missing, add it to the `lsm=` kernel parameter.
- Take a snapshot named `clean` after setup, and revert to it after every attack run.

**Exercises (bpftrace in the guest)**

1. Watch launches, file opens and connections with bpftrace's bundled tools `execsnoop.bt`, `opensnoop.bt` and `tcpconnect.bt` (find them with `dpkg -L bpftrace | grep '\.bt$'`).
2. Measure event volume per process, idle versus under load:
   `bpftrace -e 'tracepoint:raw_syscalls:sys_enter { @[comm] = count(); } interval:s:10 { exit(); }'`
3. Run three Atomic Red Team Linux tests and record what each tool showed:
   - T1552.004: private key theft
   - T1053.003: cron persistence
   - T1048: exfiltration over another protocol

**Deliverable:** `lab/notes/event-inventory.md`, covering the events that matter, their fields, idle and loaded event rates, what each attack looked like, and what was missing.

## 9. Milestones

| # | Milestone | Exit criteria | Estimate |
|---|---|---|---|
| 0 | Lab + eBPF exploration | VM with `clean` snapshot; event inventory written | 1 weekend |
| 1 | Sensors (aya) | Events in §4.1 emitted as JSON lines; drop counter; CPU overhead measured | 1 weekend |
| 2 | Chain builder | Episodes match §5 for all three attack runs | 1 weekend |
| 3 | Assessor, both backends | Six questions answered; per-episode latency recorded for local and Jev | 1–2 weekends |
| 4 | Policy engine + BPF LSM rules (observe mode) | Dry-run log shows "would contain" for attack runs, and nothing for 24 h of normal activity | 1 weekend |
| 5 | Calibration + comparison | Labeled set (normal hours + attack runs); calibrated thresholds; local vs Jev report | 2–4 weeks |

## 10. Metrics

- **Detection:** share of attack runs where the matching question crosses its threshold.
- **False alerts** per hour of normal activity.
- **Assessment latency:** from episode change to answers, per backend.
- **Sensor overhead:** CPU % and ring-buffer drops.
- **Calibration error** per question and backend.

## 11. Open questions

- Episode boundaries for long-running services (nginx workers): per cgroup or per request?
- Where baseline state lives, and how long learning "normal" takes.
- Defense against a root attacker (off-host log shipping, self-protection), planned after v0.1.
- Whether a fine-tuned small classifier should replace the LLM for high-volume questions.
