# Event inventory (lab, 2026-11-08)

What dnom's sensor records, how much of it, and what the lab runs found. Reproduce with
`make vm-start && make vm-e2e` (31 checks; results in `~/.local/state/dnom/vm-e2e/`).

- **VM:** Ubuntu 26.04, kernel 7.0.0-38-generic, 4 vCPU, 8 GB, BPF LSM on (`lab/vm`).
- **Host:** Arch (Omarchy), kernel 7.2.15.
- **dnom:** commit 4550299 plus the exec-arguments fix (finding 3).

## 1. Sensors and events

Five eBPF programs, all observe-only.

| Program | Fires on | Event |
|---|---|---|
| `raw_syscalls:sys_enter` | execve, execveat | arguments at entry (held, see `exec`) |
| | open, creat, openat, openat2 | parked until the syscall returns |
| | connect, sendto with a destination | `net` |
| `raw_syscalls:sys_exit` | successful open family | `open` (failed opens are never reported) |
| | successful execve, execveat | arguments from the new program's stack |
| `sched:sched_process_exec` | every successful exec | `exec` (path of the executable) |
| `sched:sched_process_fork` | fork, clone | `fork` (parent → child) |
| `sched:sched_process_exit` | exit of a thread-group leader | `exit` |
| startup snapshot (`/proc`) | processes running when the sensor attaches | `fork` + `exec` per process |

Every event carries `ts_ms`, `pid`, `tid`, `uid`, `comm` and `cgroup`. Per kind:
`exec {exe, argv}`, `fork {child}`, `exit {}`, `open {path, flags, write}`, `net {op, dest}`.

Dropped in the kernel: opens under `/proc/` and `/sys/`, `/dev/null`, ttys and other device
noise, read-only opens of libraries, fonts and shared data, and directory and `O_PATH` opens.

| Ring buffer record | Bytes |
|---|---|
| header (in every record) | 48 |
| exec arguments (two per exec) | 568 |
| exec, open | 312 |
| net | 72 |
| fork / exit | 56 / 48 |

The ring buffer is 16 MiB. A JSON event line averages about 145 bytes.

## 2. Rates

| Situation | Events | Notes |
|---|---|---|
| VM idle, 30 s | **0** | only the 57-line startup snapshot |
| VM under the e2e workload (round 1) | **3,222 in 13.1 s, ≈ 250/s** | open 1,436, fork 600, exec 593, exit 561, net 32 |
| e2e, every round | **0 dropped** | the reported count equals the lines written |
| Desktop, earlier sensor (before the fixes) | ≈ 13/s | about 200 per 15 s status line; not remeasured |
| Falco catch-all rules on the desktop | ≈ 57/s | about 2,550 in 45 s; Falco's own filters |

596 of the 1,436 opens in the e2e round are `/proc` noise from one `pkill` (finding 7).

Model calls are far fewer than events: only episodes that pass the pre-filter are sent. Jev
answered in 120–200 ms per episode, about 1.4k input tokens each.

## 3. Findings

| # | Finding | Effect | Status |
|---|---|---|---|
| 1 | Per-syscall tracepoints are unreliable on Ubuntu's 7.0.0-38 kernel: `syscalls:sys_enter_execve` fired for 2 of 200 execve calls; `raw_syscalls:sys_enter` for 203 of 200 (measured with bpftrace) | arguments, opens and connections missing | fixed: dispatch on `raw_syscalls` (a749b0d) |
| 2 | Collector stall: readiness was cleared after draining the ring buffer, which could erase the kernel's only wakeup | the collector could go silent for good | fixed, plus a 1 s safety drain; e2e checks delivery after 8 s of quiet (a749b0d) |
| 3 | Arguments read at execve entry come from the caller's memory; strings on pages not loaded yet read as empty. `unix_chkpwd` arrived as `['', 'lab', '']` (5 of 429 execs) | incomplete command lines sent to the model | fixed: arguments re-read at syscall exit from the new stack; 0 of 108 empty after. Scripts now show the arguments as run, e.g. `/usr/bin/env bash ./x.sh` |
| 4 | A script started over SSH (`bash -c` exec'ing into the script) counted as an interactive shell | its children split into separate episodes | fixed (a749b0d) |
| 5 | sshd `connect()`s to `0.0.0.0:22` and `[::]:22` on every login | false "new destination" rule match per login | fixed: this machine's own addresses are never new (a749b0d) |
| 6 | `classify` assessed only 4 episodes (the per-tick budget) when its input ended | 33 of 37 episodes silently dropped | fixed (4550299) |
| 7 | Opens relative to a directory handle skip the kernel noise filter. procps tools (pkill, ps, top) open `<pid>/stat` relative to `/proc`, so the prefix check never sees `/proc/` | 41% of the opens in an e2e round are `/proc` noise | **open**: drop resolved `/proc` and `/sys` paths in userspace |
| 8 | Desktop runs: ssh probes 12 key names (failed opens counted as reads); `mkdir -p` relative paths went stale after a fast `chdir` | inflated credential scores; wrong paths | fixed: opens reported only on success; directory opens dropped |

## 4. Not visible yet

1. **Reads of `/proc/<pid>/environ` and `/proc/<pid>/mem`:** a credential-theft path, filtered as `/proc` noise.
2. **Long command lines:** only the first 8 arguments, each cut to 63 bytes.
3. **32-bit (ia32) processes:** their syscall numbers differ, and the dispatch assumes x86_64 numbers.
4. **Activity that skips these syscalls:** io_uring file and network operations, `sendmsg` and `sendmmsg`, and inbound `accept`.
5. **Context:** destinations are IP addresses only, with no hostnames; cgroup ids aren't mapped to containers or pods; processes from the startup snapshot have no history.

Not built from SPEC §4.1 yet: privilege changes (`commit_creds`), module and eBPF program
loads, `ptrace`, namespace changes.
