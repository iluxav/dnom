//! `dnom collect` (root): load the observe-only eBPF sensors and print events as JSON lines.
//!
//! This process only copies kernel records to stdout. It never interprets paths or argv;
//! that happens in the unprivileged `dnom classify`.

use std::{
    collections::HashMap,
    fs,
    io::{self, BufWriter, Write},
    net::{Ipv4Addr, Ipv6Addr},
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context as _, anyhow, bail};
use aya::{
    Ebpf,
    maps::{Array, MapData, PerCpuArray, RingBuf},
    programs::TracePoint,
};
use dnom_common::*;
use tokio::{io::unix::AsyncFd, signal, time};

use crate::event::{Data, Event};

/// (program name in dnom-ebpf, tracepoint category, tracepoint name)
/// Syscalls come through the two raw_syscalls tracepoints (the per-syscall ones lost most
/// events on Ubuntu's 7.0 kernel); the eBPF side dispatches on the x86_64 syscall number
/// (execve, execveat, open, creat, openat, openat2, connect, sendto).
const PROGRAMS: [(&str, &str, &str); 5] = [
    ("raw_sys_enter", "raw_syscalls", "sys_enter"),
    ("raw_sys_exit", "raw_syscalls", "sys_exit"),
    ("sched_process_exec", "sched", "sched_process_exec"),
    ("sched_process_fork", "sched", "sched_process_fork"),
    ("sched_process_exit", "sched", "sched_process_exit"),
];

/// Tracepoint field offsets the eBPF code hard-codes; checked against tracefs at startup.
const TRACE_OFFSETS: [(&str, &str, &str, u32); 4] = [
    ("raw_syscalls", "sys_enter", "id", 8),
    ("raw_syscalls", "sys_enter", "args", 16),
    ("raw_syscalls", "sys_exit", "id", 8),
    ("raw_syscalls", "sys_exit", "ret", 16),
];

pub async fn run() -> anyhow::Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        bail!("dnom collect loads eBPF programs and must run as root: sudo dnom collect");
    }
    bump_memlock();

    let tracefs = tracefs_root()?;
    if !cfg!(target_arch = "x86_64") {
        bail!("dnom collect dispatches on x86_64 syscall numbers; other architectures are not supported yet");
    }
    for (category, name, field, want) in TRACE_OFFSETS {
        let got = field_offset(tracefs, category, name, field)?;
        if got != want {
            bail!("{category}:{name} field {field} is at offset {got}, eBPF code expects {want}");
        }
    }

    let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/dnom")))
        .context("load eBPF object")?;

    {
        let mut config: Array<_, u32> =
            Array::try_from(ebpf.map_mut("CONFIG").context("CONFIG map")?)?;
        config.set(CFG_OWN_TGID, std::process::id(), 0)?;
        let exec_fn = field_offset(tracefs, "sched", "sched_process_exec", "filename")?;
        let exec_old = field_offset(tracefs, "sched", "sched_process_exec", "old_pid")?;
        let fork_child = field_offset(tracefs, "sched", "sched_process_fork", "child_pid")?;
        config.set(CFG_EXEC_FILENAME_OFF, exec_fn, 0)?;
        config.set(CFG_EXEC_OLD_PID_OFF, exec_old, 0)?;
        config.set(CFG_FORK_CHILD_PID_OFF, fork_child, 0)?;
    }

    for (prog, category, name) in PROGRAMS {
        let program: &mut TracePoint = ebpf
            .program_mut(prog)
            .ok_or_else(|| anyhow!("program {prog} missing from eBPF object"))?
            .try_into()?;
        program.load().with_context(|| format!("load {prog}"))?;
        program
            .attach(category, name)
            .with_context(|| format!("attach {category}:{name}"))?;
    }

    let ring = RingBuf::try_from(ebpf.take_map("EVENTS").context("EVENTS map")?)?;
    let stats: PerCpuArray<MapData, u64> =
        PerCpuArray::try_from(ebpf.take_map("STATS").context("STATS map")?)?;
    // SAFETY: the RingBuf owns its map fd, which stays open and unchanged while AsyncFd owns it.
    let mut ring = unsafe {
        AsyncFd::register_with_interest(ring, tokio::io::Interest::READABLE)
            .map_err(|e| anyhow!("register ring buffer fd: {e}"))?
    };

    eprintln!("dnom collect: {} sensors attached, printing JSON lines (Ctrl-C to stop)", PROGRAMS.len());

    let clock = Clock::new();
    let mut out = BufWriter::new(io::stdout().lock());
    // Processes already running when the sensors attached: without this, a consumer on
    // another machine (classify --remote-source) would only ever see their pids.
    let snapshot = snapshot_processes(&mut out)?;
    eprintln!("dnom collect: snapshot of {snapshot} running processes");
    let mut pending_argv: HashMap<u32, Vec<String>> = HashMap::new();
    let mut emitted: u64 = 0;
    let mut dropped_reported: u64 = 0;
    // Safety net: drain once a second even without a wakeup, and report drops every 10 s.
    let mut drain_tick = time::interval(Duration::from_secs(1));
    let mut ticks: u64 = 0;
    let ctrl_c = signal::ctrl_c();
    tokio::pin!(ctrl_c);

    loop {
        tokio::select! {
            _ = &mut ctrl_c => break,
            _ = drain_tick.tick() => {
                if !drain(ring.get_mut(), &mut out, &clock, &mut pending_argv, &mut emitted)? {
                    return Ok(());
                }
                ticks += 1;
                if ticks % 10 == 0 {
                    let dropped = total_dropped(&stats);
                    if dropped > dropped_reported {
                        eprintln!("dnom collect: {} events dropped so far (ring buffer full)", dropped);
                        dropped_reported = dropped;
                    }
                }
            }
            guard = ring.readable_mut() => {
                let mut guard = guard?;
                // Clear readiness BEFORE draining. The kernel only wakes us when we have caught
                // up; clearing after the drain could erase a wakeup for a record that arrived in
                // between, and no further wakeup would ever come (the collector would stall).
                guard.clear_ready();
                if !drain(guard.get_inner_mut(), &mut out, &clock, &mut pending_argv, &mut emitted)? {
                    return Ok(());
                }
            }
        }
    }

    eprintln!(
        "dnom collect: stopped. {emitted} events emitted, {} dropped",
        total_dropped(&stats)
    );
    Ok(())
}

/// One fork (parent -> child) plus one exec event per running process, oldest first so a
/// parent is always described before its children. Kernel threads and dnom itself are skipped.
fn snapshot_processes(out: &mut impl Write) -> anyhow::Result<usize> {
    let own = std::process::id();
    let now_ms = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0);
    let mut procs = Vec::new();
    for entry in fs::read_dir("/proc").context("read /proc")?.flatten() {
        let Some(pid) = entry.file_name().to_str().and_then(|n| n.parse::<u32>().ok()) else { continue };
        if pid == own {
            continue;
        }
        let dir = entry.path();
        // Kernel threads have no executable.
        let Ok(exe) = fs::read_link(dir.join("exe")) else { continue };
        let Ok(stat) = fs::read_to_string(dir.join("stat")) else { continue };
        // comm is in parentheses and may contain spaces; fields after it are space-separated.
        let (Some(open), Some(close)) = (stat.find('('), stat.rfind(')')) else { continue };
        let comm = stat[open + 1..close].to_string();
        let rest: Vec<&str> = stat[close + 2..].split(' ').collect();
        let ppid: u32 = rest.get(1).and_then(|v| v.parse().ok()).unwrap_or(0);
        let start: u64 = rest.get(19).and_then(|v| v.parse().ok()).unwrap_or(0);
        let uid = fs::read_to_string(dir.join("status"))
            .ok()
            .and_then(|s| s.lines().find_map(|l| l.strip_prefix("Uid:").map(|u| u.split_whitespace().next().unwrap_or("").to_string())))
            .and_then(|u| u.parse().ok())
            .unwrap_or(u32::MAX);
        let argv: Vec<String> = fs::read(dir.join("cmdline"))
            .unwrap_or_default()
            .split(|&b| b == 0)
            .filter(|a| !a.is_empty())
            .take(ARGV_MAX)
            .map(|a| String::from_utf8_lossy(&a[..a.len().min(ARG_LEN - 1)]).into_owned())
            .collect();
        procs.push((start, pid, ppid, uid, comm, exe.to_string_lossy().into_owned(), argv));
    }
    procs.sort_by_key(|p| (p.0, p.1));
    for (_, pid, ppid, uid, comm, exe, argv) in &procs {
        let base = |data| Event { ts_ms: now_ms, pid: *pid, tid: *pid, uid: *uid, comm: comm.clone(), cgroup: 0, data };
        if *ppid > 0 {
            let fork = Event { pid: *ppid, tid: *ppid, comm: String::new(), ..base(Data::Fork { child: *pid }) };
            write_event(out, &fork)?;
        }
        write_event(out, &base(Data::Exec { exe: exe.clone(), argv: argv.clone() }))?;
    }
    out.flush()?;
    Ok(procs.len())
}

/// Prints every record in the ring buffer. Returns false when stdout is gone (the reader,
/// e.g. classify, exited), so the caller can stop quietly.
fn drain(
    rb: &mut RingBuf<MapData>,
    out: &mut impl Write,
    clock: &Clock,
    pending_argv: &mut HashMap<u32, Vec<String>>,
    emitted: &mut u64,
) -> anyhow::Result<bool> {
    while let Some(item) = rb.next() {
        if let Some(event) = decode(&item, clock, pending_argv) {
            if write_event(out, &event).is_err() {
                return Ok(false);
            }
            *emitted += 1;
        }
    }
    Ok(out.flush().is_ok())
}

fn write_event(out: &mut impl Write, event: &Event) -> io::Result<()> {
    serde_json::to_writer(&mut *out, event)?;
    out.write_all(b"\n")
}

fn total_dropped(stats: &PerCpuArray<MapData, u64>) -> u64 {
    stats
        .get(&STAT_DROPPED, 0)
        .map(|values| values.iter().sum())
        .unwrap_or(0)
}

/// Turns one ring buffer record into an event. `ExecArgs` records are held until the
/// matching `Exec` arrives, so failed exec attempts (PATH search) never show up.
fn decode(bytes: &[u8], clock: &Clock, pending_argv: &mut HashMap<u32, Vec<String>>) -> Option<Event> {
    let hdr: Header = read_record(bytes)?;
    let data = match hdr.kind {
        KIND_EXEC_ARGS => {
            let rec: ExecArgs = read_record(bytes)?;
            let argc = (rec.argc as usize).min(ARGV_MAX);
            let argv = rec.argv[..argc].iter().map(|a| cstr(a)).collect();
            if pending_argv.len() > 8192 {
                pending_argv.clear();
            }
            pending_argv.insert(hdr.tid, argv);
            return None;
        }
        KIND_EXEC => {
            let rec: Exec = read_record(bytes)?;
            Data::Exec {
                exe: cstr(&rec.filename),
                argv: pending_argv.remove(&rec.old_pid).unwrap_or_default(),
            }
        }
        KIND_FORK => {
            let rec: Fork = read_record(bytes)?;
            Data::Fork { child: rec.child_pid }
        }
        KIND_EXIT => Data::Exit {},
        KIND_OPEN => {
            let rec: Open = read_record(bytes)?;
            let raw = cstr(&rec.filename);
            if raw.is_empty() {
                return None;
            }
            let write = rec.flags & 0o3 != 0 || rec.flags & (0o100 | 0o1000) != 0;
            Data::Open {
                path: resolve_open_path(hdr.tid, rec.dfd, &raw),
                flags: rec.flags,
                write,
            }
        }
        KIND_NET => {
            let rec: Net = read_record(bytes)?;
            let dest = match rec.family {
                AF_INET => {
                    let a = &rec.addr;
                    format!("{}:{}", Ipv4Addr::new(a[0], a[1], a[2], a[3]), rec.port)
                }
                _ => format!("[{}]:{}", Ipv6Addr::from(rec.addr), rec.port),
            };
            let op = if rec.op == NET_OP_SENDTO { "sendto" } else { "connect" };
            Data::Net { op: op.into(), dest }
        }
        _ => return None,
    };
    Some(Event {
        ts_ms: clock.to_unix_ms(hdr.ts_ns),
        pid: hdr.tgid,
        tid: hdr.tid,
        uid: hdr.uid,
        comm: cstr(&hdr.comm),
        cgroup: hdr.cgroup_id,
        data,
    })
}

const AT_FDCWD: i32 = -100;

/// Makes a relative `openat` path absolute, using the thread's working directory
/// (`dfd == AT_FDCWD`) or the directory fd it opened relative to. Read from /proc as soon as
/// the event arrives, so it is right unless the process changed directory in the last few
/// milliseconds. Returns the path unchanged (still relative) when it can't be resolved; the
/// classifier shows those as `?/<path>`.
fn resolve_open_path(tid: u32, dfd: i32, raw: &str) -> String {
    if raw.starts_with('/') {
        return raw.to_string();
    }
    let base = match dfd {
        AT_FDCWD => format!("/proc/{tid}/cwd"),
        fd if fd >= 0 => format!("/proc/{tid}/fd/{fd}"),
        _ => return raw.to_string(),
    };
    match fs::read_link(&base) {
        // Sockets and pipes read back as "socket:[…]", not an absolute path.
        Ok(dir) if dir.is_absolute() => normalize(&dir.to_string_lossy(), raw),
        _ => raw.to_string(),
    }
}

/// Joins `dir` and `rel`, dropping `.` and resolving `..` lexically.
fn normalize(dir: &str, rel: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for part in dir.split('/').chain(rel.split('/')) {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            p => parts.push(p),
        }
    }
    format!("/{}", parts.join("/"))
}

fn read_record<T: Copy>(bytes: &[u8]) -> Option<T> {
    if bytes.len() < size_of::<T>() {
        return None;
    }
    // SAFETY: length checked; T is a plain #[repr(C)] record from dnom-common.
    Some(unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<T>()) })
}

fn cstr(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

/// Converts `bpf_ktime_get_ns` (CLOCK_MONOTONIC) to Unix time.
struct Clock {
    offset_ns: i128,
}

impl Clock {
    fn new() -> Self {
        let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
        let mono = ts.tv_sec as i128 * 1_000_000_000 + ts.tv_nsec as i128;
        let real = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as i128)
            .unwrap_or(0);
        Self { offset_ns: real - mono }
    }

    fn to_unix_ms(&self, mono_ns: u64) -> u64 {
        ((mono_ns as i128 + self.offset_ns) / 1_000_000).max(0) as u64
    }
}

fn bump_memlock() {
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
}

fn tracefs_root() -> anyhow::Result<&'static str> {
    for root in ["/sys/kernel/tracing", "/sys/kernel/debug/tracing"] {
        if Path::new(root).join("events").is_dir() {
            return Ok(root);
        }
    }
    bail!("tracefs not found at /sys/kernel/tracing or /sys/kernel/debug/tracing")
}

/// Reads a field's byte offset from `<tracefs>/events/<category>/<name>/format`.
fn field_offset(tracefs: &str, category: &str, name: &str, field: &str) -> anyhow::Result<u32> {
    let path = format!("{tracefs}/events/{category}/{name}/format");
    let text = fs::read_to_string(&path).with_context(|| format!("read {path}"))?;
    for line in text.lines() {
        let Some(rest) = line.trim().strip_prefix("field:") else {
            continue;
        };
        let mut parts = rest.split(';');
        let decl = parts.next().unwrap_or("").trim();
        let ident = decl
            .rsplit(|c: char| c.is_whitespace() || c == '*')
            .next()
            .unwrap_or("")
            .split('[')
            .next()
            .unwrap_or("");
        if ident != field {
            continue;
        }
        let offset = parts
            .next()
            .and_then(|p| p.trim().strip_prefix("offset:"))
            .ok_or_else(|| anyhow!("no offset for {field} in {path}"))?;
        return offset.parse().with_context(|| format!("parse offset for {field} in {path}"));
    }
    bail!("field {field} not found in {path}")
}

#[cfg(test)]
mod tests {
    use std::{fs::File, os::fd::AsRawFd};

    use super::*;

    #[test]
    fn normalize_joins_and_cleans() {
        assert_eq!(normalize("/tmp/a", "b/./c"), "/tmp/a/b/c");
        assert_eq!(normalize("/tmp/a", "../b"), "/tmp/b");
        assert_eq!(normalize("/", "x"), "/x");
    }

    #[test]
    fn resolves_against_cwd_and_dirfd() {
        let me = std::process::id();
        assert_eq!(resolve_open_path(me, AT_FDCWD, "/etc/passwd"), "/etc/passwd");

        let cwd = std::env::current_dir().unwrap();
        assert_eq!(
            resolve_open_path(me, AT_FDCWD, "x/y"),
            format!("{}/x/y", cwd.display())
        );

        let dir = File::open("/usr").unwrap();
        assert_eq!(resolve_open_path(me, dir.as_raw_fd(), "bin/../lib"), "/usr/lib");

        // Not a directory fd / bad fd: left relative.
        assert_eq!(resolve_open_path(me, 9999, "z"), "z");
        assert_eq!(resolve_open_path(me, -5, "z"), "z");
    }
}
