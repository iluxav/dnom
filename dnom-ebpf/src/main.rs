//! dnom eBPF sensors (observe-only): tracepoints that copy process, file and network
//! activity into one ring buffer. Nothing here blocks or changes kernel behaviour.
#![no_std]
#![no_main]

use aya_ebpf::{
    EbpfContext,
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_probe_read_kernel, bpf_probe_read_kernel_str_bytes, bpf_probe_read_user, bpf_probe_read_user_buf,
        bpf_probe_read_user_str_bytes,
        generated::{bpf_get_current_cgroup_id, bpf_get_current_task_btf, bpf_ktime_get_ns, bpf_task_pt_regs},
    },
    macros::{map, tracepoint},
    maps::{Array, LruHashMap, PerCpuArray, RingBuf},
    programs::TracePointContext,
};
use dnom_common::*;

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(16 * 1024 * 1024, 0);

#[map]
static CONFIG: Array<u32> = Array::with_max_entries(CFG_LEN, 0);

#[map]
static STATS: PerCpuArray<u64> = PerCpuArray::with_max_entries(STAT_LEN, 0);

/// Scratch space to build an `Open` record (too big for comfortable stack use).
#[map]
static OPEN_SCRATCH: PerCpuArray<Open> = PerCpuArray::with_max_entries(1, 0);

/// Opens seen at syscall entry, keyed by thread id, waiting for the syscall's result.
/// Only successful opens are emitted, so probing for files that don't exist (ssh trying
/// every default key name) doesn't look like reading them.
#[map]
static PENDING_OPENS: LruHashMap<u32, Open> = LruHashMap::with_max_entries(16384, 0);

// raw_syscalls:sys_enter is `long id` at 8 and `unsigned long args[6]` at 16;
// raw_syscalls:sys_exit is `long id` at 8 and `long ret` at 16. Userspace checks these
// offsets against tracefs before attaching.
//
// Why raw_syscalls and not syscalls:sys_enter_<name>: on Ubuntu's 7.0.0-38 kernel the
// per-syscall tracepoints fired for 2 of 200 execve calls (raw_syscalls: 203 of 200).
const RAW_ID: usize = 8;
const SYS_ARG: [usize; 6] = [16, 24, 32, 40, 48, 56];
const SYS_EXIT_RET: usize = 16;

// x86_64 syscall numbers (userspace refuses to run on other architectures).
const NR_OPEN: i64 = 2;
const NR_CONNECT: i64 = 42;
const NR_SENDTO: i64 = 44;
const NR_EXECVE: i64 = 59;
const NR_CREAT: i64 = 85;
const NR_OPENAT: i64 = 257;
const NR_EXECVEAT: i64 = 322;
const NR_OPENAT2: i64 = 437;

const AT_FDCWD: i32 = -100;
/// Offset of `sp` in x86_64 `struct pt_regs` (r15..di, orig_ax, ip, cs, flags, sp).
const PT_REGS_SP: usize = 152;
const O_WRONLY: i32 = 0o1;

const O_ACCMODE: i32 = 0o3;
const O_CREAT: i32 = 0o100;
const O_TRUNC: i32 = 0o1000;
const O_DIRECTORY: i32 = 0o200000;
const O_PATH: i32 = 0o10000000;

/// Opens dropped in the kernel whatever the flags.
const NOISE_ALWAYS: [&[u8]; 9] = [
    b"/proc/",
    b"/sys/",
    b"/dev/null",
    b"/dev/tty",
    b"/dev/pts/",
    b"/dev/urandom",
    b"/dev/random",
    b"/dev/dri/",
    b"/dev/nvidia",
];

/// Opens dropped only when read-only (libraries, fonts, icons, loader cache).
const NOISE_READ: [&[u8]; 8] = [
    b"/usr/lib",
    b"/lib",
    b"/usr/share/",
    b"/usr/local/lib",
    b"/etc/ld.so",
    b"/etc/fonts/",
    b"/var/cache/fontconfig/",
    b"/usr/libexec/",
];

#[inline(always)]
fn cfg(index: u32) -> u32 {
    CONFIG.get(index).copied().unwrap_or(0)
}

#[inline(always)]
fn current_tgid() -> u32 {
    (bpf_get_current_pid_tgid() >> 32) as u32
}

/// True for dnom's own collector process, so its activity never feeds back into the stream.
#[inline(always)]
fn is_self(tgid: u32) -> bool {
    let own = cfg(CFG_OWN_TGID);
    own != 0 && own == tgid
}

#[inline(always)]
fn count_drop() {
    if let Some(counter) = STATS.get_ptr_mut(STAT_DROPPED) {
        unsafe { *counter += 1 };
    }
}

/// # Safety
/// `hdr` must point to writable memory for a `Header` (a ring buffer reservation).
#[inline(always)]
unsafe fn fill_header(hdr: *mut Header, kind: u32) {
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();
    unsafe {
        (*hdr).kind = kind;
        (*hdr).tgid = (pid_tgid >> 32) as u32;
        (*hdr).tid = pid_tgid as u32;
        (*hdr).uid = uid_gid as u32;
        (*hdr).ts_ns = bpf_ktime_get_ns();
        (*hdr).cgroup_id = bpf_get_current_cgroup_id();
        (*hdr).comm = bpf_get_current_comm().unwrap_or([0; COMM_LEN]);
    }
}

#[inline(always)]
fn has_prefix(path: &[u8; PATH_LEN], prefix: &[u8]) -> bool {
    let mut i = 0;
    while i < prefix.len() && i < PATH_LEN {
        if path[i] != prefix[i] {
            return false;
        }
        i += 1;
    }
    true
}

#[inline(always)]
fn is_noise(path: &[u8; PATH_LEN], flags: i32) -> bool {
    // Directory handles (ls, find, `mkdir -p` stepping into folders) and O_PATH handles
    // never read file contents. They are also the opens whose relative paths go stale
    // fastest, because the same programs change directory right after.
    if flags & (O_DIRECTORY | O_PATH) != 0 {
        return true;
    }
    for prefix in NOISE_ALWAYS {
        if has_prefix(path, prefix) {
            return true;
        }
    }
    let read_only = flags & O_ACCMODE == 0 && flags & (O_CREAT | O_TRUNC) == 0;
    if read_only {
        for prefix in NOISE_READ {
            if has_prefix(path, prefix) {
                return true;
            }
        }
    }
    false
}

// ---------------------------------------------------------------------------------------------
// Syscall entry / exit: one program each, dispatching on the syscall number
// ---------------------------------------------------------------------------------------------

#[tracepoint]
pub fn raw_sys_enter(ctx: TracePointContext) -> u32 {
    let Ok(id) = (unsafe { ctx.read_at::<i64>(RAW_ID) }) else { return 0 };
    let arg = |i: usize| -> u64 { unsafe { ctx.read_at::<u64>(SYS_ARG[i]) }.unwrap_or(0) };
    let _ = match id {
        NR_EXECVE => on_execve(arg(1) as *const *const u8),
        NR_EXECVEAT => on_execve(arg(2) as *const *const u8),
        NR_OPEN => on_open(AT_FDCWD, arg(0) as *const u8, arg(1) as i32),
        NR_CREAT => on_open(AT_FDCWD, arg(0) as *const u8, O_CREAT | O_WRONLY | O_TRUNC),
        NR_OPENAT => on_open(arg(0) as i32, arg(1) as *const u8, arg(2) as i32),
        NR_OPENAT2 => {
            // openat2(dfd, filename, struct open_how *how, size): how->flags is the first u64.
            let flags: u64 = unsafe { bpf_probe_read_user(arg(2) as *const u64) }.unwrap_or(0);
            on_open(arg(0) as i32, arg(1) as *const u8, flags as i32)
        }
        // connect(fd, uservaddr, addrlen)
        NR_CONNECT => on_net(NET_OP_CONNECT, arg(1) as *const u8),
        // sendto(fd, buff, len, flags, addr, addr_len): only calls that name a destination.
        NR_SENDTO => on_net(NET_OP_SENDTO, arg(4) as *const u8),
        _ => Ok(()),
    };
    0
}

#[tracepoint]
pub fn raw_sys_exit(ctx: TracePointContext) -> u32 {
    let Ok(id) = (unsafe { ctx.read_at::<i64>(RAW_ID) }) else { return 0 };
    let ret: i64 = unsafe { ctx.read_at(SYS_EXIT_RET) }.unwrap_or(-1);
    match id {
        NR_OPEN | NR_CREAT | NR_OPENAT | NR_OPENAT2 => on_open_exit(ret),
        NR_EXECVE | NR_EXECVEAT if ret == 0 => {
            let _ = on_exec_done();
        }
        _ => {}
    }
    0
}

// ---------------------------------------------------------------------------------------------
// Process lifecycle
// ---------------------------------------------------------------------------------------------

fn on_execve(argv: *const *const u8) -> Result<(), i32> {
    if is_self(current_tgid()) {
        return Ok(());
    }
    // Read from the caller's memory. Strings on pages that aren't loaded yet (e.g. a binary's
    // read-only literals) can't be read here and come out empty; on_exec_done fills them in.
    emit_argv(argv, KIND_EXEC_ARGS)
}

/// After a successful execve the new program's arguments sit at the top of its fresh stack
/// (argc, then the argv pointers), written by the kernel just before, so unlike the caller's
/// memory they are always readable.
fn on_exec_done() -> Result<(), i32> {
    if is_self(current_tgid()) {
        return Ok(());
    }
    let regs = unsafe { bpf_task_pt_regs(bpf_get_current_task_btf()) } as *const u8;
    if regs.is_null() {
        return Ok(());
    }
    let sp: u64 = unsafe { bpf_probe_read_kernel(regs.add(PT_REGS_SP) as *const u64)? };
    emit_argv((sp + 8) as *const *const u8, KIND_EXEC_ARGS_DONE)
}

fn emit_argv(argv: *const *const u8, kind: u32) -> Result<(), i32> {
    let Some(mut entry) = EVENTS.reserve::<ExecArgs>(0) else {
        count_drop();
        return Ok(());
    };
    let ev = entry.as_mut_ptr();
    unsafe {
        fill_header(&raw mut (*ev).hdr, kind);
        (*ev).argc = 0;
        (*ev)._pad = 0;
        let mut i = 0;
        while i < ARGV_MAX {
            let arg: *const u8 = match bpf_probe_read_user(argv.add(i)) {
                Ok(p) => p,
                Err(_) => break,
            };
            if arg.is_null() {
                break;
            }
            if bpf_probe_read_user_str_bytes(arg, &mut (*ev).argv[i]).is_err() {
                (*ev).argv[i][0] = 0;
            }
            i += 1;
            (*ev).argc = i as u32;
        }
    }
    entry.submit(0);
    Ok(())
}

#[tracepoint]
pub fn sched_process_exec(ctx: TracePointContext) -> u32 {
    let _ = try_sched_process_exec(&ctx);
    0
}

fn try_sched_process_exec(ctx: &TracePointContext) -> Result<(), i32> {
    if is_self(current_tgid()) {
        return Ok(());
    }
    let loc_off = cfg(CFG_EXEC_FILENAME_OFF) as usize;
    let old_pid_off = cfg(CFG_EXEC_OLD_PID_OFF) as usize;
    if loc_off == 0 || old_pid_off == 0 {
        return Ok(());
    }
    // __data_loc: low 16 bits = offset of the string from the start of the record.
    let loc: u32 = unsafe { ctx.read_at(loc_off)? };
    let old_pid: u32 = unsafe { ctx.read_at(old_pid_off)? };
    let Some(mut entry) = EVENTS.reserve::<Exec>(0) else {
        count_drop();
        return Ok(());
    };
    let ev = entry.as_mut_ptr();
    unsafe {
        fill_header(&raw mut (*ev).hdr, KIND_EXEC);
        (*ev).old_pid = old_pid;
        (*ev)._pad = 0;
        let src = (ctx.as_ptr() as *const u8).add((loc & 0xffff) as usize);
        if bpf_probe_read_kernel_str_bytes(src, &mut (*ev).filename).is_err() {
            (*ev).filename[0] = 0;
        }
    }
    entry.submit(0);
    Ok(())
}

#[tracepoint]
pub fn sched_process_fork(ctx: TracePointContext) -> u32 {
    let _ = try_sched_process_fork(&ctx);
    0
}

fn try_sched_process_fork(ctx: &TracePointContext) -> Result<(), i32> {
    if is_self(current_tgid()) {
        return Ok(());
    }
    let child_off = cfg(CFG_FORK_CHILD_PID_OFF) as usize;
    if child_off == 0 {
        return Ok(());
    }
    let child_pid: u32 = unsafe { ctx.read_at(child_off)? };
    let Some(mut entry) = EVENTS.reserve::<Fork>(0) else {
        count_drop();
        return Ok(());
    };
    let ev = entry.as_mut_ptr();
    unsafe {
        fill_header(&raw mut (*ev).hdr, KIND_FORK);
        (*ev).child_pid = child_pid;
        (*ev)._pad = 0;
    }
    entry.submit(0);
    Ok(())
}

#[tracepoint]
pub fn sched_process_exit(_ctx: TracePointContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    // Only the thread group leader: one exit per process, not per thread.
    if pid_tgid as u32 != tgid || is_self(tgid) {
        return 0;
    }
    let Some(mut entry) = EVENTS.reserve::<Exit>(0) else {
        count_drop();
        return 0;
    };
    let ev = entry.as_mut_ptr();
    unsafe { fill_header(&raw mut (*ev).hdr, KIND_EXIT) };
    entry.submit(0);
    0
}

// ---------------------------------------------------------------------------------------------
// Files
// ---------------------------------------------------------------------------------------------

fn on_open(dfd: i32, filename: *const u8, flags: i32) -> Result<(), i32> {
    if is_self(current_tgid()) {
        return Ok(());
    }
    let Some(ev) = OPEN_SCRATCH.get_ptr_mut(0) else {
        return Ok(());
    };
    let noise = unsafe {
        if bpf_probe_read_user_str_bytes(filename, &mut (*ev).filename).is_err() {
            (*ev).filename[0] = 0;
        }
        is_noise(&(*ev).filename, flags)
    };
    if noise {
        return Ok(());
    }
    unsafe {
        fill_header(&raw mut (*ev).hdr, KIND_OPEN);
        (*ev).flags = flags;
        (*ev).dfd = dfd;
    }
    let tid = bpf_get_current_pid_tgid() as u32;
    if PENDING_OPENS.insert(tid, unsafe { &*ev }, 0).is_err() {
        count_drop();
    }
    Ok(())
}

/// Emits the open that `on_open` parked for this thread, if the syscall succeeded.
fn on_open_exit(ret: i64) {
    let tid = bpf_get_current_pid_tgid() as u32;
    // Most opens were filtered as noise at entry and have nothing pending.
    let Some(pending) = (unsafe { PENDING_OPENS.get(tid) }) else {
        return;
    };
    if ret >= 0 && EVENTS.output::<Open>(pending, 0).is_err() {
        count_drop();
    }
    let _ = PENDING_OPENS.remove(tid);
}

// ---------------------------------------------------------------------------------------------
// Network
// ---------------------------------------------------------------------------------------------

fn on_net(op: u32, addr: *const u8) -> Result<(), i32> {
    if is_self(current_tgid()) {
        return Ok(());
    }
    if addr.is_null() {
        return Ok(());
    }
    let family: u16 = unsafe { bpf_probe_read_user(addr as *const u16)? };
    if family != AF_INET && family != AF_INET6 {
        return Ok(());
    }
    let port_be: u16 = unsafe { bpf_probe_read_user(addr.add(2) as *const u16)? };
    let Some(mut entry) = EVENTS.reserve::<Net>(0) else {
        count_drop();
        return Ok(());
    };
    let ev = entry.as_mut_ptr();
    unsafe {
        fill_header(&raw mut (*ev).hdr, KIND_NET);
        (*ev).op = op;
        (*ev).family = family;
        (*ev).port = u16::from_be(port_be);
        (*ev).addr = [0; 16];
        let read = if family == AF_INET {
            // sockaddr_in: family(2) port(2) addr(4)
            bpf_probe_read_user_buf(addr.add(4), &mut (&mut (*ev).addr)[..4])
        } else {
            // sockaddr_in6: family(2) port(2) flowinfo(4) addr(16)
            bpf_probe_read_user_buf(addr.add(8), &mut (*ev).addr)
        };
        if read.is_err() {
            (*ev).addr = [0; 16];
        }
    }
    entry.submit(0);
    Ok(())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
