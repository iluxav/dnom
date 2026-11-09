//! Event records shared by the eBPF programs and the userspace collector.
//!
//! Every record starts with [`Header`]; `Header::kind` says which struct follows.
//! Records are `#[repr(C)]` and copied byte-for-byte through the BPF ring buffer.
#![no_std]

pub const COMM_LEN: usize = 16;
pub const PATH_LEN: usize = 256;
pub const ARGV_MAX: usize = 8;
pub const ARG_LEN: usize = 64;

pub const KIND_EXEC_ARGS: u32 = 1;
pub const KIND_EXEC: u32 = 2;
pub const KIND_FORK: u32 = 3;
pub const KIND_EXIT: u32 = 4;
pub const KIND_OPEN: u32 = 5;
pub const KIND_NET: u32 = 6;
/// Arguments read at the exit of a successful execve, from the new program's stack.
pub const KIND_EXEC_ARGS_DONE: u32 = 7;

pub const NET_OP_CONNECT: u32 = 1;
pub const NET_OP_SENDTO: u32 = 2;

pub const AF_INET: u16 = 2;
pub const AF_INET6: u16 = 10;

/// Indexes into the `CONFIG` array map, filled by userspace before attaching.
pub const CFG_OWN_TGID: u32 = 0;
/// Offset of `__data_loc char[] filename` in `sched:sched_process_exec`.
pub const CFG_EXEC_FILENAME_OFF: u32 = 1;
/// Offset of `pid_t old_pid` in `sched:sched_process_exec`.
pub const CFG_EXEC_OLD_PID_OFF: u32 = 2;
/// Offset of `pid_t child_pid` in `sched:sched_process_fork`.
pub const CFG_FORK_CHILD_PID_OFF: u32 = 3;
pub const CFG_LEN: u32 = 4;

/// Per-CPU counter indexes in the `STATS` map.
pub const STAT_DROPPED: u32 = 0;
pub const STAT_LEN: u32 = 1;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Header {
    pub kind: u32,
    /// Process id (thread group id).
    pub tgid: u32,
    /// Thread id.
    pub tid: u32,
    /// Real uid.
    pub uid: u32,
    /// `bpf_ktime_get_ns()`: CLOCK_MONOTONIC nanoseconds.
    pub ts_ns: u64,
    pub cgroup_id: u64,
    pub comm: [u8; COMM_LEN],
}

/// `syscalls:sys_enter_execve`. Emitted before the exec succeeds; userspace keeps it
/// only if a matching [`Exec`] (same tid as `Exec::old_pid`) follows.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExecArgs {
    pub hdr: Header,
    pub argc: u32,
    pub _pad: u32,
    pub argv: [[u8; ARG_LEN]; ARGV_MAX],
}

/// `sched:sched_process_exec`: a successful exec.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Exec {
    pub hdr: Header,
    pub old_pid: u32,
    pub _pad: u32,
    pub filename: [u8; PATH_LEN],
}

/// `sched:sched_process_fork`. The header describes the parent.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Fork {
    pub hdr: Header,
    pub child_pid: u32,
    pub _pad: u32,
}

/// `sched:sched_process_exit`, emitted only for the thread group leader.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Exit {
    pub hdr: Header,
}

/// `syscalls:sys_enter_openat`, after the in-kernel noise filter.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Open {
    pub hdr: Header,
    pub flags: i32,
    pub dfd: i32,
    pub filename: [u8; PATH_LEN],
}

/// `syscalls:sys_enter_connect` or `sys_enter_sendto` with a destination, IPv4/IPv6 only.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Net {
    pub hdr: Header,
    pub op: u32,
    pub family: u16,
    /// Host byte order.
    pub port: u16,
    /// IPv4 uses the first 4 bytes.
    pub addr: [u8; 16],
}
