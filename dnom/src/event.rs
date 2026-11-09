//! JSON-lines event format: what `dnom collect` prints and `dnom classify` reads.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    /// Unix time in milliseconds.
    pub ts_ms: u64,
    /// Process id (tgid).
    pub pid: u32,
    pub tid: u32,
    pub uid: u32,
    pub comm: String,
    pub cgroup: u64,
    /// Container the process runs in, when the source knows it (Falco). None for processes on
    /// the host itself, and for `dnom collect`, which doesn't map cgroups to containers yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container: Option<Container>,
    #[serde(flatten)]
    pub data: Data,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Container {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// `repository:tag`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    /// Kubernetes pod and namespace, when the container runs in a pod.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pod: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Data {
    /// Successful exec. `argv` is capped at 8 args of 63 bytes each.
    Exec {
        exe: String,
        argv: Vec<String>,
    },
    /// `pid` forked `child`. `child` may be a thread id; it only matters if it later shows up as a pid.
    Fork {
        child: u32,
    },
    Exit {},
    Open {
        path: String,
        flags: i32,
        write: bool,
    },
    Net {
        /// `connect` or `sendto`.
        op: String,
        /// `ip:port`, IPv6 as `[ip]:port`.
        dest: String,
    },
}
