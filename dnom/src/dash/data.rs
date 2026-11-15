//! What `dnom dash` shows: the assessment log folded into one entry per episode, the filters
//! over them, and which of an episode's processes are still running on this machine.

use std::{
    collections::{BTreeMap, HashMap},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use serde_json::Value;

use crate::{
    assess::Answer,
    audit::{self, Tail},
    driver::{Driver, DriverConfig, Kind},
    policy::Condition,
    questions::{AssessmentConfig, QuestionType},
};

/// In the order of the filter keys 1 to 5.
pub const KINDS: [Kind; 5] = [Kind::Agent, Kind::Remote, Kind::Human, Kind::Automation, Kind::Unknown];

pub fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// One episode: its last record in the log, and what the list and the filters need from it.
pub struct Episode {
    /// Stable for as long as the dashboard runs; the selection holds on to it.
    pub key: u64,
    pub id: String,
    /// The last record. Its `episode.driver` is filled in when the record had none.
    pub record: Value,
    pub answers: Option<BTreeMap<String, Answer>>,
    /// Position of that record in the log: the newest record has the highest.
    pub seq: u64,
    /// When the episode was last active (the end of its window).
    pub at_ms: u64,
    /// How many records the log holds for this episode (it is assessed again when it grows).
    pub assessed: u32,
    pub command: String,
    pub driver: Driver,
    pub rules: Vec<String>,
    /// The model's pick for what to do (`ignore`, `watch`, ...), when it was asked.
    pub response: Option<String>,
    /// The answer that stands out most, if one does: (question, probability).
    pub top: Option<(String, f64)>,
    /// For "highest risk first": a matched rule counts 1, plus the strongest answer.
    pub risk: f64,
    /// Everything the text search looks at, in lower case.
    haystack: String,
    /// Each process of the tree, to look it up in /proc.
    pids: Vec<Seen>,
    /// The processes of this episode that run right now on this machine.
    pub alive: Vec<u32>,
    /// Counts up when `alive` changes.
    pub alive_version: u64,
    /// Nothing runs and nothing will: not checked again.
    settled: bool,
}

impl Episode {
    pub fn flagged(&self) -> bool {
        !self.rules.is_empty()
    }

    pub fn ep(&self) -> &Value {
        &self.record["episode"]
    }
}

/// A process as the log knows it.
#[derive(Debug, Clone, PartialEq)]
pub struct Seen {
    pub pid: u32,
    /// The earliest time the log has for it.
    pub first_ms: u64,
    /// The program it ran last, by name: `curl` for `/usr/bin/curl`.
    pub program: String,
    /// The first word of its last command line, by name.
    pub arg0: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Sort {
    #[default]
    Newest,
    Risk,
}

impl Sort {
    pub fn next(self) -> Self {
        match self {
            Sort::Newest => Sort::Risk,
            Sort::Risk => Sort::Newest,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Sort::Newest => "newest first",
            Sort::Risk => "highest risk first",
        }
    }
}

/// How far back the list goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Since {
    #[default]
    All,
    Minutes(u64),
}

impl Since {
    const STEPS: [Since; 4] = [Since::All, Since::Minutes(15), Since::Minutes(60), Since::Minutes(24 * 60)];

    pub fn next(self) -> Self {
        let at = Self::STEPS.iter().position(|s| *s == self).unwrap_or(0);
        Self::STEPS[(at + 1) % Self::STEPS.len()]
    }

    pub fn label(self) -> &'static str {
        match self {
            Since::All => "all time",
            Since::Minutes(15) => "last 15 min",
            Since::Minutes(60) => "last hour",
            Since::Minutes(_) => "last 24 h",
        }
    }
}

/// All of them must hold for an episode to be listed.
#[derive(Default)]
pub struct Filters {
    /// Only episodes a rule matched.
    pub flagged: bool,
    /// Only these drivers, in the order of `KINDS`. None on means all.
    pub who: [bool; 5],
    pub since: Since,
    /// Words that must all appear (in the command, a path, an address, a rule name, ...).
    pub search: String,
    /// A condition in the policy language, as typed and as parsed.
    pub condition: Option<(String, Condition)>,
}

impl Filters {
    pub fn active(&self) -> usize {
        usize::from(self.flagged)
            + usize::from(self.who.contains(&true))
            + usize::from(self.since != Since::All)
            + usize::from(!self.search.trim().is_empty())
            + usize::from(self.condition.is_some())
    }

    pub fn clear(&mut self) {
        *self = Self::default();
    }
}

/// How many episodes each filter chip would show, given the other filters.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Facets {
    pub flagged: usize,
    pub by_kind: [usize; 5],
}

/// What a read of the log brought.
#[derive(Debug, Default)]
pub struct Arrived {
    /// Episodes seen for the first time.
    pub episodes: usize,
    /// Episodes that got a newer record.
    pub updated: usize,
    /// (episode, rule) for each rule that matched an episode for the first time.
    pub threats: Vec<(u64, String)>,
}

impl Arrived {
    pub fn any(&self) -> bool {
        self.episodes + self.updated > 0
    }
}

/// The log on disk, read from where the last read stopped.
pub struct Feed {
    pub path: PathBuf,
    tail: Tail,
    /// The log file is there.
    pub exists: bool,
    pub error: Option<String>,
    size: u64,
}

impl Feed {
    pub fn new(path: PathBuf) -> Self {
        Self { tail: Tail::new(path.clone()), path, exists: false, error: None, size: 0 }
    }

    pub fn pull(&mut self, store: &mut Store) -> Arrived {
        let mut arrived = Arrived::default();
        let size = std::fs::metadata(&self.path).map(|m| m.len()).unwrap_or(0);
        if size < self.size {
            // A new log took the place of the old one: start over with it.
            store.clear();
        }
        self.size = size;
        match self.tail.each_new(|record| store.fold(record, &mut arrived)) {
            Ok(exists) => {
                self.exists = exists;
                self.error = None;
            }
            Err(e) => self.error = Some(format!("{e:#}")),
        }
        arrived
    }
}

/// Every episode of the log, by its last record.
pub struct Store {
    drivers: DriverConfig,
    pub assessment: AssessmentConfig,
    episodes: HashMap<u64, Episode>,
    by_id: HashMap<String, u64>,
    next_key: u64,
    seq: u64,
    /// At most this many episodes are kept; the oldest go first.
    cap: usize,
    /// Episodes dropped because of `cap`.
    pub dropped: u64,
    /// Records in the log.
    pub records: u64,
    /// Records a model answered.
    pub model_calls: u64,
    pub tokens: u64,
    latencies: Vec<u32>,
    /// The model that answered last.
    pub model: String,
    /// (time of the episode, a rule matched) of every record, for the activity chart.
    activity: Vec<(u64, bool)>,
    /// When the latest episode was active.
    pub last_ms: Option<u64>,
    /// When the earliest episode was active.
    pub first_ms: Option<u64>,
}

impl Store {
    pub fn new(cap: usize) -> Self {
        Self {
            drivers: DriverConfig::default(),
            assessment: AssessmentConfig::default(),
            episodes: HashMap::new(),
            by_id: HashMap::new(),
            next_key: 0,
            seq: 0,
            cap: cap.max(1),
            dropped: 0,
            records: 0,
            model_calls: 0,
            tokens: 0,
            latencies: Vec::new(),
            model: String::new(),
            activity: Vec::new(),
            last_ms: None,
            first_ms: None,
        }
    }

    fn clear(&mut self) {
        let (cap, next_key) = (self.cap, self.next_key);
        *self = Self::new(cap);
        // Keys are never reused, so a selection made before cannot point at a new episode.
        self.next_key = next_key;
    }

    pub fn len(&self) -> usize {
        self.episodes.len()
    }

    pub fn get(&self, key: u64) -> Option<&Episode> {
        self.episodes.get(&key)
    }

    pub fn all(&self) -> impl Iterator<Item = &Episode> {
        self.episodes.values()
    }

    pub fn median_latency_ms(&self) -> Option<u32> {
        let mut sorted = self.latencies.clone();
        sorted.sort_unstable();
        sorted.get(sorted.len() / 2).copied().filter(|_| !sorted.is_empty())
    }

    /// Takes one record of the log.
    pub fn fold(&mut self, mut record: Value, arrived: &mut Arrived) {
        let Some(id) = record["episode_id"].as_str().map(String::from) else { return };
        self.seq += 1;
        self.records += 1;
        // When it happened, not when it was assessed: a recording or a server's events are
        // classified later, all at once.
        let at_ms = audit::rfc3339_ms(&record["episode"]["window"]["end"]).or_else(|| audit::record_ms(&record)).unwrap_or(0);
        let rules: Vec<String> = audit::rules_of(&record).into_iter().map(String::from).collect();
        self.activity.push((at_ms, !rules.is_empty()));
        if at_ms > 0 {
            self.last_ms = Some(self.last_ms.map_or(at_ms, |t| t.max(at_ms)));
            self.first_ms = Some(self.first_ms.map_or(at_ms, |t| t.min(at_ms)));
        }

        let answers = serde_json::from_value::<BTreeMap<String, Answer>>(record["answers"].clone()).ok().filter(|a| !a.is_empty());
        if answers.is_some() {
            self.model_calls += 1;
            self.tokens += record["input_tokens"].as_u64().unwrap_or(0);
            if let Some(ms) = record["latency_ms"].as_u64() {
                self.latencies.push(ms.min(u32::MAX as u64) as u32);
            }
            if let Some(model) = record["model"].as_str() {
                model.clone_into(&mut self.model);
            }
        }

        let driver = self.drivers.of_record(&record["episode"]);
        if record["episode"].is_object() && record["episode"].get("driver").is_none() {
            record["episode"]["driver"] = driver.to_json();
        }
        let ep = &record["episode"];
        let command = ep["root"]["argv"].as_str().filter(|a| !a.is_empty()).or(ep["root"]["exe"].as_str()).unwrap_or("?").to_string();
        let (top, strongest) = standing_out(&self.assessment, answers.as_ref());
        let response = answers.as_ref().and_then(|a| match a.get("response") {
            Some(Answer::Choice { choice, .. }) => Some(choice.clone()),
            _ => a.values().find_map(|answer| match answer {
                Answer::Choice { choice, .. } => Some(choice.clone()),
                _ => None,
            }),
        });
        let mut pids: Vec<Seen> = Vec::new();
        let name = |path: &str| path.rsplit('/').next().unwrap_or(path).to_string();
        for entry in ep["tree"].as_array().into_iter().flatten() {
            let (Some(pid), Some(ts)) = (entry["pid"].as_u64(), entry["ts_ms"].as_u64()) else { continue };
            let program = name(entry["exe"].as_str().unwrap_or(""));
            let arg0 = name(entry["argv"].as_str().unwrap_or("").split(' ').next().unwrap_or(""));
            match pids.iter_mut().find(|seen| seen.pid as u64 == pid) {
                // The same process ran another program: that is what it is now.
                Some(seen) => (seen.program, seen.arg0) = (program, arg0),
                None => pids.push(Seen { pid: pid as u32, first_ms: ts, program, arg0 }),
            }
        }
        let fresh = Episode {
            key: 0,
            haystack: haystack(&id, &command, &driver, &rules, ep),
            id: id.clone(),
            answers,
            seq: self.seq,
            at_ms,
            assessed: 1,
            command,
            driver,
            risk: if rules.is_empty() { 0.0 } else { 1.0 } + strongest,
            rules,
            response,
            top,
            pids,
            alive: Vec::new(),
            alive_version: 0,
            settled: false,
            record,
        };

        match self.by_id.get(&id).and_then(|key| self.episodes.get_mut(key)) {
            Some(known) => {
                for rule in fresh.rules.iter().filter(|r| !known.rules.contains(r)) {
                    arrived.threats.push((known.key, rule.clone()));
                }
                arrived.updated += 1;
                // What is known about its running processes stays until the next check.
                let keep = (known.key, known.assessed + 1, std::mem::take(&mut known.alive), known.alive_version);
                *known = fresh;
                (known.key, known.assessed, known.alive, known.alive_version) = keep;
            }
            None => {
                let key = self.next_key;
                self.next_key += 1;
                arrived.episodes += 1;
                arrived.threats.extend(fresh.rules.iter().map(|rule| (key, rule.clone())));
                self.by_id.insert(id, key);
                self.episodes.insert(key, Episode { key, ..fresh });
                if self.episodes.len() > self.cap
                    && let Some(oldest) = self.episodes.values().min_by_key(|e| e.seq).map(|e| e.key)
                    && let Some(gone) = self.episodes.remove(&oldest)
                {
                    self.by_id.remove(&gone.id);
                    self.dropped += 1;
                }
            }
        }
    }

    /// The episodes the filters let through, in display order, and the count behind each chip.
    pub fn view(&self, filters: &Filters, sort: Sort, now_ms: u64) -> (Vec<u64>, Facets) {
        let words: Vec<String> = filters.search.to_lowercase().split_whitespace().map(String::from).collect();
        let earliest = match filters.since {
            Since::All => 0,
            Since::Minutes(m) => now_ms.saturating_sub(m * 60_000),
        };
        let any_who = filters.who.contains(&true);
        let mut facets = Facets::default();
        let mut shown: Vec<&Episode> = Vec::new();
        for ep in self.episodes.values() {
            let base = ep.at_ms >= earliest
                && words.iter().all(|w| ep.haystack.contains(w.as_str()))
                && filters.condition.as_ref().is_none_or(|(_, c)| c.holds(ep.ep(), ep.answers.as_ref()));
            if !base {
                continue;
            }
            let kind = KINDS.iter().position(|k| *k == ep.driver.kind).unwrap_or(4);
            let who_ok = !any_who || filters.who[kind];
            let flag_ok = !filters.flagged || ep.flagged();
            if flag_ok {
                facets.by_kind[kind] += 1;
            }
            if who_ok && ep.flagged() {
                facets.flagged += 1;
            }
            if who_ok && flag_ok {
                shown.push(ep);
            }
        }
        match sort {
            Sort::Newest => shown.sort_by_key(|e| std::cmp::Reverse(e.seq)),
            Sort::Risk => shown.sort_by(|a, b| b.risk.total_cmp(&a.risk).then(b.seq.cmp(&a.seq))),
        }
        (shown.iter().map(|e| e.key).collect(), facets)
    }

    /// Records per slice of time between `from_ms` and `to_ms`: (how many, a rule matched).
    pub fn chart(&self, from_ms: u64, to_ms: u64, slices: usize) -> Vec<(u32, bool)> {
        let mut out = vec![(0u32, false); slices];
        let span = to_ms.saturating_sub(from_ms).max(1);
        for &(at, flagged) in &self.activity {
            if at < from_ms || at > to_ms || slices == 0 {
                continue;
            }
            let i = (((at - from_ms) as u128 * slices as u128) / span as u128).min(slices as u128 - 1) as usize;
            out[i].0 += 1;
            out[i].1 |= flagged;
        }
        out
    }

    /// Looks up which processes of each episode run now. True when something changed.
    ///
    /// A process that runs for hours (an agent, a daemon) is in many episodes, one for each
    /// burst of activity. It counts as running in the newest of them only: the older ones
    /// are over, even though the process is not.
    pub fn refresh_alive(&mut self, procs: &Procs, now_ms: u64) -> bool {
        let mut found: Vec<(u64, Vec<u32>)> = Vec::new();
        let mut newest: HashMap<u32, u64> = HashMap::new();
        for ep in self.episodes.values().filter(|e| !e.settled) {
            let alive: Vec<u32> = ep.pids.iter().filter(|seen| procs.alive(seen)).map(|seen| seen.pid).collect();
            for pid in &alive {
                let seq = newest.entry(*pid).or_insert(ep.seq);
                *seq = (*seq).max(ep.seq);
            }
            found.push((ep.key, alive));
        }
        let mut changed = false;
        for (key, mut alive) in found {
            let Some(ep) = self.episodes.get_mut(&key) else { continue };
            alive.retain(|pid| newest.get(pid) == Some(&ep.seq));
            if alive != ep.alive {
                ep.alive = alive;
                ep.alive_version += 1;
                changed = true;
            }
            // What ended does not come back; a newer record makes a new entry that is checked again.
            ep.settled = ep.alive.is_empty() && now_ms.saturating_sub(ep.at_ms) > 60_000;
        }
        changed
    }
}

/// The answer that stands out most (if any passes its question's threshold), and the strongest
/// sign of trouble among all yes/no answers as a number from 0 to 1.
fn standing_out(assessment: &AssessmentConfig, answers: Option<&BTreeMap<String, Answer>>) -> (Option<(String, f64)>, f64) {
    let mut top: Option<(String, f64, f64)> = None;
    let mut strongest = 0.0f64;
    for (id, answer) in answers.into_iter().flatten() {
        let Answer::Noul { noul: p } = answer else { continue };
        let question = assessment.questions.iter().find(|q| q.id == *id && q.kind == QuestionType::Noul);
        // "Is this normal here?" counts the other way round.
        let trouble = if question.is_some_and(|q| q.highlight_below.is_some()) { 1.0 - p } else { *p };
        strongest = strongest.max(trouble);
        if question.is_some_and(|q| q.highlighted(*p)) && top.as_ref().is_none_or(|(_, _, t)| trouble > *t) {
            top = Some((id.clone(), *p, trouble));
        }
    }
    (top.map(|(id, p, _)| (id, p)), strongest)
}

fn haystack(id: &str, command: &str, driver: &Driver, rules: &[String], ep: &Value) -> String {
    let mut parts: Vec<&str> = vec![id, command, driver.kind.name(), &driver.by];
    parts.extend(rules.iter().map(String::as_str));
    parts.extend(ep["flags"].as_array().into_iter().flatten().filter_map(|f| f.as_str()));
    parts.extend(ep["root"]["exe"].as_str());
    parts.extend(ep["root"]["started_by"].as_str());
    for entry in ep["tree"].as_array().into_iter().flatten() {
        parts.extend(entry["argv"].as_str());
        parts.extend(entry["exe"].as_str());
    }
    for step in ep["trail"].as_array().into_iter().flatten() {
        parts.extend(step["path"].as_str());
        parts.extend(step["dest"].as_str());
    }
    for list in ep["files"].as_object().into_iter().flatten().map(|(_, list)| list) {
        parts.extend(list.as_array().into_iter().flatten().filter_map(|f| f.as_str()));
    }
    parts.extend(ep["network"].as_array().into_iter().flatten().filter_map(|n| n["dest"].as_str()));
    parts.extend(ep["container"].as_object().into_iter().flatten().filter_map(|(_, v)| v.as_str()));
    parts.join("\n").to_lowercase()
}

/// Looks up processes in /proc. A process id alone says little: it is used again by later,
/// unrelated programs, and in a log copied from another machine it means nothing here. So a
/// process counts as the one from the log only when it was already running at the time the
/// log has for it (then, on this machine, it is the same process) and it runs the same program.
pub struct Procs {
    dir: PathBuf,
    /// When this machine booted, as Unix time.
    boot_ms: f64,
    /// Length of one clock tick of /proc/<pid>/stat.
    tick_ms: f64,
}

impl Procs {
    pub fn now() -> Self {
        let clock = |id| {
            let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
            unsafe { libc::clock_gettime(id, &mut ts) };
            ts.tv_sec as f64 * 1000.0 + ts.tv_nsec as f64 / 1e6
        };
        let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
        Self {
            dir: PathBuf::from("/proc"),
            boot_ms: clock(libc::CLOCK_REALTIME) - clock(libc::CLOCK_BOOTTIME),
            tick_ms: 1000.0 / if hz > 0 { hz as f64 } else { 100.0 },
        }
    }

    #[cfg(test)]
    fn fake(dir: &Path, boot_ms: f64) -> Self {
        Self { dir: dir.to_path_buf(), boot_ms, tick_ms: 10.0 }
    }

    /// Whether the process the log saw is still there.
    pub fn alive(&self, seen: &Seen) -> bool {
        let dir = self.dir.join(seen.pid.to_string());
        let Ok(stat) = std::fs::read_to_string(dir.join("stat")) else { return false };
        let Some((comm, state, start_ticks)) = parse_stat(&stat) else { return false };
        if matches!(state, 'Z' | 'X') {
            return false;
        }
        // Started after the log saw this id: a later process that got the same id. The two
        // seconds allow for clocks that are read a moment apart.
        let (started_ms, first_ms) = (self.boot_ms + start_ticks as f64 * self.tick_ms, seen.first_ms as f64);
        if started_ms > first_ms + 2_000.0 || first_ms < self.boot_ms - 2_000.0 {
            return false;
        }
        // The same program: by the name the kernel keeps (15 characters of it), by the first
        // word of its command line, or by its executable. One of them is enough: a program
        // can rename itself (sshd-session does), and a link can point at another file name.
        let named = |name: &str| !name.is_empty() && (name == seen.program || name == seen.arg0);
        let short = |name: &str| name.chars().take(15).collect::<String>();
        if !comm.is_empty() && (comm == short(&seen.program) || comm == short(&seen.arg0)) {
            return true;
        }
        let base = |path: &str| path.rsplit('/').next().unwrap_or(path).trim_end_matches(" (deleted)").to_string();
        if let Ok(cmdline) = std::fs::read(dir.join("cmdline"))
            && let Some(first) = cmdline.split(|b| *b == 0).next()
            && named(&base(&String::from_utf8_lossy(first)))
        {
            return true;
        }
        std::fs::read_link(dir.join("exe")).is_ok_and(|exe| named(&base(&exe.to_string_lossy())))
    }
}

/// Program name, state and start time (in clock ticks since boot) from /proc/<pid>/stat. The
/// name can hold spaces and brackets, so the other fields are counted from its closing bracket.
fn parse_stat(stat: &str) -> Option<(&str, char, u64)> {
    let (open, close) = (stat.find('(')?, stat.rfind(')')?);
    let mut fields = stat[close + 1..].split_ascii_whitespace();
    let state = fields.next()?.chars().next()?;
    // The start time is field 22 of the line; the state was field 3.
    Some((stat.get(open + 1..close)?, state, fields.nth(18)?.parse().ok()?))
}

/// A folder as the user would type it: `~/…` under the home directory.
pub fn tilde(path: &Path) -> String {
    let text = path.display().to_string();
    match std::env::var("HOME") {
        Ok(home) if !home.is_empty() && text.starts_with(&home) => format!("~{}", &text[home.len()..]),
        _ => text,
    }
}

#[cfg(test)]
pub mod tests {
    use serde_json::json;

    use super::*;

    /// A record as `dnom classify` writes it. `secs` is seconds after 2026-11-14 12:00:00 UTC.
    pub fn record(id: &str, secs: u64, command: &str, parent: &str, rules: &[&str], scores: Option<(f64, f64)>) -> Value {
        let at = 1_794_657_600_000 + secs * 1000;
        let ts = humantime::format_rfc3339_seconds(UNIX_EPOCH + std::time::Duration::from_millis(at)).to_string();
        let exe = format!("/usr/bin/{}", command.split(' ').next().unwrap_or("x"));
        let answers = match scores {
            Some((credential_access, fits_baseline)) => json!({
                "credential_access": { "type": "noul", "noul": credential_access },
                "fits_baseline": { "type": "noul", "noul": fits_baseline },
                "response": { "type": "choice", "choice": if credential_access > 0.8 { "alert" } else { "ignore" }, "confidence": 0.6,
                              "probabilities": { "ignore": 0.2, "watch": 0.2, "alert": 0.6, "contain": 0.0 } },
            }),
            None => json!({}),
        };
        json!({
            "ts": ts,
            "episode_id": id,
            "backend": if scores.is_some() { "jev" } else { "none" },
            "model": "jev-test",
            "latency_ms": 100 + secs,
            "input_tokens": 1000,
            "answers": answers,
            "policy": rules.iter().map(|r| json!({ "rule": r, "actions": ["alert"], "dry_run": true, "protected": false, "values": { "files.credentials": "1" } })).collect::<Vec<_>>(),
            "episode": {
                "window": { "start": ts, "end": ts },
                "root": { "exe": exe, "argv": command, "uid": 1000, "started_by": parent },
                "flags": ["new_destination"],
                "files": { "credentials": ["~/.ssh/id_ed25519"] },
                "network": [{ "dest": "203.0.113.7:443", "by": "curl", "new_destination": true }],
                "tree": [
                    { "pid": 100 + secs, "ppid": 1, "ts_ms": at, "exe": exe, "argv": command, "parent": parent },
                    { "pid": 200 + secs, "ppid": 100 + secs, "ts_ms": at + 5, "exe": "/usr/bin/curl", "argv": "curl https://203.0.113.7/", "parent": "x" },
                ],
                "trail": [
                    { "ts_ms": at + 1, "pid": 100 + secs, "event": "open", "path": "~/.ssh/id_ed25519", "category": "credentials", "write": false },
                    { "ts_ms": at + 6, "pid": 200 + secs, "event": "net", "dest": "203.0.113.7:443", "new_destination": true },
                ],
            },
        })
    }

    pub const NOON_MS: u64 = 1_794_657_600_000;

    pub fn store(records: Vec<Value>) -> Store {
        let mut store = Store::new(1000);
        let mut arrived = Arrived::default();
        for r in records {
            store.fold(r, &mut arrived);
        }
        store
    }

    /// Four episodes: a planted theft from a terminal, an agent, a cron job, an SSH session.
    pub fn sample() -> Store {
        store(vec![
            record("ep-1", 10, "bash -i", "foot", &["credential-theft", "exfiltration"], Some((0.95, 0.1))),
            record("ep-2", 20, "claude --resume", "bash", &[], Some((0.3, 0.9))),
            record("ep-3", 30, "backup.sh --nightly", "cron", &[], None),
            record("ep-4", 40, "sshd-session: deploy", "sshd", &["credentials-then-new-destination"], Some((0.75, 0.5))),
        ])
    }

    fn ids(store: &Store, keys: &[u64]) -> Vec<String> {
        keys.iter().map(|k| store.get(*k).unwrap().id.clone()).collect()
    }

    fn shown(store: &Store, filters: &Filters, sort: Sort) -> Vec<String> {
        ids(store, &store.view(filters, sort, NOON_MS + 3_600_000).0)
    }

    #[test]
    fn the_log_folds_into_one_entry_per_episode_newest_first() {
        let mut store = sample();
        assert_eq!(shown(&store, &Filters::default(), Sort::Newest), ["ep-4", "ep-3", "ep-2", "ep-1"]);
        assert_eq!(store.get(0).unwrap().driver.kind, Kind::Human);
        assert_eq!(store.get(1).unwrap().driver.kind, Kind::Agent);
        assert_eq!(store.get(2).unwrap().driver.kind, Kind::Automation);
        assert_eq!(store.get(3).unwrap().driver.kind, Kind::Remote);

        // A newer record of a known episode replaces it, moves it up and reports only the new rule.
        let mut arrived = Arrived::default();
        store.fold(record("ep-2", 50, "claude --resume", "bash", &["exfiltration"], Some((0.9, 0.2))), &mut arrived);
        store.fold(record("ep-1", 55, "bash -i", "foot", &["credential-theft", "exfiltration"], Some((0.95, 0.1))), &mut arrived);
        assert_eq!((arrived.episodes, arrived.updated), (0, 2));
        assert_eq!(arrived.threats, [(1, "exfiltration".to_string())]);
        assert_eq!(shown(&store, &Filters::default(), Sort::Newest), ["ep-1", "ep-2", "ep-4", "ep-3"]);
        assert_eq!((store.len(), store.records, store.get(1).unwrap().assessed), (4, 6, 2));
        assert_eq!((store.model_calls, store.tokens, store.median_latency_ms()), (5, 5000, Some(140)));
    }

    #[test]
    fn filters_combine_and_each_chip_counts_what_it_would_show() {
        let store = sample();
        let mut f = Filters { flagged: true, ..Filters::default() };
        assert_eq!(shown(&store, &f, Sort::Newest), ["ep-4", "ep-1"]);
        let (_, facets) = store.view(&f, Sort::Newest, NOON_MS);
        // With "flagged" on, the driver chips count flagged episodes only.
        assert_eq!((facets.flagged, facets.by_kind), (2, [0, 1, 1, 0, 0]));

        f.who[1] = true;
        assert_eq!(shown(&store, &f, Sort::Newest), ["ep-4"]);
        let (_, facets) = store.view(&f, Sort::Newest, NOON_MS);
        assert_eq!((facets.flagged, facets.by_kind), (1, [0, 1, 1, 0, 0]));
        f.who[2] = true;
        assert_eq!(shown(&store, &f, Sort::Newest), ["ep-4", "ep-1"]);
        assert_eq!(f.active(), 2);
        f.clear();
        assert_eq!((f.active(), shown(&store, &f, Sort::Newest).len()), (0, 4));
    }

    #[test]
    fn search_needs_every_word_and_looks_inside_the_episode() {
        let store = sample();
        let search = |text: &str| shown(&store, &Filters { search: text.into(), ..Filters::default() }, Sort::Newest);
        assert_eq!(search("BACKUP"), ["ep-3"]);
        assert_eq!(search("id_ed25519 claude"), ["ep-2"]);
        assert_eq!(search("203.0.113.7").len(), 4);
        assert_eq!(search("credential-theft"), ["ep-1"]);
        assert_eq!(search("remote"), ["ep-4"]);
        assert!(search("no-such-thing").is_empty());
    }

    #[test]
    fn a_policy_condition_filters_stored_episodes() {
        let store = sample();
        let with = |text: &str| {
            let condition = Condition::parse(text, &store.assessment).unwrap();
            shown(&store, &Filters { condition: Some((text.into(), condition)), ..Filters::default() }, Sort::Newest)
        };
        assert_eq!(with(r#"driver == "agent""#), ["ep-2"]);
        assert_eq!(with("credential_access >= 0.7 and net.new > 0"), ["ep-4", "ep-1"]);
        // An episode no model answered has no value for the question: it does not match.
        assert_eq!(with("credential_access < 2"), ["ep-4", "ep-2", "ep-1"]);
        assert_eq!(with(r#"response == "alert" or driver == "automation""#), ["ep-3", "ep-1"]);
        assert!(Condition::parse(r#"driver == "robot""#, &store.assessment).is_err());
        assert!(Condition::parse("no_such_field > 1", &store.assessment).is_err());
    }

    #[test]
    fn time_filter_and_risk_order() {
        let store = sample();
        let f = Filters { since: Since::Minutes(15), ..Filters::default() };
        // 15 minutes before 12:15:25 is 12:00:25: the first two episodes are older.
        assert_eq!(ids(&store, &store.view(&f, Sort::Newest, NOON_MS + 925_000).0), ["ep-4", "ep-3"]);
        assert_eq!(Since::All.next().next().next().next(), Since::All);

        // Matched rules first, then the strongest answer; no model answer sorts last.
        assert_eq!(shown(&store, &Filters::default(), Sort::Risk), ["ep-1", "ep-4", "ep-2", "ep-3"]);
        let top = |key| store.get(key).unwrap().top.clone();
        assert_eq!(top(0), Some(("credential_access".into(), 0.95)));
        assert_eq!(top(1), None);
        assert_eq!(top(3), Some(("credential_access".into(), 0.75)));
        assert_eq!(store.get(0).unwrap().response.as_deref(), Some("alert"));
    }

    #[test]
    fn the_oldest_episodes_go_when_the_cap_is_reached() {
        let mut store = Store::new(2);
        let mut arrived = Arrived::default();
        for (i, id) in ["a", "b", "c"].iter().enumerate() {
            store.fold(record(id, i as u64, "true", "cron", &[], None), &mut arrived);
        }
        assert_eq!((store.len(), store.dropped, store.records), (2, 1, 3));
        assert_eq!(shown(&store, &Filters::default(), Sort::Newest), ["c", "b"]);
        // The dropped one is new again if it comes back.
        store.fold(record("a", 9, "true", "cron", &[], None), &mut arrived);
        assert_eq!(shown(&store, &Filters::default(), Sort::Newest), ["a", "c"]);
    }

    #[test]
    fn the_chart_counts_records_per_slice_and_marks_matched_rules() {
        let store = sample();
        let chart = store.chart(NOON_MS, NOON_MS + 40_000, 4);
        assert_eq!(chart, [(0, false), (1, true), (1, false), (2, true)]);
        assert_eq!(store.chart(NOON_MS + 100_000, NOON_MS + 200_000, 3), [(0, false); 3]);
        assert!(store.chart(0, 0, 0).is_empty());
    }

    #[test]
    fn stat_line_gives_name_state_and_start_time() {
        let line = "4242 (tmux: server) S 1 4242 4242 0 -1 4194560 100 0 0 0 5 3 0 0 20 0 1 0 987654 12345 678 18446744073709551615 1 1 0 0 0 0 0 0 0 0 0 0 17 3 0 0 0 0 0";
        assert_eq!(parse_stat(line), Some(("tmux: server", 'S', 987654)));
        // A program can name itself anything, brackets included.
        let odd = "7 (a) b) (c) Z 1 7 7 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 55 0 0";
        assert_eq!(parse_stat(odd), Some(("a) b) (c", 'Z', 55)));
        assert_eq!(parse_stat("garbage"), None);
    }

    #[test]
    fn a_process_is_alive_only_if_it_is_the_one_the_log_saw() {
        let dir = std::env::temp_dir().join(format!("dnom-dash-proc-{}", std::process::id()));
        let stat = |pid: u32, comm: &str, state: char, ticks: u64, cmdline: &str| {
            std::fs::create_dir_all(dir.join(pid.to_string())).unwrap();
            let line = format!("{pid} ({comm}) {state} 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 {ticks} 0 0");
            std::fs::write(dir.join(pid.to_string()).join("stat"), line).unwrap();
            std::fs::write(dir.join(pid.to_string()).join("cmdline"), cmdline.replace(' ', "\0")).unwrap();
        };
        // Boot at 10,000,000 ms; ticks of 10 ms. Processes 5 to 8 started at 10,050,000 ms.
        stat(5, "claude", 'S', 5_000, "claude --resume");
        stat(6, "claude", 'Z', 5_000, "claude --resume");
        stat(7, "MainThread", 'S', 5_000, "/opt/node/bin/node server.js");
        stat(8, "sshd-session", 'S', 5_000, "sshd-session: deploy [priv]");
        let procs = Procs::fake(&dir, 10_000_000.0);
        let seen = |pid: u32, first_ms: u64, program: &str, arg0: &str| Seen { pid, first_ms, program: program.into(), arg0: arg0.into() };

        assert!(procs.alive(&seen(5, 10_050_020, "claude", "claude")));
        // A long-running process shows up in the log again hours after it started: still it.
        assert!(procs.alive(&seen(5, 10_050_000 + 3_600_000, "claude", "claude")));
        // The log saw this id before the process here started: the id was used again.
        assert!(!procs.alive(&seen(5, 10_050_000 - 3_600_000, "claude", "claude")));
        // Another program under the same id: a log from another machine.
        assert!(!procs.alive(&seen(5, 10_050_020, "sshd", "sshd")));
        // Older than this machine's last boot: not from here.
        assert!(!procs.alive(&seen(5, 9_000_000, "claude", "claude")));
        assert!(!procs.alive(&seen(6, 10_050_020, "claude", "claude")), "a zombie is not running");
        assert!(!procs.alive(&seen(9, 10_050_020, "claude", "claude")), "no such process");
        // The kernel's name differs (a thread name): the command line settles it.
        assert!(procs.alive(&seen(7, 10_050_020, "node", "node")));
        // The program renamed its command line: the kernel's name settles it.
        assert!(procs.alive(&seen(8, 10_050_020, "sshd-session", "sshd-session")));

        let mut store = sample();
        // The log is from another machine and another time: nothing of it runs here.
        assert!(!store.refresh_alive(&procs, NOON_MS + 120_000));
        assert!(store.all().all(|e| e.alive.is_empty() && e.settled));

        // A process that keeps running is in three episodes: only the newest counts as running.
        let long_lived = |id: &str, secs: u64| {
            let mut r = record(id, secs, "claude --resume", "desl", &[], None);
            r["episode"]["tree"] = json!([{ "pid": 5, "ppid": 1, "ts_ms": NOON_MS + secs * 1000, "exe": "/opt/claude", "argv": "claude --resume", "parent": "desl" }]);
            r
        };
        let mut store = self::store(vec![long_lived("a", 10), long_lived("b", 20), long_lived("c", 30)]);
        assert!(store.refresh_alive(&procs, NOON_MS + 31_000));
        let running: Vec<&str> = store.all().filter(|e| !e.alive.is_empty()).map(|e| e.id.as_str()).collect();
        assert_eq!(running, ["c"]);
        // The process ends: nothing runs any more.
        std::fs::remove_dir_all(dir.join("5")).unwrap();
        assert!(store.refresh_alive(&procs, NOON_MS + 32_000));
        assert!(store.all().all(|e| e.alive.is_empty()));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
