//! `dnom audit` and `dnom monitor`: the assessment log (`assessments.jsonl`, written by
//! `dnom classify`) shown to a person. Read-only; neither needs root or a model.
//!
//! - `dnom audit` lists the assessed episodes, `dnom audit <episode>` shows one in full:
//!   what matched, the process tree with what each process did and when, the model's answers.
//! - `dnom monitor` follows the log and prints that same report only for episodes a policy
//!   rule matched.
//!
//! `classify` reassesses an episode when it changes, so the log can hold several records per
//! episode; the last one is the whole episode.

use std::{
    collections::{BTreeSet, HashMap},
    fmt::Write as _,
    fs::File,
    io::{self, IsTerminal, Read, Seek, SeekFrom, Write as _},
    path::{Path, PathBuf},
    thread,
    time::{Duration, UNIX_EPOCH},
};

use anyhow::{Context as _, bail};
use clap::Args;
use serde_json::Value;

#[derive(Args)]
pub struct AuditArgs {
    /// Episode to show in full: an id from the list (or the start of one), or `last`.
    episode: Option<String>,
    /// Only episodes a policy rule matched.
    #[arg(long)]
    threats: bool,
    /// How many episodes to list (the most recent ones).
    #[arg(short = 'n', long, default_value_t = 20)]
    last: usize,
    /// Print the stored record as JSON instead of the readable view.
    #[arg(long)]
    json: bool,
    /// Directory holding assessments.jsonl (default ~/.local/state/dnom).
    #[arg(long)]
    state_dir: Option<PathBuf>,
}

#[derive(Args)]
pub struct MonitorArgs {
    /// Also show the last N threat reports already in the log.
    #[arg(short = 'n', long, default_value_t = 0)]
    last: usize,
    /// Directory holding assessments.jsonl (default ~/.local/state/dnom).
    #[arg(long)]
    state_dir: Option<PathBuf>,
}

pub fn audit(args: AuditArgs) -> anyhow::Result<()> {
    let path = log_path(args.state_dir.as_deref())?;
    let mut tail = Tail::new(path.clone());
    let records = latest(tail.read_new()?);
    let paint = Paint::auto();
    let mut out = io::stdout().lock();

    if let Some(wanted) = &args.episode {
        let record = find(&records, wanted, args.threats).with_context(|| format!("in {}", path.display()))?;
        if args.json {
            writeln!(out, "{}", serde_json::to_string_pretty(record)?)?;
        } else {
            write!(out, "{}", render(record, &paint))?;
        }
        return Ok(());
    }

    let shown: Vec<&Value> = records.iter().filter(|r| !args.threats || is_threat(r)).collect();
    if shown.is_empty() {
        let what = if args.threats { "episodes with matched rules" } else { "assessed episodes" };
        writeln!(out, "No {what} in {} yet.", path.display())?;
        return Ok(());
    }
    let recent = &shown[shown.len().saturating_sub(args.last)..];
    write!(out, "{}", render_list(recent, &paint, terminal_width()))?;
    let threats = records.iter().filter(|r| is_threat(r)).count();
    writeln!(
        out,
        "\n{} of {} episodes shown, {threats} with matched rules. One in full: dnom audit <episode>",
        recent.len(),
        records.len(),
    )?;
    Ok(())
}

pub fn monitor(args: MonitorArgs) -> anyhow::Result<()> {
    let path = log_path(args.state_dir.as_deref())?;
    let paint = Paint::auto();
    let mut tail = Tail::new(path.clone());
    let mut reported: HashMap<String, BTreeSet<String>> = HashMap::new();

    // What is already in the log is history: counted, and shown only if asked for.
    let existing = tail.read_new()?;
    for r in &existing {
        newly_matched(&mut reported, r);
    }
    let history = latest(existing);
    let threats: Vec<&Value> = history.iter().filter(|r| is_threat(r)).collect();
    eprintln!("dnom monitor: watching {} (threat reports only; Ctrl-C to stop)", path.display());
    eprintln!("dnom monitor: {} episodes in the log so far, {} with matched rules", history.len(), threats.len());
    let mut out = io::stdout().lock();
    for r in &threats[threats.len().saturating_sub(args.last)..] {
        write!(out, "{}", card(r, &[], &paint))?;
    }
    out.flush()?;

    loop {
        thread::sleep(Duration::from_millis(500));
        for r in tail.read_new()? {
            if let Some(new) = newly_matched(&mut reported, &r) {
                write!(out, "{}", card(&r, &new, &paint))?;
                out.flush()?;
            }
        }
    }
}

fn log_path(state_dir: Option<&Path>) -> anyhow::Result<PathBuf> {
    let dir = match state_dir {
        Some(d) => d.to_path_buf(),
        None => PathBuf::from(std::env::var("HOME").context("HOME not set")?).join(".local/state/dnom"),
    };
    Ok(dir.join("assessments.jsonl"))
}

/// Reads the log from where it stopped last time. Keeps a partly written last line for the
/// next call, and starts over if the file was truncated.
struct Tail {
    path: PathBuf,
    pos: u64,
    pending: Vec<u8>,
}

impl Tail {
    fn new(path: PathBuf) -> Self {
        Self { path, pos: 0, pending: Vec::new() }
    }

    fn read_new(&mut self) -> anyhow::Result<Vec<Value>> {
        let mut file = match File::open(&self.path) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e).with_context(|| format!("open {}", self.path.display())),
        };
        if file.metadata()?.len() < self.pos {
            self.pos = 0;
            self.pending.clear();
        }
        file.seek(SeekFrom::Start(self.pos))?;
        let mut fresh = Vec::new();
        self.pos += file.read_to_end(&mut fresh)? as u64;
        self.pending.extend(fresh);

        let mut records = Vec::new();
        while let Some(end) = self.pending.iter().position(|b| *b == b'\n') {
            let line: Vec<u8> = self.pending.drain(..=end).collect();
            if let Ok(v) = serde_json::from_slice::<Value>(&line)
                && v["episode_id"].is_string()
            {
                records.push(v);
            }
        }
        Ok(records)
    }
}

/// The last record of each episode, in the order of those last records.
fn latest(records: Vec<Value>) -> Vec<Value> {
    let mut last_at: HashMap<String, usize> = HashMap::new();
    for (i, r) in records.iter().enumerate() {
        last_at.insert(id_of(r).to_string(), i);
    }
    records.into_iter().enumerate().filter(|(i, r)| last_at[id_of(r)] == *i).map(|(_, r)| r).collect()
}

fn id_of(record: &Value) -> &str {
    record["episode_id"].as_str().unwrap_or("?")
}

pub(crate) fn rules_of(record: &Value) -> Vec<&str> {
    record["policy"].as_array().into_iter().flatten().filter_map(|p| p["rule"].as_str()).collect()
}

fn is_threat(record: &Value) -> bool {
    !rules_of(record).is_empty()
}

/// For `monitor`: the rules this record matched that weren't reported for its episode yet.
/// None when there is nothing new to report (no match, or the same rules as before).
pub(crate) fn newly_matched(reported: &mut HashMap<String, BTreeSet<String>>, record: &Value) -> Option<Vec<String>> {
    let seen = reported.entry(id_of(record).to_string()).or_default();
    let new: Vec<String> = rules_of(record).into_iter().filter(|r| seen.insert(r.to_string())).map(String::from).collect();
    (!new.is_empty()).then_some(new)
}

fn find<'a>(records: &'a [Value], wanted: &str, threats_only: bool) -> anyhow::Result<&'a Value> {
    if wanted == "last" {
        return records
            .iter()
            .rev()
            .find(|r| !threats_only || is_threat(r))
            .context(if threats_only { "no episode with matched rules" } else { "no assessed episodes" });
    }
    if let Some(exact) = records.iter().find(|r| id_of(r) == wanted) {
        return Ok(exact);
    }
    let matching: Vec<&Value> = records.iter().filter(|r| id_of(r).starts_with(wanted)).collect();
    match matching.as_slice() {
        [one] => Ok(one),
        [] => bail!("no episode '{wanted}' (list them: dnom audit)"),
        many => bail!(
            "'{wanted}' matches {} episodes: {}",
            many.len(),
            many.iter().take(5).map(|r| id_of(r)).collect::<Vec<_>>().join(", ")
        ),
    }
}

// --- rendering -----------------------------------------------------------------------------

/// One line per episode: when, id, result, where, command.
fn render_list(records: &[&Value], paint: &Paint, width: usize) -> String {
    let rows: Vec<[String; 5]> = records
        .iter()
        .map(|r| {
            let rules = rules_of(r);
            let result = match rules.as_slice() {
                [] => "ok".to_string(),
                [one] => format!("THREAT {one}"),
                [first, rest @ ..] => format!("THREAT {first} +{}", rest.len()),
            };
            let command = r["episode"]["root"]["argv"].as_str().filter(|a| !a.is_empty());
            let command = command.or(r["episode"]["root"]["exe"].as_str()).unwrap_or("").to_string();
            [local(record_ms(r), "%m-%d %H:%M:%S"), id_of(r).to_string(), clip(&result, 44), clip(&place(&r["episode"], true), 28), command]
        })
        .collect();
    let col = |i: usize, title: &str| rows.iter().map(|r| r[i].chars().count()).max().unwrap_or(0).max(title.len());
    let titles = ["WHEN", "EPISODE", "RESULT", "WHERE", "COMMAND"];
    let widths: Vec<usize> = (0..4).map(|i| col(i, titles[i])).collect();
    let used: usize = widths.iter().sum::<usize>() + 2 * 4;
    let command_width = width.saturating_sub(used).max(20);

    let mut o = String::new();
    let head: Vec<String> = (0..4).map(|i| format!("{:<w$}", titles[i], w = widths[i])).collect();
    let _ = writeln!(o, "{}", paint.dim(&format!("{}  {}", head.join("  "), titles[4])));
    for row in &rows {
        let result = format!("{:<w$}", row[2], w = widths[2]);
        let result = if row[2] == "ok" { paint.dim(&result) } else { paint.red(&result) };
        let _ = writeln!(
            o,
            "{:<w0$}  {:<w1$}  {result}  {:<w3$}  {}",
            row[0],
            row[1],
            row[3],
            clip(&row[4], command_width),
            w0 = widths[0],
            w1 = widths[1],
            w3 = widths[3],
        );
    }
    o
}

/// A threat report for `monitor`: a separator, then the full view.
fn card(record: &Value, new_rules: &[String], paint: &Paint) -> String {
    let rules = rules_of(record);
    let update = if !new_rules.is_empty() && new_rules.len() < rules.len() {
        format!("  (updated: now also {})", new_rules.join(", "))
    } else {
        String::new()
    };
    let title = format!("━━━━ {}{update} ", local(record_ms(record), "%Y-%m-%d %H:%M:%S"));
    format!("\n{}\n{}", paint.red(&format!("{title}{}", "━".repeat(72usize.saturating_sub(title.chars().count())))), render(record, paint))
}

/// The readable view of one record.
pub fn render(record: &Value, paint: &Paint) -> String {
    let ep = &record["episode"];
    let policy: Vec<&Value> = record["policy"].as_array().into_iter().flatten().collect();
    let mut o = String::new();

    let verdict = match policy.len() {
        0 => paint.green("no rule matched"),
        1 => paint.red_bold("THREAT · 1 rule matched (dry run)"),
        n => paint.red_bold(&format!("THREAT · {n} rules matched (dry run)")),
    };
    let _ = writeln!(o, "{}  {verdict}", paint.bold(id_of(record)));
    let (start, end) = (rfc3339_ms(&ep["window"]["start"]), rfc3339_ms(&ep["window"]["end"]));
    if let (Some(s), Some(e)) = (start, end) {
        let _ = writeln!(
            o,
            "  when      {} → {} ({})",
            local(Some(s), "%Y-%m-%d %H:%M:%S"),
            local(Some(e), "%H:%M:%S"),
            span(e.saturating_sub(s))
        );
    }
    let _ = writeln!(o, "  where     {}", place(ep, false));
    let started_by = ep["root"]["started_by"].as_str().filter(|s| !s.is_empty());
    let _ = writeln!(
        o,
        "  user      uid {}{}",
        ep["root"]["uid"].as_u64().map_or("?".to_string(), |u| u.to_string()),
        started_by.map(|s| format!(", started by {s}")).unwrap_or_default()
    );
    let _ = writeln!(o, "  command   {}", ep["root"]["argv"].as_str().unwrap_or(""));

    if !policy.is_empty() {
        let _ = writeln!(o, "\n{}", paint.bold("Rules matched"));
        let name_width = policy.iter().filter_map(|p| p["rule"].as_str()).map(|r| r.chars().count()).max().unwrap_or(0);
        for p in &policy {
            let actions: Vec<&str> = p["actions"].as_array().into_iter().flatten().filter_map(|a| a.as_str()).collect();
            let values: Vec<String> =
                p["values"].as_object().into_iter().flatten().map(|(k, v)| format!("{k}={}", v.as_str().map_or(v.to_string(), String::from))).collect();
            let protected = if p["protected"] == true { "  (protected program: would only alert)" } else { "" };
            let rule = format!("{:<name_width$}", p["rule"].as_str().unwrap_or("?"));
            let _ = writeln!(o, "  {}  WOULD: {}{protected}   {}", paint.red(&rule), actions.join(", "), paint.dim(&values.join(" ")));
        }
    }

    let _ = writeln!(o, "\n{}", paint.bold("What happened"));
    render_tree(ep, paint, &mut o);

    let _ = writeln!(o, "\n{}", paint.bold("Model"));
    render_model(record, paint, &mut o);
    o
}

struct Node<'a> {
    /// (time, command line) of each program this process ran, in order.
    ran: Vec<(Option<u64>, &'a str)>,
    /// Name of the program it ran last (`cat` for `/bin/cat`).
    name: &'a str,
    pid: u64,
    children: Vec<usize>,
    steps: Vec<&'a Value>,
}

fn render_tree(ep: &Value, paint: &Paint, o: &mut String) {
    let mut nodes: Vec<Node> = Vec::new();
    let mut by_pid: HashMap<u64, usize> = HashMap::new();
    let mut roots: Vec<usize> = Vec::new();
    let mut not_shown = 0;
    for entry in ep["tree"].as_array().into_iter().flatten() {
        let Some(pid) = entry["pid"].as_u64() else {
            not_shown += entry["more_processes_not_shown"].as_u64().unwrap_or(0);
            continue;
        };
        let ran = (entry["ts_ms"].as_u64(), entry["argv"].as_str().filter(|a| !a.is_empty()).or(entry["exe"].as_str()).unwrap_or("?"));
        let name = entry["exe"].as_str().and_then(|x| x.rsplit('/').next()).unwrap_or("");
        if let Some(&i) = by_pid.get(&pid) {
            nodes[i].ran.push(ran);
            nodes[i].name = name;
            continue;
        }
        // Records written before the tree stored parent pids only name the parent.
        let parent = match entry["ppid"].as_u64() {
            Some(pp) => by_pid.get(&pp).copied(),
            None if entry.get("ppid").is_none() => named_parent(&nodes, entry["parent"].as_str().unwrap_or("")),
            None => None,
        };
        let index = nodes.len();
        nodes.push(Node { ran: vec![ran], name, pid, children: Vec::new(), steps: Vec::new() });
        by_pid.insert(pid, index);
        match parent {
            Some(p) => nodes[p].children.push(index),
            None => roots.push(index),
        }
    }
    let mut loose: Vec<&Value> = Vec::new();
    for step in ep["trail"].as_array().into_iter().flatten() {
        match step["pid"].as_u64().and_then(|p| by_pid.get(&p)) {
            Some(&i) => nodes[i].steps.push(step),
            None => loose.push(step),
        }
    }

    for &root in &roots {
        draw(&nodes, root, "", "", paint, o);
    }
    for step in loose {
        let _ = writeln!(o, "  {}  {} {}", time_col(step["ts_ms"].as_u64()), step_text(step, paint), paint.dim("(process not in the tree)"));
    }
    if not_shown > 0 {
        let _ = writeln!(o, "  {}", paint.dim(&format!("… {not_shown} more processes not shown")));
    }
    if let Some(n) = ep["trail_truncated"].as_u64() {
        let _ = writeln!(o, "  {}", paint.dim(&format!("… {n} more steps not shown")));
    }

    // Records written before the trail existed: list files and connections without a process.
    let has_trail = ep.get("trail").is_some();
    let files = ep["files"].as_object();
    for (category, list) in files.into_iter().flatten() {
        if has_trail && category != "temp" {
            continue;
        }
        let list: Vec<&str> = list.as_array().into_iter().flatten().filter_map(|f| f.as_str()).collect();
        let _ = writeln!(o, "  {}", paint.dim(&format!("{category} files: {}", list.join(", "))));
    }
    if !has_trail {
        for n in ep["network"].as_array().into_iter().flatten() {
            let new = if n["new_destination"] == true { "  [new destination]" } else { "" };
            let _ = writeln!(o, "  {}", paint.dim(&format!("connect {} by {}{new}", n["dest"].as_str().unwrap_or("?"), n["by"].as_str().unwrap_or("?"))));
        }
    }
    if let Some(n) = ep["other_file_opens"].as_u64().filter(|n| *n > 0) {
        let _ = writeln!(o, "  {}", paint.dim(&format!("{n} other file opens (uncategorized, not listed)")));
    }
}

/// The most recent process with this program name, for records that only name the parent.
fn named_parent(nodes: &[Node], name: &str) -> Option<usize> {
    if name.is_empty() {
        return None;
    }
    nodes.iter().rposition(|n| n.name == name)
}

/// Draws a process, then what it did and the processes it started, in time order. `lead` is
/// printed before this process's own line, `rest` before every line below it.
fn draw(nodes: &[Node], index: usize, lead: &str, rest: &str, paint: &Paint, o: &mut String) {
    enum Item<'a> {
        Step(&'a Value),
        Child(usize),
    }
    let node = &nodes[index];
    let (ts, command) = node.ran[0];
    let _ = writeln!(o, "  {}  {lead}{command}  {}", time_col(ts), paint.dim(&format!("pid {}", node.pid)));

    let mut items: Vec<(Option<u64>, Item)> = node.steps.iter().map(|s| (s["ts_ms"].as_u64(), Item::Step(s))).collect();
    items.extend(node.children.iter().map(|&c| (nodes[c].ran[0].0, Item::Child(c))));
    // Stable: records without times keep steps first, then children, as stored.
    items.sort_by_key(|(ts, _)| *ts);
    let children_after = |from: usize| items[from..].iter().any(|(_, item)| matches!(item, Item::Child(_)));

    let line = if children_after(0) { "│  " } else { "   " };
    for (ts, command) in &node.ran[1..] {
        let _ = writeln!(o, "  {}  {rest}{line}↳ then ran: {command}", time_col(*ts));
    }
    let mut i = 0;
    while i < items.len() {
        match &items[i].1 {
            Item::Step(first) => {
                // A long run of the same kind of step (a scan's connections) is cut short.
                let run = items[i..].iter().take_while(|(_, item)| matches!(item, Item::Step(s) if step_kind(s) == step_kind(first))).count();
                let shown = if run > RUN_MAX { RUN_SHOWN } else { run };
                let line = if children_after(i + run) { "│  " } else { "   " };
                for (ts, item) in &items[i..i + shown] {
                    if let Item::Step(step) = item {
                        let _ = writeln!(o, "  {}  {rest}{line}▸ {}", time_col(*ts), step_text(step, paint));
                    }
                }
                if run > shown {
                    let note = format!("… {} more like these", run - shown);
                    let _ = writeln!(o, "  {}  {rest}{line}▸ {}", time_col(items[i + run - 1].0), paint.dim(&note));
                }
                i += run;
            }
            Item::Child(child) => {
                let (branch, cont) = if children_after(i + 1) { ("├─ ", "│  ") } else { ("└─ ", "   ") };
                draw(nodes, *child, &format!("{rest}{branch}"), &format!("{rest}{cont}"), paint, o);
                i += 1;
            }
        }
    }
}

/// Runs of more than RUN_MAX steps of one kind show the first RUN_SHOWN and a count.
const RUN_MAX: usize = 6;
const RUN_SHOWN: usize = 4;

fn step_kind(step: &Value) -> (&str, &str, bool, bool) {
    (
        step["event"].as_str().unwrap_or(""),
        step["category"].as_str().unwrap_or(""),
        step["write"] == true || step["new_destination"] == true,
        step["decoy"] == true,
    )
}

fn step_text(step: &Value, paint: &Paint) -> String {
    match step["event"].as_str() {
        Some("open") => {
            let verb = if step["write"] == true { "wrote" } else { "read" };
            let category = step["category"].as_str().unwrap_or("");
            let tag = match category {
                "decoys" => paint.red_bold("[DECOY]"),
                "dnom_config" => paint.red_bold("[DNOM CONFIG]"),
                other => paint.yellow(&format!("[{other}]")),
            };
            format!("{verb} {}  {tag}", step["path"].as_str().unwrap_or("?"))
        }
        Some("net") => {
            let tag = if step["decoy"] == true {
                format!("  {}", paint.red_bold("[DECOY]"))
            } else if step["new_destination"] == true {
                format!("  {}", paint.yellow("[new destination]"))
            } else {
                String::new()
            };
            // Port 0: no connection but a ping, or a packet built by the program itself.
            let dest = step["dest"].as_str().unwrap_or("?");
            match dest.strip_suffix(":0") {
                Some(ip) => format!("ping or raw packet to {}{tag}", ip.trim_start_matches('[').trim_end_matches(']')),
                None => format!("connect {dest}{tag}"),
            }
        }
        _ => step.to_string(),
    }
}

fn render_model(record: &Value, paint: &Paint, o: &mut String) {
    let Some(answers) = record["answers"].as_object().filter(|a| !a.is_empty()) else {
        let _ = writeln!(o, "  {}", paint.dim("not asked (no model backend for this record)"));
        return;
    };
    let _ = writeln!(
        o,
        "  {}",
        paint.dim(&format!(
            "{} · {} · {} ms",
            record["backend"].as_str().unwrap_or("?"),
            record["model"].as_str().unwrap_or("?"),
            record["latency_ms"].as_u64().unwrap_or(0)
        ))
    );
    let width = answers.keys().map(|k| k.chars().count()).max().unwrap_or(0);
    for (id, a) in answers {
        let value = if let Some(p) = a["noul"].as_f64() {
            format!("{p:.2}  {}", bar(p))
        } else if let Some(choice) = a["choice"].as_str() {
            format!("{choice}  {}", paint.dim(&format!("(confidence {:.2})", a["confidence"].as_f64().unwrap_or(0.0))))
        } else if let Some(score) = a["score"].as_f64() {
            format!("{score:.1}  {}", paint.dim(&format!("(confidence {:.2})", a["confidence"].as_f64().unwrap_or(0.0))))
        } else {
            a.to_string()
        };
        let _ = writeln!(o, "  {id:<width$}  {value}");
    }
    for note in record["notes"].as_array().into_iter().flatten().filter_map(|n| n.as_str()) {
        let _ = writeln!(o, "  {}", paint.dim(&format!("note: {note}")));
    }
}

/// A probability as a bar of ten cells.
fn bar(p: f64) -> String {
    let cells = (p.clamp(0.0, 1.0) * 10.0).round() as usize;
    format!("{}{}", "█".repeat(cells), "░".repeat(10 - cells))
}

/// Where the episode ran. Short form for the list: `pod · namespace`.
fn place(ep: &Value, short: bool) -> String {
    let Some(c) = ep["container"].as_object() else {
        return if short { "host".into() } else { "this machine (not in a container)".into() };
    };
    let get = |k: &str| c.get(k).and_then(|v| v.as_str());
    if short {
        return match (get("pod"), get("namespace"), get("name")) {
            (Some(pod), Some(ns), _) => format!("{pod} · {ns}"),
            (_, _, Some(name)) => name.to_string(),
            _ => "container".into(),
        };
    }
    let parts: Vec<String> = [("pod", "pod"), ("namespace", "namespace"), ("name", "container"), ("image", "image")]
        .iter()
        .filter_map(|(key, label)| get(key).map(|v| format!("{label} {v}")))
        .collect();
    if parts.is_empty() { "a container (no name known)".into() } else { parts.join(" · ") }
}

/// When the record was written; older dry-run records have no `ts`, so the episode's end.
fn record_ms(record: &Value) -> Option<u64> {
    rfc3339_ms(&record["ts"]).or_else(|| rfc3339_ms(&record["episode"]["window"]["end"]))
}

fn rfc3339_ms(v: &Value) -> Option<u64> {
    let t = humantime::parse_rfc3339(v.as_str()?).ok()?;
    Some(t.duration_since(UNIX_EPOCH).ok()?.as_millis() as u64)
}

fn time_col(ms: Option<u64>) -> String {
    match ms {
        Some(_) => local(ms, "%H:%M:%S"),
        None => " ".repeat(8),
    }
}

/// Local time; `format` uses strftime's %Y %m %d %H %M %S.
fn local(ms: Option<u64>, format: &str) -> String {
    let Some(ms) = ms else { return "-".into() };
    let secs = (ms / 1000) as libc::time_t;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    unsafe { libc::localtime_r(&secs, &mut tm) };
    let two = |n: i32| format!("{n:02}");
    format
        .replace("%Y", &(tm.tm_year + 1900).to_string())
        .replace("%m", &two(tm.tm_mon + 1))
        .replace("%d", &two(tm.tm_mday))
        .replace("%H", &two(tm.tm_hour))
        .replace("%M", &two(tm.tm_min))
        .replace("%S", &two(tm.tm_sec))
}

fn span(ms: u64) -> String {
    match ms / 1000 {
        0 => "under 1 s".into(),
        s if s < 120 => format!("{s} s"),
        s => format!("{} min", s / 60),
    }
}

fn clip(s: &str, max: usize) -> String {
    if s.chars().count() <= max { s.to_string() } else { format!("{}…", s.chars().take(max.saturating_sub(1)).collect::<String>()) }
}

fn terminal_width() -> usize {
    let mut size: libc::winsize = unsafe { std::mem::zeroed() };
    let ok = unsafe { libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut size) } == 0;
    if ok && size.ws_col > 0 { size.ws_col as usize } else { 120 }
}

/// Colour only on a terminal, and never when NO_COLOR is set.
pub struct Paint {
    on: bool,
}

impl Paint {
    fn auto() -> Self {
        Self { on: io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none() }
    }

    /// No colour: for text that goes into a file or a message.
    pub fn plain() -> Self {
        Self { on: false }
    }

    fn wrap(&self, code: &str, s: &str) -> String {
        if self.on { format!("\x1b[{code}m{s}\x1b[0m") } else { s.to_string() }
    }

    fn red(&self, s: &str) -> String {
        self.wrap("31", s)
    }

    fn red_bold(&self, s: &str) -> String {
        self.wrap("1;31", s)
    }

    fn yellow(&self, s: &str) -> String {
        self.wrap("33", s)
    }

    fn green(&self, s: &str) -> String {
        self.wrap("32", s)
    }

    fn bold(&self, s: &str) -> String {
        self.wrap("1", s)
    }

    fn dim(&self, s: &str) -> String {
        self.wrap("2", s)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const PLAIN: Paint = Paint { on: false };

    fn record(id: &str, rules: &[&str]) -> Value {
        json!({
            "ts": "2026-11-09T18:12:54Z",
            "episode_id": id,
            "backend": "none",
            "policy": rules.iter().map(|r| json!({ "rule": r, "actions": ["alert"], "dry_run": true, "protected": false, "values": { "files.decoys": "1" } })).collect::<Vec<_>>(),
            "episode": {
                "window": { "start": "2026-11-09T18:12:51Z", "end": "2026-11-09T18:12:53Z" },
                "root": { "exe": "/bin/busybox", "argv": "sh -c cat keys; wget http://203.0.113.7/", "uid": 0, "started_by": "containerd-shim" },
                "container": { "name": "web", "image": "alpine:3.20", "pod": "web", "namespace": "dnom-test" },
                "tree": [
                    { "pid": 10, "ppid": 5, "ts_ms": 1000, "exe": "/bin/busybox", "argv": "sh -c cat keys; wget http://203.0.113.7/", "parent": "containerd-shim" },
                    { "pid": 11, "ppid": 10, "ts_ms": 1100, "exe": "/bin/busybox", "argv": "cat /opt/keys-old/id_rsa", "parent": "sh" },
                    { "pid": 12, "ppid": 10, "ts_ms": 1200, "exe": "/bin/busybox", "argv": "sh helper.sh", "parent": "sh" },
                    { "pid": 13, "ppid": 12, "ts_ms": 1300, "exe": "/bin/busybox", "argv": "wget http://203.0.113.7/", "parent": "sh" },
                ],
                "trail": [
                    { "ts_ms": 1150, "pid": 11, "event": "open", "path": "/opt/keys-old/id_rsa", "category": "decoys", "write": false },
                    { "ts_ms": 3300, "pid": 13, "event": "net", "dest": "203.0.113.7:80", "new_destination": true },
                ],
                "files": { "decoys": ["/opt/keys-old/id_rsa"], "temp": ["/tmp/x"] },
                "other_file_opens": 4,
                "network": [{ "dest": "203.0.113.7:80", "by": "busybox", "new_destination": true }],
                "flags": ["new_destination"],
            },
        })
    }

    /// Text after the time column, so the test doesn't depend on the local time zone.
    fn tree_lines(view: &str) -> Vec<String> {
        let body = view.split("What happened\n").nth(1).unwrap().split("\n\n").next().unwrap();
        body.lines().map(|l| l.chars().skip(12).collect()).collect()
    }

    #[test]
    fn full_view_draws_the_tree_with_each_process_steps() {
        let view = render(&record("ep-10-abc", &["decoy-touched"]), &PLAIN);
        assert!(view.starts_with("ep-10-abc  THREAT · 1 rule matched (dry run)\n"), "{view}");
        assert!(view.contains("  where     pod web · namespace dnom-test · container web · image alpine:3.20\n"), "{view}");
        assert!(view.contains("  user      uid 0, started by containerd-shim\n"), "{view}");
        assert!(view.contains("  decoy-touched  WOULD: alert   files.decoys=1\n"), "{view}");
        assert_eq!(
            tree_lines(&view)[..6],
            [
                "sh -c cat keys; wget http://203.0.113.7/  pid 10",
                "├─ cat /opt/keys-old/id_rsa  pid 11",
                "│     ▸ read /opt/keys-old/id_rsa  [DECOY]",
                "└─ sh helper.sh  pid 12",
                "   └─ wget http://203.0.113.7/  pid 13",
                "         ▸ connect 203.0.113.7:80  [new destination]",
            ],
            "{view}"
        );
        assert!(view.contains("  temp files: /tmp/x\n") && view.contains("  4 other file opens"), "{view}");
        assert!(view.contains("Model\n  not asked"), "{view}");
    }

    #[test]
    fn model_answers_and_exec_chains() {
        let mut r = record("ep-10-abc", &[]);
        r["backend"] = json!("jev");
        r["model"] = json!("jev-1");
        r["latency_ms"] = json!(135);
        r["answers"] = json!({
            "credential_access": { "type": "noul", "noul": 0.97 },
            "response": { "type": "choice", "choice": "alert", "confidence": 0.52, "probabilities": {} },
        });
        // The same process ran two programs: env, then bash.
        r["episode"]["tree"] = json!([
            { "pid": 10, "ppid": 5, "ts_ms": 1000, "exe": "/usr/bin/env", "argv": "env bash x.sh", "parent": "sshd" },
            { "pid": 10, "ppid": 5, "ts_ms": 1010, "exe": "/usr/bin/bash", "argv": "bash x.sh", "parent": "sshd" },
            { "more_processes_not_shown": 3 },
        ]);
        r["episode"]["trail"] = json!([]);
        let view = render(&r, &PLAIN);
        assert!(view.starts_with("ep-10-abc  no rule matched\n") && !view.contains("Rules matched"), "{view}");
        assert_eq!(tree_lines(&view)[..2], ["env bash x.sh  pid 10", "   ↳ then ran: bash x.sh"], "{view}");
        assert!(view.contains("  … 3 more processes not shown\n"), "{view}");
        assert!(view.contains("  jev · jev-1 · 135 ms\n"), "{view}");
        assert!(view.contains("  credential_access  0.97  ██████████\n"), "{view}");
        assert!(view.contains("  response           alert  (confidence 0.52)\n"), "{view}");
    }

    #[test]
    fn long_runs_of_one_kind_of_step_are_cut_short() {
        let mut r = record("ep-10-abc", &[]);
        let scan: Vec<Value> = (1..=20).map(|i| json!({ "ts_ms": 2000 + i, "pid": 10, "event": "net", "dest": format!("10.0.0.{i}:22"), "new_destination": true })).collect();
        r["episode"]["trail"] = json!(scan);
        let lines = tree_lines(&render(&r, &PLAIN));
        assert_eq!(
            lines[..9],
            [
                "sh -c cat keys; wget http://203.0.113.7/  pid 10",
                "├─ cat /opt/keys-old/id_rsa  pid 11",
                "└─ sh helper.sh  pid 12",
                "   └─ wget http://203.0.113.7/  pid 13",
                "   ▸ connect 10.0.0.1:22  [new destination]",
                "   ▸ connect 10.0.0.2:22  [new destination]",
                "   ▸ connect 10.0.0.3:22  [new destination]",
                "   ▸ connect 10.0.0.4:22  [new destination]",
                "   ▸ … 16 more like these",
            ],
            "{lines:#?}"
        );
    }

    /// A decoy address in the middle of a scan is never folded into "more like these".
    #[test]
    fn decoy_address_stands_out_of_a_scan() {
        let mut r = record("ep-10-abc", &["decoy-contacted"]);
        let mut scan: Vec<Value> = (1..=20).map(|i| json!({ "ts_ms": 2000 + i, "pid": 10, "event": "net", "dest": format!("10.0.0.{i}:22"), "new_destination": true })).collect();
        scan[11]["decoy"] = json!(true);
        scan.push(json!({ "ts_ms": 2100, "pid": 10, "event": "net", "dest": "10.0.0.99:0", "new_destination": false, "decoy": true }));
        r["episode"]["trail"] = json!(scan);
        let lines = tree_lines(&render(&r, &PLAIN));
        assert_eq!(
            lines[8..12],
            ["   ▸ … 7 more like these", "   ▸ connect 10.0.0.12:22  [DECOY]", "   ▸ connect 10.0.0.13:22  [new destination]", "   ▸ connect 10.0.0.14:22  [new destination]"],
            "{lines:#?}"
        );
        assert!(lines.contains(&"   ▸ ping or raw packet to 10.0.0.99  [DECOY]".to_string()), "{lines:#?}");
    }

    /// Records written before the tree stored parent pids and before the trail existed.
    #[test]
    fn older_records_still_render() {
        let mut r = record("ep-10-abc", &["credentials-then-new-destination"]);
        let ep = r["episode"].as_object_mut().unwrap();
        ep.remove("trail");
        ep.insert("files".into(), json!({ "credentials": ["/etc/shadow"] }));
        ep.insert(
            "tree".into(),
            json!([
                { "pid": 10, "exe": "/bin/sh", "argv": "sh run.sh", "parent": "sshd" },
                { "pid": 11, "exe": "/bin/cat", "argv": "cat /etc/shadow", "parent": "sh" },
            ]),
        );
        let view = render(&r, &PLAIN);
        assert_eq!(tree_lines(&view)[..2], ["sh run.sh  pid 10", "└─ cat /etc/shadow  pid 11"], "{view}");
        assert!(view.contains("  credentials files: /etc/shadow\n"), "{view}");
        assert!(view.contains("  connect 203.0.113.7:80 by busybox  [new destination]\n"), "{view}");
    }

    #[test]
    fn list_shows_the_last_record_of_each_episode() {
        let records = latest(vec![record("ep-1-a", &[]), record("ep-2-b", &["decoy-touched"]), record("ep-1-a", &["x", "y"])]);
        assert_eq!(records.iter().map(id_of).collect::<Vec<_>>(), ["ep-2-b", "ep-1-a"]);
        let refs: Vec<&Value> = records.iter().collect();
        let list = render_list(&refs, &PLAIN, 200);
        let lines: Vec<&str> = list.lines().collect();
        assert!(lines[0].starts_with("WHEN") && lines[0].ends_with("COMMAND"), "{list}");
        assert!(lines[1].contains("ep-2-b   THREAT decoy-touched  web · dnom-test  sh -c cat keys"), "{list}");
        assert!(lines[2].contains("ep-1-a   THREAT x +1"), "{list}");
        // A narrower terminal clips the command, never the other columns.
        let narrow = render_list(&refs, &PLAIN, 100);
        assert!(narrow.lines().all(|l| l.chars().count() <= 100) && narrow.contains("…"), "{narrow}");

        assert_eq!(id_of(find(&records, "last", false).unwrap()), "ep-1-a");
        assert_eq!(id_of(find(&records, "ep-2", false).unwrap()), "ep-2-b");
        assert!(find(&records, "ep-", false).unwrap_err().to_string().contains("matches 2 episodes"));
        assert!(find(&records, "nope", false).is_err());
    }

    /// `monitor` reports an episode when a rule first matches, and again only for new rules.
    #[test]
    fn monitor_reports_each_rule_once_per_episode() {
        let mut reported = HashMap::new();
        assert_eq!(newly_matched(&mut reported, &record("ep-1-a", &[])), None);
        assert_eq!(newly_matched(&mut reported, &record("ep-1-a", &["decoy-touched"])), Some(vec!["decoy-touched".to_string()]));
        assert_eq!(newly_matched(&mut reported, &record("ep-1-a", &["decoy-touched"])), None, "reassessed, nothing new");
        assert_eq!(newly_matched(&mut reported, &record("ep-1-a", &["decoy-touched", "exfiltration"])), Some(vec!["exfiltration".to_string()]));
        assert_eq!(newly_matched(&mut reported, &record("ep-2-b", &["decoy-touched"])), Some(vec!["decoy-touched".to_string()]));

        let update = card(&record("ep-1-a", &["decoy-touched", "exfiltration"]), &["exfiltration".to_string()], &PLAIN);
        assert!(update.contains("(updated: now also exfiltration)"), "{update}");
        assert!(!card(&record("ep-1-a", &["decoy-touched"]), &["decoy-touched".to_string()], &PLAIN).contains("updated"));
    }

    #[test]
    fn tail_reads_only_complete_new_lines() {
        let dir = std::env::temp_dir().join(format!("dnom-audit-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("assessments.jsonl");
        let mut tail = Tail::new(path.clone());
        assert!(tail.read_new().unwrap().is_empty(), "no log yet");

        let line = |id: &str| format!("{}\n", record(id, &[]));
        std::fs::write(&path, format!("{}not json\n{}", line("ep-1-a"), &line("ep-2-b")[..20])).unwrap();
        assert_eq!(tail.read_new().unwrap().iter().map(id_of).collect::<Vec<_>>(), ["ep-1-a"]);
        let mut f = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(&line("ep-2-b").as_bytes()[20..]).unwrap();
        assert_eq!(tail.read_new().unwrap().iter().map(id_of).collect::<Vec<_>>(), ["ep-2-b"], "the half-written line, once complete");
        assert!(tail.read_new().unwrap().is_empty());
        // Truncated (a new log): start over.
        std::fs::write(&path, line("ep-3-c")).unwrap();
        assert_eq!(tail.read_new().unwrap().iter().map(id_of).collect::<Vec<_>>(), ["ep-3-c"]);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
