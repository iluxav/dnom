//! `dnom classify` (unprivileged): events in, episodes built, model answers out.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, BufRead, BufReader, Write},
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc::{self, RecvTimeoutError},
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context as _, bail};
use clap::{Args, ValueEnum};
use serde_json::{Value, json};

use crate::{
    assess::{Answer, Assessment, Backend, Jev, Local, QUESTIONS},
    config,
    episode::{Baseline, Episode, Tracker},
    event::{Data, Event},
};

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum BackendKind {
    /// Ollama on this machine. Nothing leaves the host.
    Local,
    /// TypeSafe's Jev API. Episode data leaves the host; needs --only.
    Jev,
    /// No model: print the episodes that would be assessed.
    None,
}

#[derive(Args)]
pub struct ClassifyArgs {
    #[arg(long, value_enum, default_value_t = BackendKind::Local)]
    backend: BackendKind,
    /// Read events from this JSONL file (a recording) instead of stdin.
    #[arg(long)]
    input: Option<PathBuf>,
    /// Config file (default: ./dnom.yaml, then ~/.config/dnom/dnom.yaml).
    #[arg(long)]
    config: Option<PathBuf>,
    /// Only assess episodes whose root command line contains this text.
    #[arg(long)]
    only: Option<String>,
    /// Let --backend jev receive every episode, not just --only matches.
    #[arg(long)]
    allow_all_to_jev: bool,
    /// Also assess episodes whose only signal is a new network destination.
    #[arg(long)]
    assess_new_destinations: bool,
    /// Seconds between assessment ticks.
    #[arg(long, default_value_t = 5)]
    interval: u64,
    /// Maximum episodes assessed per tick; the rest wait for the next tick.
    /// The local 27B model takes about 8 s per episode (six questions).
    #[arg(long, default_value_t = 4)]
    budget: usize,
    /// Seconds of learning when the baseline is empty (no new_exe / new_destination flags).
    #[arg(long, default_value_t = 120)]
    learn: u64,
    /// Episode closes after this many idle seconds.
    #[arg(long, default_value_t = 60)]
    idle: u64,
    #[arg(long, default_value = "http://127.0.0.1:11434")]
    ollama_url: String,
    #[arg(long, default_value = "qwen3.6:27b-q8_0")]
    model: String,
    #[arg(long, default_value = "https://api.typesafe.ai")]
    jev_url: String,
    #[arg(long, default_value = "jev-latest")]
    jev_model: String,
    /// Print each assessment as one JSON line instead of the text summary.
    #[arg(long)]
    json: bool,
    /// Directory for baseline.json and assessments.jsonl (default ~/.local/state/dnom).
    #[arg(long)]
    state_dir: Option<PathBuf>,
}

static STOP: AtomicBool = AtomicBool::new(false);
/// Model input tokens used so far (Jev bills input tokens).
static INPUT_TOKENS: AtomicU64 = AtomicU64::new(0);

extern "C" fn on_sigint(_: libc::c_int) {
    STOP.store(true, Ordering::SeqCst);
}

pub fn run(args: ClassifyArgs) -> anyhow::Result<()> {
    if args.backend == BackendKind::Jev && args.only.is_none() && !args.allow_all_to_jev {
        bail!(
            "--backend jev sends episode data off this machine. Pass --only <text> to limit it to \
             a test (e.g. --only fake-exfil), or --allow-all-to-jev to send everything."
        );
    }
    let (config, config_path) = config::load(args.config.as_deref())?;
    let state_dir = match &args.state_dir {
        Some(d) => d.clone(),
        None => PathBuf::from(std::env::var("HOME").context("HOME not set")?).join(".local/state/dnom"),
    };
    fs::create_dir_all(&state_dir).with_context(|| format!("create {}", state_dir.display()))?;
    let baseline_path = state_dir.join("baseline.json");
    let log_path = state_dir.join("assessments.jsonl");

    let backend: Option<Box<dyn Backend>> = match args.backend {
        BackendKind::Local => Some(Box::new(Local::new(&args.ollama_url, &args.model))),
        BackendKind::Jev => Some(Box::new(Jev::new(&args.jev_url, &args.jev_model)?)),
        BackendKind::None => None,
    };

    let (baseline, had_baseline) = Baseline::load(&baseline_path);
    let replay = args.input.is_some();
    let rx = spawn_reader(args.input.clone())?;
    let ignore_count = config.ignore.len();

    unsafe { libc::signal(libc::SIGINT, on_sigint as *const () as libc::sighandler_t) };

    let mut tracker = Tracker::new(config, baseline, 0);
    let (exes, dests) = tracker.baseline.len();
    eprintln!(
        "dnom classify: backend={} config={} ignore_rules={} baseline={} exes/{} destinations{}",
        backend_label(&args),
        config_path.map(|p| p.display().to_string()).unwrap_or_else(|| "defaults".into()),
        ignore_count,
        exes,
        dests,
        if had_baseline { String::new() } else { format!(", learning for {} s", args.learn) },
    );

    if let Some(only) = &args.only {
        eprintln!("dnom classify: only assessing episodes whose command contains '{only}'");
    } else if args.backend == BackendKind::Jev {
        eprintln!(
            "dnom classify: sending every assessed episode to Jev (commands, file paths, \
             destinations; home shortened to ~, secrets in command lines redacted)"
        );
    }

    let mut log = OpenOptions::new().create(true).append(true).open(&log_path)
        .with_context(|| format!("open {}", log_path.display()))?;
    let interval_ms = args.interval * 1000;
    let mut next_tick: Option<u64> = None;
    let mut last_save = Instant::now();
    let mut now_ms: u64;
    let mut counts = EventCounts::default();
    let mut assessed_total = 0u64;
    // First status line after 5 s, then every 15 s.
    let mut last_status = Instant::now().checked_sub(Duration::from_secs(10)).unwrap_or_else(Instant::now);

    loop {
        if STOP.load(Ordering::SeqCst) {
            break;
        }
        let msg = rx.recv_timeout(Duration::from_millis(200));
        let ended = matches!(msg, Err(RecvTimeoutError::Disconnected));
        match msg {
            Ok(event) => {
                counts.add(&event);
                now_ms = if replay { event.ts_ms } else { wall_ms() };
                if tracker.learn_until_ms == 0 && !had_baseline {
                    tracker.learn_until_ms = event.ts_ms + args.learn * 1000;
                }
                tracker.ingest(event);
            }
            Err(_) if replay && !ended => continue,
            Err(_) => now_ms = if replay { u64::MAX / 2 } else { wall_ms() },
        }
        let due = *next_tick.get_or_insert(now_ms + interval_ms);
        if now_ms >= due || ended {
            assessed_total += tick(&mut tracker, &args, backend.as_deref(), &mut log, now_ms, ended)?;
            next_tick = Some(now_ms + interval_ms);
        }
        if !replay && last_status.elapsed() >= Duration::from_secs(15) {
            status(&tracker, &counts, assessed_total, now_ms);
            last_status = Instant::now();
        }
        if last_save.elapsed() > Duration::from_secs(30) {
            tracker.baseline.save(&baseline_path)?;
            last_save = Instant::now();
        }
        if ended {
            break;
        }
    }
    tracker.baseline.save(&baseline_path)?;
    let (exes, dests) = tracker.baseline.len();
    eprintln!(
        "dnom classify: stopped. baseline saved ({exes} exes, {dests} destinations), log: {}",
        log_path.display()
    );
    Ok(())
}

#[derive(Default)]
struct EventCounts {
    total: u64,
    exec: u64,
    open: u64,
    net: u64,
}

impl EventCounts {
    fn add(&mut self, event: &Event) {
        self.total += 1;
        match event.data {
            Data::Exec { .. } => self.exec += 1,
            Data::Open { .. } => self.open += 1,
            Data::Net { .. } => self.net += 1,
            Data::Fork { .. } | Data::Exit {} => {}
        }
    }
}

/// Heartbeat on stderr so a quiet terminal is clearly "nothing worth assessing", not "stuck".
fn status(tracker: &Tracker, counts: &EventCounts, assessed: u64, now_ms: u64) {
    let open = tracker.episodes.len();
    let not_sent = tracker.episodes.values().filter(|e| e.needs_assessment()).count();
    let mut line = format!(
        "dnom classify: {} events (exec {}, open {}, net {}) | {open} episodes open, \
         {not_sent} filtered out | {assessed} assessed",
        counts.total, counts.exec, counts.open, counts.net
    );
    let tokens = INPUT_TOKENS.load(Ordering::Relaxed);
    if tokens > 0 {
        line.push_str(&format!(" | {tokens} input tokens"));
    }
    let learning_left = tracker.learn_until_ms.saturating_sub(now_ms) / 1000;
    if learning_left > 0 {
        line.push_str(&format!(" | learning, {learning_left} s left"));
    }
    eprintln!("{line}");
}

fn backend_label(args: &ClassifyArgs) -> String {
    match args.backend {
        BackendKind::Local => format!("local ({})", args.model),
        BackendKind::Jev => format!("jev ({})", args.jev_model),
        BackendKind::None => "none (dry run)".into(),
    }
}

/// Reads JSON lines on a thread so model calls never block event intake.
fn spawn_reader(input: Option<PathBuf>) -> anyhow::Result<mpsc::Receiver<Event>> {
    let reader: Box<dyn BufRead + Send> = match input {
        Some(path) => Box::new(BufReader::new(
            File::open(&path).with_context(|| format!("open {}", path.display()))?,
        )),
        None => Box::new(BufReader::new(io::stdin())),
    };
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut bad = 0u64;
        for line in reader.lines() {
            let Ok(line) = line else { break };
            match serde_json::from_str::<Event>(&line) {
                Ok(event) => {
                    if tx.send(event).is_err() {
                        break;
                    }
                }
                Err(_) => {
                    bad += 1;
                    if bad <= 3 {
                        eprintln!("dnom classify: skipping unreadable line: {}", line.chars().take(120).collect::<String>());
                    }
                }
            }
        }
    });
    Ok(rx)
}

fn tick(
    tracker: &mut Tracker,
    args: &ClassifyArgs,
    backend: Option<&dyn Backend>,
    log: &mut File,
    now_ms: u64,
    final_tick: bool,
) -> anyhow::Result<u64> {
    // Pick changed episodes that pass the pre-filter, after they settle for 1 s
    // (or after 10 s of continuous change), highest priority first.
    let mut ready: Vec<(usize, u64, u32)> = tracker
        .episodes
        .values()
        .filter(|ep| ep.needs_assessment() && ep.passes_prefilter(args.assess_new_destinations))
        .filter(|ep| args.only.as_deref().is_none_or(|o| ep.root_argv.contains(o) || ep.root_exe.contains(o)))
        .filter(|ep| {
            final_tick
                || now_ms.saturating_sub(ep.last_change_ms) >= 1000
                || ep.first_unassessed_ms.is_some_and(|t| now_ms.saturating_sub(t) >= 10_000)
        })
        .map(|ep| (ep.sensitive_count(), ep.first_unassessed_ms.unwrap_or(0), ep.root))
        .collect();
    ready.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
    let waiting = ready.len().saturating_sub(args.budget);
    let mut assessed = 0;

    for &(_, _, root) in ready.iter().take(args.budget) {
        let Some(ep) = tracker.episodes.get_mut(&root) else { continue };
        let version = ep.version;
        let episode_json = ep.to_json(tracker_home());
        let result = match backend {
            None => None,
            Some(b) => {
                let started = Instant::now();
                match b.assess(&episode_json) {
                    Ok(a) => {
                        INPUT_TOKENS.fetch_add(a.input_tokens.unwrap_or(0), Ordering::Relaxed);
                        Some((b.name(), a, started.elapsed()))
                    }
                    Err(e) => {
                        // Leave it unassessed so the next tick retries.
                        eprintln!("dnom classify: {} failed for {}: {e:#}", b.name(), ep.id);
                        continue;
                    }
                }
            }
        };
        ep.assessed_version = version;
        ep.first_unassessed_ms = None;
        report(ep, &episode_json, result.as_ref(), args.json, log)?;
        assessed += 1;
    }
    if waiting > 0 {
        eprintln!("dnom classify: {waiting} episodes waiting for the next tick (budget {})", args.budget);
    }
    tracker.gc(now_ms, args.idle * 1000, 600_000);
    Ok(assessed)
}

fn tracker_home() -> &'static str {
    static HOME: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    HOME.get_or_init(|| std::env::var("HOME").unwrap_or_default())
}

fn report(
    ep: &Episode,
    episode_json: &Value,
    result: Option<&(&'static str, Assessment, Duration)>,
    as_json: bool,
    log: &mut File,
) -> anyhow::Result<()> {
    let record = match result {
        Some((backend, a, took)) => json!({
            "ts": crate::episode::rfc3339(wall_ms()),
            "episode_id": ep.id,
            "episode_hash": format!("{:016x}", fnv1a(episode_json.to_string().as_bytes())),
            "backend": backend,
            "model": a.model,
            "latency_ms": took.as_millis() as u64,
            "input_tokens": a.input_tokens,
            "answers": a.answers,
            "notes": a.notes,
            "episode": episode_json,
        }),
        None => json!({ "episode_id": ep.id, "backend": "none", "episode": episode_json }),
    };
    if result.is_some() {
        writeln!(log, "{record}")?;
    }

    let mut out = io::stdout().lock();
    if as_json {
        writeln!(out, "{record}")?;
        return Ok(out.flush()?);
    }
    let header = match result {
        Some((backend, a, took)) => format!("[{backend} {} {:.1}s]", a.model, took.as_secs_f64()),
        None => "[dry run]".into(),
    };
    writeln!(out, "\n{}  {}  {}  uid={}  {header}", clock(ep.last_ms), ep.id, ep.label(), ep.root_uid)?;
    writeln!(out, "  cmd:   {}", episode_json["root"]["argv"].as_str().unwrap_or(""))?;
    if let Some((_, a, _)) = result {
        let mut parts = Vec::new();
        for q in &QUESTIONS {
            match a.answers.get(q.id) {
                Some(Answer::Noul { noul }) => {
                    let mark = if *noul >= 0.7 && q.id != "fits_baseline" { "!" } else { " " };
                    parts.push(format!("{}{} {:.2}", mark, short(q.id), noul));
                }
                Some(Answer::Choice { choice, confidence, .. }) => {
                    parts.push(format!(" → {choice} ({confidence:.2})"));
                }
                None => {}
            }
        }
        writeln!(out, "  model: {}", parts.join("  "))?;
        for note in &a.notes {
            writeln!(out, "  note:  {note}")?;
        }
    }
    for (cat, files) in episode_json["files"].as_object().into_iter().flatten() {
        let list: Vec<&str> = files.as_array().into_iter().flatten().filter_map(|f| f.as_str()).collect();
        writeln!(out, "  {:<6} {}", category_label(cat), list.join(", "))?;
    }
    let net: Vec<String> = episode_json["network"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|n| {
            let new = if n["new_destination"].as_bool() == Some(true) { " (new)" } else { "" };
            format!("{}{} by {}", n["dest"].as_str().unwrap_or(""), new, n["by"].as_str().unwrap_or(""))
        })
        .collect();
    if !net.is_empty() {
        writeln!(out, "  net:   {}", net.join(", "))?;
    }
    let flags: Vec<&str> = episode_json["flags"].as_array().into_iter().flatten().filter_map(|f| f.as_str()).collect();
    if !flags.is_empty() {
        writeln!(out, "  flags: {}", flags.join(", "))?;
    }
    if result.is_none() {
        writeln!(out, "  procs: {}", episode_json["tree"].as_array().map_or(0, |t| t.len()))?;
    }
    Ok(out.flush()?)
}

fn short(id: &str) -> &str {
    match id {
        "credential_access" => "cred",
        "persistence" => "persist",
        "exfiltration" => "exfil",
        "lateral_movement" => "lateral",
        "fits_baseline" => "normal",
        other => other,
    }
}

fn category_label(category: &str) -> &str {
    match category {
        "credentials" => "creds:",
        "persistence" => "persist:",
        "system_binaries" => "bins:",
        "temp" => "temp:",
        other => other,
    }
}

fn wall_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// Local HH:MM:SS for terminal output.
fn clock(ms: u64) -> String {
    let secs = (ms / 1000) as libc::time_t;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    unsafe { libc::localtime_r(&secs, &mut tm) };
    format!("{:02}:{:02}:{:02}", tm.tm_hour, tm.tm_min, tm.tm_sec)
}

fn fnv1a(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in bytes {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}
