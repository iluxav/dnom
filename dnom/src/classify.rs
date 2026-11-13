//! `dnom classify` (unprivileged): events in, episodes built, model answers out.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, BufRead, BufReader, Write},
    path::{Path, PathBuf},
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
    assess::{Answer, Assessment, Backend, Local, OpenAi, SystemOne},
    backends::{self, BackendType},
    config,
    decoys::Planted,
    episode::{Baseline, Episode, Tracker},
    notify::Notifier,
    event::{Data, Event},
    policy::{Match, Policies},
    questions::Question,
};

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Source {
    /// JSON lines from `dnom collect`.
    Dnom,
    /// Falco JSON output with the dnom catch-all rules (integrations/falco/dnom-catchall.yaml).
    Falco,
}

#[derive(Args)]
pub struct ClassifyArgs {
    /// Format of the input events.
    #[arg(long, value_enum, default_value_t = Source::Dnom)]
    source: Source,
    /// The events come from another machine (e.g. `dnom collect` in the lab VM over SSH):
    /// don't look processes up in this machine's /proc.
    #[arg(long)]
    remote_source: bool,
    /// Home directory shortened to ~ in episodes (default: $HOME; set it to the monitored
    /// machine's home with --remote-source).
    #[arg(long)]
    home: Option<String>,
    /// Backend name from `backends:` in dnom.yaml (default: its `backend:` setting), or `none`
    /// to print the episodes that would be assessed without asking a model.
    #[arg(long)]
    backend: Option<String>,
    /// Use this model instead of the backend's `model` from dnom.yaml.
    #[arg(long)]
    model: Option<String>,
    /// Read events from this JSONL file (a recording) instead of stdin.
    #[arg(long)]
    input: Option<PathBuf>,
    /// Config file (default: ./dnom.yaml, then ~/.config/dnom/dnom.yaml).
    #[arg(long)]
    config: Option<PathBuf>,
    /// Only assess episodes whose root command line contains this text.
    #[arg(long)]
    only: Option<String>,
    /// Let a backend on another machine (e.g. Jev) receive every episode, not just --only matches.
    #[arg(long, alias = "allow-all-to-jev")]
    allow_all_remote: bool,
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
    /// Print each assessment as one JSON line instead of the text summary.
    #[arg(long)]
    json: bool,
    /// Only print episodes a policy rule matched (all assessments are still logged).
    #[arg(long)]
    matches_only: bool,
    /// Send webhook alerts (`notify:` in dnom.yaml) also when replaying a recording with
    /// --input. Live runs send them whenever a URL is configured.
    #[arg(long)]
    notify: bool,
    /// Directory for baseline.json and assessments.jsonl (default ~/.local/state/dnom).
    #[arg(long)]
    state_dir: Option<PathBuf>,
}

static STOP: AtomicBool = AtomicBool::new(false);
/// Model input tokens used so far (hosted decision APIs bill input tokens).
static INPUT_TOKENS: AtomicU64 = AtomicU64::new(0);

/// Ctrl-C, `kill`, or the terminal closing: stop the loop so the run ends cleanly (baseline
/// saved, generated decoys removed).
extern "C" fn on_sigint(_: libc::c_int) {
    STOP.store(true, Ordering::SeqCst);
}

pub fn run(args: ClassifyArgs) -> anyhow::Result<()> {
    let (mut config, config_path) = config::load(args.config.as_deref())?;
    // The config is a tripwire: another program opening it is reported (files.dnom_config).
    // Only on this machine; paths in events from another machine are that machine's.
    if !args.remote_source
        && let Some(path) = &config_path
    {
        for form in [std::path::absolute(path).ok(), fs::canonicalize(path).ok()].into_iter().flatten() {
            let form = form.to_string_lossy().into_owned();
            if !config.paths.own_config.contains(&form) {
                config.paths.own_config.push(form);
            }
        }
    }
    let selected = backends::select(&config.backends, &config.backend, args.backend.as_deref())?;
    if let Some((name, def)) = &selected
        && def.is_remote()
        && args.only.is_none()
        && !args.allow_all_remote
    {
        bail!(
            "backend {name} sends episode data off this machine (to {}). Pass --only <text> to \
             limit it to a test (e.g. --only fake-exfil), or --allow-all-remote to send everything.",
            def.host()
        );
    }
    let state_dir = match &args.state_dir {
        Some(d) => d.clone(),
        None => PathBuf::from(std::env::var("HOME").context("HOME not set")?).join(".local/state/dnom"),
    };
    fs::create_dir_all(&state_dir).with_context(|| format!("create {}", state_dir.display()))?;
    // Generated decoys only make sense for a live run on this machine. Their list is a
    // tripwire like the config.
    let live_here = args.input.is_none() && !args.remote_source;
    let decoy_config = config.decoys.clone();
    // A replayed recording is old news: it alerts only when asked to.
    let mut notifier = match args.input.is_none() || args.notify {
        true => Notifier::from_config(&config.notify, args.remote_source)?,
        false => None,
    };
    if live_here {
        let list = Planted::state_path(&state_dir);
        config.paths.own_config.push(std::path::absolute(&list).unwrap_or(list).to_string_lossy().into_owned());
    }
    let baseline_path = state_dir.join("baseline.json");
    let log_path = state_dir.join("assessments.jsonl");

    let assessment = config.assessment.clone();
    let policies = config.policies.compile(&assessment)?;
    let model = args.model.as_deref();
    let backend: Option<Box<dyn Backend>> = match &selected {
        None => None,
        Some((name, def)) => Some(match def.kind {
            BackendType::Systemone => Box::new(SystemOne::new(name, def, model, assessment.clone())?),
            BackendType::Openai => Box::new(OpenAi::new(name, def, model, assessment.clone())?),
            BackendType::Ollama => Box::new(Local::new(name, def, model, assessment.clone())?),
        }),
    };
    let backend_label = match &selected {
        None => "none (dry run)".to_string(),
        Some((name, def)) => format!("{name} ({} at {})", model.unwrap_or(&def.model), def.host()),
    };
    // (name, host) of a backend on another machine; drives the startup notice below.
    let remote_target = selected
        .as_ref()
        .filter(|(_, def)| def.is_remote())
        .map(|(name, def)| (name.clone(), def.host().to_string()));

    let (baseline, had_baseline) = Baseline::load(&baseline_path);
    let replay = args.input.is_some();
    let rx = spawn_reader(args.input.clone(), args.source)?;
    let ignore_count = config.ignore.len();

    for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
        unsafe { libc::signal(signal, on_sigint as *const () as libc::sighandler_t) };
    }

    let home = args.home.clone().unwrap_or_else(|| std::env::var("HOME").unwrap_or_default());
    let _ = HOME.set(home.trim_end_matches('/').to_string());
    let mut tracker = Tracker::new(config, baseline, 0);
    if args.remote_source {
        tracker = tracker.remote();
    }
    // Planted last, once nothing else can fail on the way to the loop; removed when `planted`
    // is dropped, on every way out of this function.
    let mut planted = match std::env::var_os("HOME") {
        Some(home) if live_here => Planted::start(&state_dir, Path::new(&home), &decoy_config.auto)?,
        _ => None,
    };
    if let Some(p) = &planted {
        tracker.set_generated_decoys(p.paths());
        eprintln!("dnom classify: decoys planted: {}; removed when dnom stops", p.summary());
    }
    let (exes, dests) = tracker.baseline.len();
    eprintln!(
        "dnom classify: backend={} config={} questions={} policies={} (dry run) ignore_rules={} baseline={} exes/{} destinations{}",
        backend_label,
        config_path.map(|p| p.display().to_string()).unwrap_or_else(|| "defaults".into()),
        assessment.questions.len(),
        policies.len(),
        ignore_count,
        exes,
        dests,
        if had_baseline { String::new() } else { format!(", learning for {} s", args.learn) },
    );

    if let Some(only) = &args.only {
        eprintln!("dnom classify: only assessing episodes whose command contains '{only}'");
    } else if let Some((name, host)) = &remote_target {
        eprintln!(
            "dnom classify: sending every assessed episode to {name} at {host} (commands, file \
             paths, destinations; home shortened to ~, secrets in command lines redacted)"
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
            assessed_total +=
                tick(&mut tracker, &args, backend.as_deref(), &assessment.questions, &policies, &mut log, notifier.as_mut(), now_ms, ended)?;
            if let Some(n) = &mut notifier {
                n.flush();
            }
            next_tick = Some(now_ms + interval_ms);
        }
        if !replay && last_status.elapsed() >= Duration::from_secs(15) {
            status(&tracker, &counts, assessed_total, now_ms);
            last_status = Instant::now();
        }
        if last_save.elapsed() > Duration::from_secs(30) {
            tracker.baseline.save(&baseline_path)?;
            last_save = Instant::now();
            if let Some(p) = &mut planted
                && p.rotation_due(decoy_config.rotate_days)
            {
                p.rotate()?;
                tracker.set_generated_decoys(p.paths());
                eprintln!("dnom classify: decoys rotated: {} new", p.summary());
            }
        }
        if ended {
            break;
        }
    }
    drop(planted);
    if let Some(n) = &mut notifier {
        n.flush();
        if n.waiting() > 0 {
            eprintln!("dnom classify: {} alerts were not delivered (they are in the log: dnom audit --threats)", n.waiting());
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

/// Reads JSON lines on a thread so model calls never block event intake.
fn spawn_reader(input: Option<PathBuf>, source: Source) -> anyhow::Result<mpsc::Receiver<Event>> {
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
            let parsed = match source {
                Source::Dnom => serde_json::from_str::<Event>(&line).map(|e| vec![e]).map_err(anyhow::Error::from),
                Source::Falco => crate::falco::parse_line(&line),
            };
            match parsed {
                Ok(events) => {
                    if events.into_iter().any(|e| tx.send(e).is_err()) {
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
    questions: &[Question],
    policies: &Policies,
    log: &mut File,
    mut notifier: Option<&mut Notifier>,
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
    // The budget bounds model calls per tick. When the input has ended there is no next tick,
    // so everything still waiting is assessed now instead of being silently dropped.
    let budget = if final_tick { usize::MAX } else { args.budget };
    let waiting = ready.len().saturating_sub(budget);
    let mut assessed = 0;

    for &(_, _, root) in ready.iter().take(budget) {
        let Some(ep) = tracker.episodes.get_mut(&root) else { continue };
        let version = ep.version;
        // The full record goes to the policies and the log; the model gets its own view of it
        // (no decoy marking, no audit trail).
        let episode_json = ep.to_json(tracker_home());
        let result = match backend {
            None => None,
            Some(b) => {
                let started = Instant::now();
                match b.assess(&crate::episode::model_view(&episode_json)) {
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
        let matches = policies.evaluate(&episode_json, result.as_ref().map(|(_, a, _)| &a.answers));
        let record = if !args.matches_only || !matches.is_empty() {
            report(ep, &episode_json, result.as_ref(), questions, &matches, args.json, log)?
        } else {
            log_record(ep, &episode_json, result.as_ref(), &matches, log)?
        };
        if let Some(n) = notifier.as_deref_mut() {
            n.offer(&record);
        }
        assessed += 1;
    }
    if waiting > 0 {
        eprintln!("dnom classify: {waiting} episodes waiting for the next tick (budget {})", args.budget);
    }
    tracker.gc(now_ms, args.idle * 1000, 600_000);
    Ok(assessed)
}

/// Home directory shortened to ~ in episodes; set once at startup.
static HOME: std::sync::OnceLock<String> = std::sync::OnceLock::new();

fn tracker_home() -> &'static str {
    HOME.get().map(String::as_str).unwrap_or("")
}

fn report(
    ep: &Episode,
    episode_json: &Value,
    result: Option<&(&str, Assessment, Duration)>,
    questions: &[Question],
    matches: &[Match],
    as_json: bool,
    log: &mut File,
) -> anyhow::Result<Value> {
    let record = log_record(ep, episode_json, result, matches, log)?;

    let mut out = io::stdout().lock();
    if as_json {
        writeln!(out, "{record}")?;
        out.flush()?;
        return Ok(record);
    }
    let header = match result {
        Some((backend, a, took)) => format!("[{backend} {} {:.1}s]", a.model, took.as_secs_f64()),
        None => "[dry run]".into(),
    };
    writeln!(out, "\n{}  {}  {}  uid={}  {header}", clock(ep.last_ms), ep.id, ep.label(), ep.root_uid)?;
    writeln!(out, "  cmd:   {}", episode_json["root"]["argv"].as_str().unwrap_or(""))?;
    for m in matches {
        let actions: Vec<&str> = m.actions.iter().map(|a| a.name()).collect();
        let values: Vec<String> = m.values.iter().map(|(k, v)| format!("{k}={v}")).collect();
        let protected = if m.protected { " (protected program: would skip all but alert)" } else { "" };
        writeln!(out, "  WOULD: {} → {}{protected}   [{}]", m.rule, actions.join(", "), values.join(" "))?;
    }
    report_body(episode_json, result, questions, &mut out)?;
    out.flush()?;
    Ok(record)
}

/// Appends the assessment (with policy matches) to assessments.jsonl and returns it.
fn log_record(
    ep: &Episode,
    episode_json: &Value,
    result: Option<&(&str, Assessment, Duration)>,
    matches: &[Match],
    log: &mut File,
) -> anyhow::Result<Value> {
    let policy: Vec<Value> = matches.iter().map(Match::to_json).collect();
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
            "policy": policy,
            "episode": episode_json,
        }),
        None => json!({
            "ts": crate::episode::rfc3339(wall_ms()),
            "episode_id": ep.id,
            "backend": "none",
            "policy": policy,
            "episode": episode_json,
        }),
    };
    // Dry runs (no model) are logged only when a rule matched, so the log stays useful.
    if result.is_some() || !matches.is_empty() {
        writeln!(log, "{record}")?;
    }
    Ok(record)
}

/// Model answers, files, network and flags of an episode, for the text summary.
fn report_body(
    episode_json: &Value,
    result: Option<&(&str, Assessment, Duration)>,
    questions: &[Question],
    out: &mut impl Write,
) -> anyhow::Result<()> {
    if let Some((_, a, _)) = result {
        let mut parts = Vec::new();
        for q in questions {
            match a.answers.get(&q.id) {
                Some(Answer::Noul { noul }) => {
                    let mark = if q.highlighted(*noul) { "!" } else { " " };
                    parts.push(format!("{mark}{} {noul:.2}", q.label()));
                }
                Some(Answer::Choice { choice, confidence, .. }) => {
                    parts.push(format!(" {}={choice} ({confidence:.2})", q.label()));
                }
                Some(Answer::Score { score, .. }) => {
                    let top = q.levels.len().saturating_sub(1);
                    parts.push(format!(" {}={score:.1}/{top}", q.label()));
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
    let decoys: Vec<&str> = episode_json["decoy_destinations"].as_array().into_iter().flatten().filter_map(|d| d.as_str()).collect();
    if !decoys.is_empty() {
        writeln!(out, "  decoy: connect {}", decoys.join(", "))?;
    }
    let flags: Vec<&str> = episode_json["flags"].as_array().into_iter().flatten().filter_map(|f| f.as_str()).collect();
    if !flags.is_empty() {
        writeln!(out, "  flags: {}", flags.join(", "))?;
    }
    if result.is_none() {
        writeln!(out, "  procs: {}", episode_json["tree"].as_array().map_or(0, |t| t.len()))?;
    }
    Ok(())
}


fn category_label(category: &str) -> &str {
    match category {
        "credentials" => "creds:",
        "persistence" => "persist:",
        "system_binaries" => "bins:",
        "temp" => "temp:",
        "decoys" => "decoy:",
        "dnom_config" => "config:",
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

pub(crate) fn fnv1a(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in bytes {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}
