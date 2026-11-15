//! `dnom dash`: the assessment log as a live dashboard in the terminal.
//!
//! A list of assessed episodes that follows the log, the selected episode in full next to it,
//! and filters over the list: matched rules only, who drives the episode, a time window,
//! words to search for, and a condition in the policy language (to try a rule on what was
//! recorded before it goes into dnom.yaml).
//!
//! It reads `assessments.jsonl` and nothing else, so it needs neither root nor a model, and it
//! works the same on a log copied from another machine. Processes are only looked up in
//! /proc to mark the ones that still run; the dashboard sends no signal and changes nothing.

mod data;
mod theme;
mod view;

use std::{
    io::{IsTerminal, Write as _, stdout},
    path::PathBuf,
    time::{Duration, Instant},
};

use anyhow::ensure;
use clap::Args;
use ratatui::{
    DefaultTerminal,
    crossterm::{
        event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers, MouseButton, MouseEvent, MouseEventKind},
        execute,
    },
    layout::{Position, Rect},
    text::Line,
};

use self::{
    data::{Facets, Feed, Filters, Procs, Sort, Store, now_ms},
    theme::Theme,
};
use crate::{audit, policy::Condition};

#[derive(Args)]
pub struct DashArgs {
    /// Directory holding assessments.jsonl (default ~/.local/state/dnom).
    #[arg(long)]
    state_dir: Option<PathBuf>,
    /// How many episodes to keep in memory (the most recent ones).
    #[arg(long, default_value_t = 5000)]
    keep: usize,
    /// Leave the mouse to the terminal, to select text with it.
    #[arg(long)]
    no_mouse: bool,
    /// Nothing moves: the logo stands still and running episodes get a fixed mark.
    #[arg(long)]
    still: bool,
}

pub fn run(args: DashArgs) -> anyhow::Result<()> {
    ensure!(stdout().is_terminal(), "dnom dash needs a terminal. In a script or a pipe, use: dnom audit");
    let path = audit::log_path(args.state_dir.as_deref())?;
    let mut app = App::new(path, args.keep, args.still);

    let mut terminal = ratatui::init();
    if !args.no_mouse {
        let _ = execute!(stdout(), EnableMouseCapture);
        // ratatui's panic hook puts the screen back; the mouse has to be given back too.
        let hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let _ = execute!(stdout(), DisableMouseCapture);
            hook(info);
        }));
    }
    let result = app.run(&mut terminal);
    if !args.no_mouse {
        let _ = execute!(stdout(), DisableMouseCapture);
    }
    ratatui::restore();
    result
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Focus {
    List,
    Detail,
}

/// One line of the list: a day heading or an episode.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Row {
    Day(String),
    Episode(u64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InputKind {
    Search,
    Where,
}

/// The line being typed: search words or a condition.
pub(crate) struct Input {
    pub kind: InputKind,
    pub text: String,
    /// Cursor position, in characters.
    pub cursor: usize,
    /// What the filter was before, for Esc.
    before: String,
    pub error: Option<String>,
    /// Position in the history while going through it with the arrow keys.
    recall: Option<usize>,
}

/// Something the mouse can click.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum Hit {
    Episode(u64),
    List,
    Detail,
    Flagged,
    Who(usize),
    Since,
    Sort,
    Search,
    Where,
    Clear,
}

pub(crate) struct Toast {
    pub text: String,
    pub alarm: bool,
    until: Instant,
}

/// The detail pane's lines, kept until what they show changes.
#[derive(Default)]
pub(crate) struct DetailCache {
    pub stamp: Option<(u64, u64, u64, u16, bool)>,
    pub lines: Vec<Line<'static>>,
}

pub(crate) struct App {
    pub feed: Feed,
    pub store: Store,
    pub theme: Theme,
    pub filters: Filters,
    pub sort: Sort,
    /// Episodes the filters let through, in display order.
    pub view: Vec<u64>,
    pub rows: Vec<Row>,
    pub facets: Facets,
    pub selected: Option<u64>,
    /// The selection stays on the newest episode as new ones arrive.
    pub follow: bool,
    /// Episodes that arrived above the selection since `follow` went off.
    pub unseen: usize,
    seen_seq: u64,
    pub focus: Focus,
    /// The detail takes the whole width.
    pub zoom: bool,
    /// The stored record as JSON instead of the readable view.
    pub raw: bool,
    pub banner: bool,
    pub help: bool,
    pub input: Option<Input>,
    history: Vec<String>,
    pub toast: Option<Toast>,
    pub still: bool,
    /// Animation step, 8 a second.
    pub frame: u64,
    pub now_ms: u64,
    // Kept by the drawing code between frames.
    pub list_top: usize,
    pub list_height: usize,
    pub detail_scroll: usize,
    pub detail_height: usize,
    pub detail_lines: usize,
    pub detail: DetailCache,
    pub hits: Vec<(Rect, Hit)>,
    /// Both panes fit side by side (set while drawing).
    pub wide: bool,
    started: Instant,
    quit: bool,
}

const TICK: Duration = Duration::from_millis(125);

impl App {
    pub fn new(path: PathBuf, keep: usize, still: bool) -> Self {
        let mut app = Self {
            feed: Feed::new(path),
            store: Store::new(keep),
            theme: Theme::detect(),
            filters: Filters::default(),
            sort: Sort::Newest,
            view: Vec::new(),
            rows: Vec::new(),
            facets: Facets::default(),
            selected: None,
            follow: true,
            unseen: 0,
            seen_seq: 0,
            focus: Focus::List,
            zoom: false,
            raw: false,
            banner: true,
            help: false,
            input: None,
            history: Vec::new(),
            toast: None,
            still,
            frame: 0,
            now_ms: now_ms(),
            list_top: 0,
            list_height: 10,
            detail_scroll: 0,
            detail_height: 10,
            detail_lines: 0,
            detail: DetailCache::default(),
            hits: Vec::new(),
            wide: true,
            started: Instant::now(),
            quit: false,
        };
        // What is already in the log is history: no alarms for it.
        app.feed.pull(&mut app.store);
        app.store.refresh_alive(&Procs::now(), app.now_ms);
        app.recompute();
        app
    }

    fn run(&mut self, terminal: &mut DefaultTerminal) -> anyhow::Result<()> {
        let (mut pulled, mut second) = (Instant::now(), Instant::now());
        let mut dirty = true;
        loop {
            if dirty {
                terminal.draw(|frame| view::draw(self, frame))?;
                dirty = false;
            }
            if self.quit {
                return Ok(());
            }
            // Something on screen moves 8 times a second; without it, twice is enough.
            let moving = !self.still && (self.banner_moves() || self.store.all().any(|e| !e.alive.is_empty()));
            if event::poll(if moving { TICK } else { TICK * 4 })? {
                loop {
                    match event::read()? {
                        Event::Key(key) if key.kind != KeyEventKind::Release => self.on_key(key),
                        Event::Mouse(mouse) => self.on_mouse(mouse),
                        _ => {}
                    }
                    if !event::poll(Duration::ZERO)? {
                        break;
                    }
                }
                dirty = true;
            }
            let frame = (self.started.elapsed().as_millis() / TICK.as_millis()) as u64;
            if moving && frame != self.frame {
                dirty = true;
            }
            self.frame = frame;
            if pulled.elapsed() >= Duration::from_millis(500) {
                pulled = Instant::now();
                dirty |= self.pull();
            }
            if second.elapsed() >= Duration::from_secs(1) {
                second = Instant::now();
                self.every_second();
                dirty = true;
            }
        }
    }

    /// The header's helix turns only while the log is being written.
    fn banner_moves(&self) -> bool {
        self.store.last_ms.is_some_and(|t| self.now_ms.saturating_sub(t) < 120_000)
    }

    /// Which step of its turn the logo's helix is at.
    pub fn turn(&self) -> u64 {
        if self.still || !self.banner_moves() { 4 } else { self.frame / 2 }
    }

    /// Reads what was added to the log. True when the screen has to change.
    fn pull(&mut self) -> bool {
        let had_error = self.feed.error.is_some();
        let arrived = self.feed.pull(&mut self.store);
        if !arrived.any() {
            return had_error != self.feed.error.is_some();
        }
        if let Some((key, rule)) = arrived.threats.last() {
            let command = self.store.get(*key).map(|e| e.command.clone()).unwrap_or_default();
            let more = if arrived.threats.len() > 1 { format!(" (+{} more)", arrived.threats.len() - 1) } else { String::new() };
            self.say(format!("rule matched: {rule}{more} · {command}"), true);
        }
        self.recompute();
        true
    }

    fn every_second(&mut self) {
        self.now_ms = now_ms();
        if self.toast.as_ref().is_some_and(|t| Instant::now() >= t.until) {
            self.toast = None;
        }
        self.store.refresh_alive(&Procs::now(), self.now_ms);
        if self.filters.since != data::Since::All {
            self.recompute();
        }
    }

    pub fn say(&mut self, text: String, alarm: bool) {
        self.toast = Some(Toast { text, alarm, until: Instant::now() + Duration::from_secs(if alarm { 12 } else { 4 }) });
    }

    /// Applies filters and order again, and keeps the selection on its episode.
    pub fn recompute(&mut self) {
        let (view, facets) = self.store.view(&self.filters, self.sort, self.now_ms);
        self.view = view;
        self.facets = facets;
        self.rows = self.day_rows();
        let wanted = match self.selected {
            Some(key) if !self.follow && self.view.contains(&key) => Some(key),
            _ => self.view.first().copied(),
        };
        self.select(wanted);
        if self.follow {
            self.seen_seq = self.newest_seq();
        }
        self.unseen = self.view.iter().filter_map(|k| self.store.get(*k)).filter(|e| e.seq > self.seen_seq).count();
    }

    fn newest_seq(&self) -> u64 {
        self.store.all().map(|e| e.seq).max().unwrap_or(0)
    }

    fn day_rows(&self) -> Vec<Row> {
        let mut rows = Vec::with_capacity(self.view.len() + 4);
        let mut day = String::new();
        for key in &self.view {
            // By risk, the days are mixed: the row shows its date instead.
            if self.sort == Sort::Newest
                && let Some(ep) = self.store.get(*key)
            {
                let this = view::day_label(ep.at_ms, self.now_ms);
                if this != day {
                    rows.push(Row::Day(this.clone()));
                    day = this;
                }
            }
            rows.push(Row::Episode(*key));
        }
        rows
    }

    fn select(&mut self, key: Option<u64>) {
        if key != self.selected {
            self.detail_scroll = 0;
        }
        self.selected = key;
    }

    pub fn selected_index(&self) -> Option<usize> {
        self.selected.and_then(|key| self.view.iter().position(|k| *k == key))
    }

    fn select_index(&mut self, index: usize) {
        let Some(key) = self.view.get(index.min(self.view.len().saturating_sub(1))).copied() else { return };
        self.select(Some(key));
        self.follow = self.sort == Sort::Newest && self.view.first() == Some(&key);
        if self.follow {
            self.seen_seq = self.newest_seq();
            self.unseen = 0;
        }
    }

    fn move_selection(&mut self, by: isize) {
        let at = self.selected_index().unwrap_or(0) as isize;
        self.select_index((at + by).max(0) as usize);
    }

    fn scroll_detail(&mut self, by: isize) {
        let last = self.detail_lines.saturating_sub(self.detail_height);
        self.detail_scroll = (self.detail_scroll as isize + by).clamp(0, last as isize) as usize;
    }

    /// Arrow keys and paging act on the pane that has the focus.
    fn travel(&mut self, by: isize) {
        match self.focus {
            Focus::List => self.move_selection(by),
            Focus::Detail => self.scroll_detail(by),
        }
    }

    /// To the next episode with a matched rule, below (`down`) or above the selection.
    fn jump_flagged(&mut self, down: bool) {
        let at = self.selected_index().unwrap_or(0);
        let flagged = |key: &u64| self.store.get(*key).is_some_and(|e| e.flagged());
        let found = if down {
            self.view.iter().enumerate().skip(at + 1).find(|(_, k)| flagged(k)).map(|(i, _)| i)
        } else {
            self.view.iter().enumerate().take(at).rev().find(|(_, k)| flagged(k)).map(|(i, _)| i)
        };
        match found {
            Some(index) => self.select_index(index),
            None => self.say(format!("no flagged episode {} this one", if down { "below" } else { "above" }), false),
        }
    }

    fn toggle_filter(&mut self, hit: Hit) {
        match hit {
            Hit::Flagged => self.filters.flagged = !self.filters.flagged,
            Hit::Who(i) if i < self.filters.who.len() => self.filters.who[i] = !self.filters.who[i],
            Hit::Since => self.filters.since = self.filters.since.next(),
            Hit::Sort => self.sort = self.sort.next(),
            Hit::Search => return self.open_input(InputKind::Search),
            Hit::Where => return self.open_input(InputKind::Where),
            Hit::Clear => self.filters.clear(),
            _ => return,
        }
        // The list changed under the selection: start from its top again.
        self.follow = self.sort == Sort::Newest;
        self.recompute();
        if let Some(first) = self.view.first().copied() {
            self.select(Some(first));
        }
        self.list_top = 0;
    }

    fn open_input(&mut self, kind: InputKind) {
        let text = match kind {
            InputKind::Search => self.filters.search.clone(),
            InputKind::Where => self.filters.condition.as_ref().map(|(text, _)| text.clone()).unwrap_or_default(),
        };
        self.input = Some(Input { kind, cursor: text.chars().count(), before: text.clone(), text, error: None, recall: None });
    }

    /// Filters by what is typed so far. A condition that does not parse yet keeps the last
    /// one that did, and says what is wrong.
    fn apply_input(&mut self) {
        let Some(input) = self.input.as_mut() else { return };
        match input.kind {
            InputKind::Search => self.filters.search = input.text.clone(),
            InputKind::Where if input.text.trim().is_empty() => {
                self.filters.condition = None;
                input.error = None;
            }
            InputKind::Where => match Condition::parse(&input.text, &self.store.assessment) {
                Ok(condition) => {
                    self.filters.condition = Some((input.text.clone(), condition));
                    input.error = None;
                }
                Err(e) => input.error = Some(e.to_string()),
            },
        }
        self.follow = self.sort == Sort::Newest;
        self.recompute();
        self.list_top = 0;
    }

    fn on_input_key(&mut self, key: KeyEvent) {
        let Some(input) = self.input.as_mut() else { return };
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        let at = |text: &str, chars: usize| text.char_indices().nth(chars).map_or(text.len(), |(i, _)| i);
        let len = input.text.chars().count();
        match key.code {
            KeyCode::Esc => {
                input.text = input.before.clone();
                self.apply_input();
                self.input = None;
                return;
            }
            KeyCode::Enter => {
                if input.error.is_some() {
                    return;
                }
                if input.kind == InputKind::Where && !input.text.trim().is_empty() {
                    let text = input.text.trim().to_string();
                    self.history.retain(|h| *h != text);
                    self.history.push(text);
                }
                self.input = None;
                return;
            }
            KeyCode::Left => input.cursor = input.cursor.saturating_sub(1),
            KeyCode::Right => input.cursor = (input.cursor + 1).min(len),
            KeyCode::Home => input.cursor = 0,
            KeyCode::End => input.cursor = len,
            KeyCode::Char('a') if ctrl => input.cursor = 0,
            KeyCode::Char('e') if ctrl => input.cursor = len,
            KeyCode::Char('u') if ctrl => {
                input.text.drain(..at(&input.text, input.cursor));
                input.cursor = 0;
            }
            KeyCode::Char('w') if ctrl => {
                // Back over spaces, then over the word before them.
                let chars: Vec<char> = input.text.chars().collect();
                let mut start = input.cursor;
                while start > 0 && chars[start - 1] == ' ' {
                    start -= 1;
                }
                while start > 0 && chars[start - 1] != ' ' {
                    start -= 1;
                }
                input.text.drain(at(&input.text, start)..at(&input.text, input.cursor));
                input.cursor = start;
            }
            KeyCode::Backspace if input.cursor > 0 => {
                input.text.remove(at(&input.text, input.cursor - 1));
                input.cursor -= 1;
            }
            KeyCode::Delete if input.cursor < len => {
                input.text.remove(at(&input.text, input.cursor));
            }
            KeyCode::Up | KeyCode::Down if input.kind == InputKind::Where && !self.history.is_empty() => {
                let last = self.history.len() - 1;
                let next = match (input.recall, key.code) {
                    (None, KeyCode::Up) => Some(last),
                    (Some(i), KeyCode::Up) => Some(i.saturating_sub(1)),
                    (Some(i), _) if i < last => Some(i + 1),
                    _ => None,
                };
                input.recall = next;
                input.text = next.map(|i| self.history[i].clone()).unwrap_or_default();
                input.cursor = input.text.chars().count();
            }
            KeyCode::Char(c) if !ctrl && !c.is_control() => {
                input.text.insert(at(&input.text, input.cursor), c);
                input.cursor += 1;
            }
            _ => return,
        }
        self.apply_input();
    }

    pub(crate) fn on_key(&mut self, key: KeyEvent) {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        if ctrl && key.code == KeyCode::Char('c') {
            self.quit = true;
            return;
        }
        if self.help {
            self.help = false;
            return;
        }
        if self.input.is_some() {
            return self.on_input_key(key);
        }
        let page = match self.focus {
            Focus::List => self.list_height,
            Focus::Detail => self.detail_height,
        }
        .saturating_sub(2)
        .max(1) as isize;
        match key.code {
            KeyCode::Char('q') => self.quit = true,
            KeyCode::Char('?') => self.help = true,
            KeyCode::Up | KeyCode::Char('k') => self.travel(-1),
            KeyCode::Down | KeyCode::Char('j') => self.travel(1),
            KeyCode::PageUp => self.travel(-page),
            KeyCode::PageDown | KeyCode::Char(' ') => self.travel(page),
            KeyCode::Char('u') if ctrl => self.travel(-page / 2),
            KeyCode::Char('d') if ctrl => self.travel(page / 2),
            KeyCode::Home | KeyCode::Char('g') => self.travel(isize::MIN / 2),
            KeyCode::End | KeyCode::Char('G') => self.travel(isize::MAX / 2),
            KeyCode::Char('K') => self.scroll_detail(-3),
            KeyCode::Char('J') => self.scroll_detail(3),
            KeyCode::Char('n') => self.jump_flagged(true),
            KeyCode::Char('N') => self.jump_flagged(false),
            KeyCode::Tab | KeyCode::BackTab => self.set_focus(if self.focus == Focus::List { Focus::Detail } else { Focus::List }),
            KeyCode::Right | KeyCode::Char('l') => self.set_focus(Focus::Detail),
            KeyCode::Left | KeyCode::Char('h') => self.set_focus(Focus::List),
            KeyCode::Enter => match self.focus {
                Focus::List => self.set_focus(Focus::Detail),
                Focus::Detail => self.zoom = !self.zoom,
            },
            KeyCode::Esc => {
                if self.zoom {
                    self.zoom = false;
                } else {
                    self.set_focus(Focus::List);
                }
            }
            KeyCode::Char('z') => {
                self.zoom = !self.zoom;
                if self.zoom && self.selected.is_some() {
                    self.focus = Focus::Detail;
                }
            }
            KeyCode::Char('f') => self.toggle_filter(Hit::Flagged),
            KeyCode::Char(c @ '1'..='5') => self.toggle_filter(Hit::Who(c as usize - '1' as usize)),
            KeyCode::Char('t') => self.toggle_filter(Hit::Since),
            KeyCode::Char('s') => self.toggle_filter(Hit::Sort),
            KeyCode::Char('/') => self.open_input(InputKind::Search),
            KeyCode::Char('w') => self.open_input(InputKind::Where),
            KeyCode::Char('x') if self.filters.active() > 0 => self.toggle_filter(Hit::Clear),
            KeyCode::Char('r') => {
                self.raw = !self.raw;
                self.detail_scroll = 0;
            }
            KeyCode::Char('b') => self.banner = !self.banner,
            KeyCode::Char('y') => self.copy(false),
            KeyCode::Char('Y') => self.copy(true),
            _ => {}
        }
    }

    fn set_focus(&mut self, focus: Focus) {
        if focus == Focus::Detail && self.selected.is_none() {
            return;
        }
        self.focus = focus;
        if focus == Focus::List {
            self.zoom = false;
        }
    }

    pub(crate) fn on_mouse(&mut self, mouse: MouseEvent) {
        if self.help {
            if matches!(mouse.kind, MouseEventKind::Down(_)) {
                self.help = false;
            }
            return;
        }
        let at = Position::new(mouse.column, mouse.row);
        // Later entries lie on top of earlier ones.
        let Some(hit) = self.hits.iter().rev().find(|(area, _)| area.contains(at)).map(|(_, hit)| *hit) else { return };
        let over_list = matches!(hit, Hit::Episode(_) | Hit::List);
        match mouse.kind {
            MouseEventKind::ScrollUp | MouseEventKind::ScrollDown => {
                let down = mouse.kind == MouseEventKind::ScrollDown;
                match hit {
                    Hit::Detail => self.scroll_detail(if down { 3 } else { -3 }),
                    _ if over_list => self.move_selection(if down { 1 } else { -1 }),
                    _ => {}
                }
            }
            MouseEventKind::Down(MouseButton::Left) => match hit {
                Hit::Episode(key) => {
                    if self.input.is_none() {
                        self.focus = Focus::List;
                        if let Some(index) = self.view.iter().position(|k| *k == key) {
                            self.select_index(index);
                        }
                    }
                }
                Hit::List => self.set_focus(Focus::List),
                Hit::Detail => self.set_focus(Focus::Detail),
                chip if self.input.is_none() => self.toggle_filter(chip),
                _ => {}
            },
            _ => {}
        }
    }

    /// Puts the command (or the episode id) of the selected episode on the clipboard.
    fn copy(&mut self, id: bool) {
        let Some(ep) = self.selected.and_then(|key| self.store.get(key)) else { return };
        let text = if id { ep.id.clone() } else { ep.command.clone() };
        // OSC 52: the terminal sets the clipboard, which also works over SSH.
        let mut out = stdout();
        let _ = write!(out, "\x1b]52;c;{}\x07", base64(text.as_bytes()));
        let _ = out.flush();
        self.say(format!("{} sent to the clipboard", if id { "episode id" } else { "command" }), false);
    }
}

fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = (chunk[0] as u32) << 16 | (*chunk.get(1).unwrap_or(&0) as u32) << 8 | *chunk.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use ratatui::{Terminal, backend::TestBackend};

    use super::{data::tests::record, *};

    /// An app over a log file with the given records.
    pub(crate) fn app_with(name: &str, records: &[serde_json::Value]) -> App {
        let dir = std::env::temp_dir().join(format!("dnom-dash-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("assessments.jsonl");
        let text: String = records.iter().map(|r| format!("{r}\n")).collect();
        std::fs::write(&path, text).unwrap();
        let mut app = App::new(path, 1000, true);
        app.theme = Theme::plain();
        app
    }

    pub(crate) fn sample_records() -> Vec<serde_json::Value> {
        vec![
            record("ep-1", 10, "bash -i", "foot", &["credential-theft", "exfiltration"], Some((0.95, 0.1))),
            record("ep-2", 20, "claude --resume", "bash", &[], Some((0.3, 0.9))),
            record("ep-3", 30, "backup.sh --nightly", "cron", &[], None),
            record("ep-4", 40, "sshd-session: deploy", "sshd", &["credentials-then-new-destination"], Some((0.75, 0.5))),
        ]
    }

    pub(crate) fn screen(app: &mut App, width: u16, height: u16) -> String {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal.draw(|frame| view::draw(app, frame)).unwrap();
        let buffer = terminal.backend().buffer().clone();
        (0..height).map(|y| (0..width).map(|x| buffer[(x, y)].symbol()).collect::<String>().trim_end().to_string() + "\n").collect()
    }

    fn press(app: &mut App, keys: &str) {
        for c in keys.chars() {
            let code = match c {
                '\n' => KeyCode::Enter,
                '\x1b' => KeyCode::Esc,
                '\t' => KeyCode::Tab,
                '↓' => KeyCode::Down,
                '↑' => KeyCode::Up,
                c => KeyCode::Char(c),
            };
            app.on_key(KeyEvent::new(code, KeyModifiers::NONE));
        }
    }

    fn selected(app: &App) -> String {
        app.selected.and_then(|k| app.store.get(k)).map(|e| e.id.clone()).unwrap_or_default()
    }

    fn append(app: &mut App, record: serde_json::Value) {
        let mut log = std::fs::OpenOptions::new().append(true).open(&app.feed.path).unwrap();
        writeln!(log, "{record}").unwrap();
        app.pull();
    }

    #[test]
    fn the_selection_follows_the_newest_until_the_user_moves_away() {
        let mut app = app_with("follow", &sample_records());
        assert_eq!((selected(&app), app.follow), ("ep-4".to_string(), true));
        append(&mut app, record("ep-5", 50, "make test", "foot", &[], None));
        assert_eq!((selected(&app), app.unseen), ("ep-5".to_string(), 0));

        // Moved down: the selection stays on its episode, new arrivals are counted.
        press(&mut app, "j");
        assert_eq!((selected(&app), app.follow), ("ep-4".to_string(), false));
        append(&mut app, record("ep-6", 60, "ls", "foot", &["decoy-touched"], None));
        append(&mut app, record("ep-7", 70, "ls", "foot", &[], None));
        assert_eq!((selected(&app), app.unseen), ("ep-4".to_string(), 2));
        let toast = app.toast.as_ref().unwrap();
        assert!(toast.alarm && toast.text.contains("decoy-touched"), "{}", toast.text);

        // Back to the top: following again.
        press(&mut app, "g");
        assert_eq!((selected(&app), app.follow, app.unseen), ("ep-7".to_string(), true, 0));
        let _ = std::fs::remove_dir_all(app.feed.path.parent().unwrap());
    }

    #[test]
    fn keys_filter_the_list() {
        let mut app = app_with("keys", &sample_records());
        press(&mut app, "f");
        assert_eq!(app.view.len(), 2);
        press(&mut app, "2");
        assert_eq!((app.view.len(), selected(&app)), (1, "ep-4".to_string()));
        press(&mut app, "x");
        assert_eq!((app.view.len(), app.filters.active()), (4, 0));
        // x does nothing without filters (it must not surprise).
        press(&mut app, "x");
        assert_eq!(app.view.len(), 4);

        // Search narrows while typing; Esc puts back what was there before.
        press(&mut app, "/back");
        assert_eq!((app.view.len(), selected(&app)), (1, "ep-3".to_string()));
        press(&mut app, "\x1b");
        assert_eq!((app.view.len(), app.input.is_none()), (4, true));
        press(&mut app, "/claude\n");
        assert_eq!((app.view.len(), app.filters.search.as_str(), app.input.is_none()), (1, "claude", true));
        press(&mut app, "x");

        // A condition that does not parse keeps the input open and says why.
        press(&mut app, "wdriver == \"agent\n");
        let input = app.input.as_ref().expect("still typing");
        assert!(input.error.as_ref().is_some_and(|e| e.contains("unclosed")), "{:?}", input.error);
        press(&mut app, "\"\n");
        assert_eq!((app.view.len(), selected(&app), app.input.is_none()), (1, "ep-2".to_string(), true));
        // The condition is in the history for the next time.
        press(&mut app, "xw↑");
        assert_eq!(app.input.as_ref().unwrap().text, "driver == \"agent\"");
        press(&mut app, "\x1b");

        // n and N jump between flagged episodes.
        press(&mut app, "xgn");
        assert_eq!(selected(&app), "ep-1");
        press(&mut app, "N");
        assert_eq!(selected(&app), "ep-4");
        // s sorts by risk: the planted theft first.
        press(&mut app, "s");
        assert_eq!((app.sort, selected(&app)), (Sort::Risk, "ep-1".to_string()));
        let _ = std::fs::remove_dir_all(app.feed.path.parent().unwrap());
    }

    #[test]
    fn typing_edits_at_the_cursor() {
        let mut app = app_with("typing", &sample_records());
        press(&mut app, "/héllo wörld");
        let key = |app: &mut App, code, modifiers| app.on_key(KeyEvent::new(code, modifiers));
        key(&mut app, KeyCode::Left, KeyModifiers::NONE);
        key(&mut app, KeyCode::Backspace, KeyModifiers::NONE);
        assert_eq!(app.input.as_ref().unwrap().text, "héllo wörd");
        key(&mut app, KeyCode::Char('w'), KeyModifiers::CONTROL);
        assert_eq!(app.input.as_ref().unwrap().text, "héllo d");
        key(&mut app, KeyCode::Home, KeyModifiers::NONE);
        key(&mut app, KeyCode::Delete, KeyModifiers::NONE);
        press(&mut app, "j");
        assert_eq!(app.input.as_ref().unwrap().text, "jéllo d");
        key(&mut app, KeyCode::End, KeyModifiers::NONE);
        key(&mut app, KeyCode::Char('u'), KeyModifiers::CONTROL);
        assert_eq!((app.input.as_ref().unwrap().text.as_str(), app.filters.search.as_str()), ("", ""));
        let _ = std::fs::remove_dir_all(app.feed.path.parent().unwrap());
    }

    #[test]
    fn base64_matches_the_standard() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
    }
}
