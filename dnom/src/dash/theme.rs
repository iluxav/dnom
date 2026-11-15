//! Colours and the logo of `dnom dash`.
//!
//! Everything except the logo uses the terminal's own 16 colours, so the dashboard follows
//! the terminal theme (dark or light). Red is kept for one thing: a matched rule.

use ratatui::{
    style::{Color, Modifier, Style},
    text::{Line, Span},
};

use crate::driver::Kind;

#[derive(Debug, Clone, Copy)]
pub struct Theme {
    /// False under NO_COLOR: bold, dim and reverse only.
    color: bool,
    /// The terminal takes 24-bit colours (the logo's gradient).
    truecolor: bool,
}

impl Theme {
    pub fn detect() -> Self {
        let color = std::env::var_os("NO_COLOR").is_none();
        let truecolor = std::env::var("COLORTERM").is_ok_and(|v| v.contains("truecolor") || v.contains("24bit"));
        Self { color, truecolor: color && truecolor }
    }

    #[cfg(test)]
    pub fn plain() -> Self {
        Self { color: false, truecolor: false }
    }

    fn fg(self, color: Color) -> Style {
        if self.color { Style::new().fg(color) } else { Style::new() }
    }

    pub fn text(self) -> Style {
        Style::new()
    }

    pub fn bold(self) -> Style {
        Style::new().add_modifier(Modifier::BOLD)
    }

    /// Secondary text.
    pub fn dim(self) -> Style {
        if self.color { Style::new().fg(Color::DarkGray) } else { Style::new().add_modifier(Modifier::DIM) }
    }

    /// The interface's own colour: keys, focus, headings.
    pub fn accent(self) -> Style {
        self.fg(Color::Cyan)
    }

    pub fn key(self) -> Style {
        self.accent().add_modifier(Modifier::BOLD)
    }

    pub fn heading(self) -> Style {
        self.bold()
    }

    /// A matched rule, a decoy touched.
    pub fn threat(self) -> Style {
        self.fg(Color::Red).add_modifier(Modifier::BOLD)
    }

    /// Worth a look: a sensitive file, a new destination, a high score.
    pub fn warn(self) -> Style {
        self.fg(Color::Yellow)
    }

    pub fn good(self) -> Style {
        self.fg(Color::Green)
    }

    pub fn driver(self, kind: Kind) -> Style {
        match kind {
            Kind::Agent => self.fg(Color::Magenta),
            Kind::Remote => self.fg(Color::Blue),
            Kind::Human => self.fg(Color::Green),
            Kind::Automation => self.dim(),
            // Not known is not a warning: yellow stays for what is.
            Kind::Unknown => Style::new(),
        }
    }

    /// The colour a filter chip takes when it is on.
    pub fn driver_chip(self, kind: Kind) -> Color {
        match kind {
            Kind::Agent => Color::Magenta,
            Kind::Remote => Color::Blue,
            Kind::Human => Color::Green,
            Kind::Automation => Color::Gray,
            Kind::Unknown => Color::White,
        }
    }

    /// A filter chip that is on: a solid block in its colour. Reversed, so the text takes the
    /// terminal's background colour and stays readable in dark and in light themes.
    pub fn chip_on(self, color: Color) -> Style {
        self.fg(color).add_modifier(Modifier::REVERSED | Modifier::BOLD)
    }

    /// Laid over the selected row.
    pub fn selected(self) -> Style {
        if self.color { Style::new().bg(Color::DarkGray).add_modifier(Modifier::BOLD) } else { Style::new().add_modifier(Modifier::REVERSED) }
    }

    /// Secondary text on the selected row, where the usual dim colour is the background.
    pub fn dim_on_selected(self) -> Style {
        if self.color { Style::new().fg(Color::Gray) } else { Style::new() }
    }

    pub fn border(self, focused: bool) -> Style {
        if focused { self.accent() } else { self.dim() }
    }

    /// A colour along the logo's gradient, `t` from 0 (start) to 1 (end).
    pub fn gradient(self, t: f32) -> Style {
        let t = t.clamp(0.0, 1.0);
        if !self.color {
            return Style::new().add_modifier(Modifier::BOLD);
        }
        if !self.truecolor {
            let color = if t < 0.34 {
                Color::Cyan
            } else if t < 0.67 {
                Color::Blue
            } else {
                Color::Magenta
            };
            return Style::new().fg(color).add_modifier(Modifier::BOLD);
        }
        // Cyan, through indigo, to pink: readable on dark and on light backgrounds.
        const STOPS: [(f32, f32, f32); 3] = [(34.0, 211.0, 238.0), (129.0, 140.0, 248.0), (232.0, 121.0, 249.0)];
        let scaled = t * (STOPS.len() - 1) as f32;
        let i = (scaled as usize).min(STOPS.len() - 2);
        let f = scaled - i as f32;
        let mix = |a: f32, b: f32| (a + (b - a) * f).round() as u8;
        let (a, b) = (STOPS[i], STOPS[i + 1]);
        Style::new().fg(Color::Rgb(mix(a.0, b.0), mix(a.1, b.1), mix(a.2, b.2))).add_modifier(Modifier::BOLD)
    }
}

/// `dnom` in block letters, five rows.
const WORDMARK: [&str; 5] = [
    "    ██                         ",
    "    ██                         ",
    "▄█████ █████▄ ▄████▄ █████▄███▄",
    "██  ██ ██  ██ ██  ██ ██  ██  ██",
    "▀█████ ██  ██ ▀████▀ ██  ██  ██",
];

pub const LOGO_ROWS: usize = 5;
/// Helix, a gap, the wordmark.
pub const LOGO_WIDTH: u16 = 5 + 2 + 31;

/// The logo: a double helix that turns with `turn`, next to the wordmark.
pub fn logo(theme: Theme, turn: u64) -> Vec<Line<'static>> {
    let helix = helix(theme, turn);
    WORDMARK
        .iter()
        .zip(helix)
        .map(|(row, mut spans)| {
            spans.push(Span::raw("  "));
            let width = row.chars().count().max(2) as f32 - 1.0;
            // One span per run of cells would be shorter; one per cell keeps the gradient smooth.
            spans.extend(row.chars().enumerate().map(|(i, c)| Span::styled(c.to_string(), theme.gradient(i as f32 / width))));
            Line::from(spans)
        })
        .collect()
}

/// A double helix seen from the side, five cells wide and five rows tall. Each step of
/// `turn` rotates it by a sixteenth: the two strands swap sides, the one in front is solid.
fn helix(theme: Theme, turn: u64) -> Vec<Vec<Span<'static>>> {
    let (front_a, front_b) = (theme.gradient(0.0), theme.gradient(1.0));
    let rung = theme.dim();
    (0..LOGO_ROWS)
        .map(|row| {
            let angle = (turn % 16) as f32 * std::f32::consts::TAU / 16.0 + row as f32 * std::f32::consts::FRAC_PI_4;
            let offset = (2.0 * angle.sin()).round() as i32;
            // Depth of strand A: in front above zero. Near zero both are side by side.
            let depth = angle.cos();
            let (a, b) = ((2 + offset) as usize, (2 - offset) as usize);
            let mut cells: Vec<Span<'static>> = (0..5).map(|_| Span::raw(" ")).collect();
            if a == b {
                // The strands cross: the one in front hides the other.
                cells[a] = Span::styled("●", if depth >= 0.0 { front_a } else { front_b });
            } else {
                for cell in &mut cells[a.min(b) + 1..a.max(b)] {
                    *cell = Span::styled("─", rung);
                }
                cells[a] = Span::styled(if depth > -0.3 { "●" } else { "○" }, front_a);
                cells[b] = Span::styled(if depth < 0.3 { "●" } else { "○" }, front_b);
            }
            cells
        })
        .collect()
}

/// The helix as one row of braille dots, for the one-line header: two waves, half a turn
/// apart, moving with `turn`.
pub fn helix_inline(theme: Theme, turn: u64, cells: usize) -> Vec<Span<'static>> {
    let dots = cells * 2;
    let level = |x: usize, flip: bool| {
        let angle = (turn % 16) as f32 * std::f32::consts::TAU / 16.0 + x as f32 * std::f32::consts::TAU / 8.0;
        let s = if flip { -angle.sin() } else { angle.sin() };
        (1.5 + 1.5 * s).round() as usize
    };
    (0..cells)
        .map(|cell| {
            let mut bits = 0u32;
            for column in 0..2 {
                let x = cell * 2 + column;
                for row in [level(x, false), level(x, true)] {
                    bits |= match (column, row) {
                        (0, 0) => 0x01,
                        (0, 1) => 0x02,
                        (0, 2) => 0x04,
                        (0, _) => 0x40,
                        (_, 0) => 0x08,
                        (_, 1) => 0x10,
                        (_, 2) => 0x20,
                        _ => 0x80,
                    };
                }
            }
            let glyph = char::from_u32(0x2800 + bits).unwrap_or(' ');
            Span::styled(glyph.to_string(), theme.gradient(cell as f32 / (dots.max(4) / 2 - 1) as f32))
        })
        .collect()
}

/// A running process: one frame of a spinner.
pub fn spinner(tick: u64) -> &'static str {
    const FRAMES: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
    FRAMES[(tick % FRAMES.len() as u64) as usize]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(line: &Line) -> String {
        line.spans.iter().map(|s| s.content.as_ref()).collect()
    }

    #[test]
    fn logo_rows_are_all_the_same_width() {
        for turn in 0..16 {
            let logo = logo(Theme::plain(), turn);
            assert_eq!(logo.len(), LOGO_ROWS);
            for line in &logo {
                assert_eq!(text(line).chars().count(), LOGO_WIDTH as usize, "turn {turn}: {:?}", text(line));
            }
        }
    }

    #[test]
    fn helix_turns_and_comes_back() {
        let at = |turn| logo(Theme::plain(), turn).iter().map(|l| text(l).chars().take(5).collect::<String>()).collect::<Vec<_>>();
        // A quarter turn in: the strands are widest apart at the top and bottom, and cross in the middle.
        assert_eq!(at(4), ["●───●", " ●─○ ", "  ●  ", " ○─● ", "●───●"]);
        assert_ne!(at(0), at(1));
        assert_eq!(at(0), at(16));
    }

    #[test]
    fn inline_helix_is_braille_of_the_asked_width() {
        for turn in 0..16 {
            let spans = helix_inline(Theme::plain(), turn, 4);
            let s: String = spans.iter().map(|s| s.content.as_ref()).collect();
            assert_eq!(s.chars().count(), 4);
            assert!(s.chars().all(|c| ('\u{2800}'..='\u{28ff}').contains(&c)), "{s:?}");
        }
    }
}
