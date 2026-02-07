use std::collections::{HashMap, VecDeque};
use std::io::{self};
use std::time::{Duration, Instant};

use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEvent};
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use crossterm::{ExecutableCommand, execute};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Gauge, List, ListItem, Paragraph, Row, Sparkline, Table};
use tokio::sync::mpsc::UnboundedReceiver;

#[derive(Debug, Clone)]
pub enum AppEvent {
    Status {
        node_id: String,
        rate: f64,
        processed: u64,
        cracked: u64,
        in_flight: u64,
    },
    Cracked {
        username: String,
        plaintext: String,
    },
    Error {
        code: i32,
        message: String,
    },
    SentBatch {
        count: u64,
    },
    InputDone,
}

pub struct UiOutcome {
    pub quit: bool,
}

struct TerminalGuard;

impl TerminalGuard {
    fn enter() -> Result<Self> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        stdout.execute(EnterAlternateScreen)?;
        Ok(Self)
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let mut stdout = io::stdout();
        let _ = execute!(stdout, LeaveAlternateScreen);
    }
}

#[derive(Clone)]
struct NodeStatus {
    rate: f64,
    processed: u64,
    cracked: u64,
    in_flight: u64,
    last_seen: Instant,
}

impl Default for NodeStatus {
    fn default() -> Self {
        Self {
            rate: 0.0,
            processed: 0,
            cracked: 0,
            in_flight: 0,
            last_seen: Instant::now(),
        }
    }
}

#[derive(Clone)]
struct CrackEntry {
    username: String,
    plaintext: String,
    when: Instant,
}

struct AppState {
    start: Instant,
    total_sent: u64,
    input_done: bool,
    nodes: HashMap<String, NodeStatus>,
    recent_cracks: VecDeque<CrackEntry>,
    errors: VecDeque<String>,
    rate_history: Vec<u64>,
    paused: bool,
    quit: bool,
}

impl AppState {
    fn new() -> Self {
        Self {
            start: Instant::now(),
            total_sent: 0,
            input_done: false,
            nodes: HashMap::new(),
            recent_cracks: VecDeque::with_capacity(20),
            errors: VecDeque::with_capacity(5),
            rate_history: Vec::with_capacity(120),
            paused: false,
            quit: false,
        }
    }

    fn handle_event(&mut self, event: AppEvent) {
        match event {
            AppEvent::Status {
                node_id,
                rate,
                processed,
                cracked,
                in_flight,
            } => {
                let entry = self.nodes.entry(node_id).or_default();
                entry.rate = rate;
                entry.processed = processed;
                entry.cracked = cracked;
                entry.in_flight = in_flight;
                entry.last_seen = Instant::now();
            }
            AppEvent::Cracked {
                username,
                plaintext,
            } => {
                if self.recent_cracks.len() >= 20 {
                    self.recent_cracks.pop_back();
                }
                self.recent_cracks.push_front(CrackEntry {
                    username,
                    plaintext,
                    when: Instant::now(),
                });
            }
            AppEvent::Error { code, message } => {
                if self.errors.len() >= 5 {
                    self.errors.pop_back();
                }
                self.errors.push_front(format!("[{code}] {message}"));
            }
            AppEvent::SentBatch { count } => {
                self.total_sent += count;
            }
            AppEvent::InputDone => {
                self.input_done = true;
            }
        }
    }

    fn handle_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('q') => self.quit = true,
            KeyCode::Char('c') => self.recent_cracks.clear(),
            KeyCode::Char('p') => self.paused = !self.paused,
            _ => {}
        }
    }

    fn on_tick(&mut self) {
        let totals = self.totals();
        let rate = totals.rate.round() as u64;
        self.rate_history.push(rate);
        if self.rate_history.len() > 120 {
            let excess = self.rate_history.len() - 120;
            self.rate_history.drain(0..excess);
        }
    }

    fn totals(&self) -> Totals {
        let mut processed = 0u64;
        let mut cracked = 0u64;
        let mut in_flight = 0u64;
        let mut rate = 0f64;

        for status in self.nodes.values() {
            processed = processed.saturating_add(status.processed);
            cracked = cracked.saturating_add(status.cracked);
            in_flight = in_flight.saturating_add(status.in_flight);
            rate += status.rate;
        }

        Totals {
            processed,
            cracked,
            in_flight,
            rate,
        }
    }
}

struct Totals {
    processed: u64,
    cracked: u64,
    in_flight: u64,
    rate: f64,
}

pub async fn run(mut rx: UnboundedReceiver<AppEvent>) -> Result<UiOutcome> {
    let _guard = TerminalGuard::enter()?;
    let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;

    let (key_tx, mut key_rx) = tokio::sync::mpsc::unbounded_channel::<KeyEvent>();
    std::thread::spawn(move || {
        loop {
            if let Ok(true) = event::poll(Duration::from_millis(100)) {
                if let Ok(Event::Key(key)) = event::read() {
                    let _ = key_tx.send(key);
                }
            }
        }
    });

    let mut state = AppState::new();
    let mut tick = tokio::time::interval(Duration::from_millis(250));

    loop {
        tokio::select! {
            _ = tick.tick() => state.on_tick(),
            Some(ev) = rx.recv() => state.handle_event(ev),
            Some(key) = key_rx.recv() => state.handle_key(key),
            else => break,
        }

        terminal.draw(|f| draw_ui(f, &state))?;

        if state.quit {
            break;
        }
    }

    Ok(UiOutcome { quit: state.quit })
}

fn draw_ui(f: &mut ratatui::Frame<'_>, state: &AppState) {
    let size = f.size();

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(10),
            Constraint::Length(3),
        ])
        .split(size);

    let header = header_widget(state);
    f.render_widget(header, chunks[0]);

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(65), Constraint::Percentage(35)])
        .split(chunks[1]);

    draw_left(f, body[0], state);
    draw_right(f, body[1], state);

    let footer = footer_widget(state);
    f.render_widget(footer, chunks[2]);
}

fn header_widget(state: &AppState) -> Paragraph<'static> {
    let totals = state.totals();
    let rate = totals.rate;
    let uptime_s = state.start.elapsed().as_secs();

    let eta = if state.total_sent > 0 && rate > 0.0 {
        let remaining = state.total_sent.saturating_sub(totals.processed);
        let secs = (remaining as f64 / rate).round() as u64;
        format!("ETA ~{}s", secs)
    } else {
        "ETA n/a".to_string()
    };

    let status = if state.input_done {
        "input done"
    } else {
        "streaming"
    };
    let line = Line::from(vec![
        Span::styled("FlashAudit", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw(" | "),
        Span::raw(format!("sent {}", state.total_sent)),
        Span::raw(" | "),
        Span::raw(format!("processed {}", totals.processed)),
        Span::raw(" | "),
        Span::raw(format!("cracked {}", totals.cracked)),
        Span::raw(" | "),
        Span::raw(format!("in-flight {}", totals.in_flight)),
        Span::raw(" | "),
        Span::raw(format!("rate {:.1} H/s", rate)),
        Span::raw(" | "),
        Span::raw(eta),
        Span::raw(" | "),
        Span::raw(format!("uptime {}s", uptime_s)),
        Span::raw(" | "),
        Span::raw(status),
    ]);

    Paragraph::new(line).block(Block::default().borders(Borders::ALL).title("Lattice"))
}

fn draw_left(f: &mut ratatui::Frame<'_>, area: Rect, state: &AppState) {
    let left = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(6),
            Constraint::Length(6),
            Constraint::Length(3),
            Constraint::Min(5),
        ])
        .split(area);

    let spark = Sparkline::default()
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Rate Sparkline"),
        )
        .data(&state.rate_history)
        .style(Style::default().fg(Color::Cyan));
    f.render_widget(spark, left[0]);

    let errors = if state.errors.is_empty() {
        vec![ListItem::new("no errors")]
    } else {
        state
            .errors
            .iter()
            .map(|e| ListItem::new(e.clone()))
            .collect()
    };
    let error_list =
        List::new(errors).block(Block::default().borders(Borders::ALL).title("Errors"));
    f.render_widget(error_list, left[1]);

    let totals = state.totals();
    let percent = if state.total_sent > 0 {
        ((totals.processed as f64 / state.total_sent as f64) * 100.0).min(100.0)
    } else {
        0.0
    };
    let gauge = Gauge::default()
        .block(Block::default().borders(Borders::ALL).title("Progress"))
        .gauge_style(Style::default().fg(Color::Green))
        .percent(percent as u16);
    f.render_widget(gauge, left[2]);

    let cracks: Vec<ListItem> = if state.recent_cracks.is_empty() {
        vec![ListItem::new("no cracks yet")]
    } else {
        state
            .recent_cracks
            .iter()
            .map(|c| {
                let age = c.when.elapsed().as_secs();
                let line = if c.username.is_empty() {
                    format!("{} ({}s ago)", c.plaintext, age)
                } else {
                    format!("{} : {} ({}s ago)", c.username, c.plaintext, age)
                };
                ListItem::new(line)
            })
            .collect()
    };

    let crack_list = List::new(cracks).block(
        Block::default()
            .borders(Borders::ALL)
            .title("Recent Cracks"),
    );
    f.render_widget(crack_list, left[3]);
}

fn draw_right(f: &mut ratatui::Frame<'_>, area: Rect, state: &AppState) {
    let header = Row::new(["node", "rate", "processed", "cracked", "in-flight", "last"]).style(
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    );

    let rows: Vec<Row> = if state.nodes.is_empty() {
        vec![Row::new(vec![
            "(none)".to_string(),
            "-".to_string(),
            "-".to_string(),
            "-".to_string(),
            "-".to_string(),
            "-".to_string(),
        ])]
    } else {
        state
            .nodes
            .iter()
            .map(|(id, status)| {
                let ago = status.last_seen.elapsed().as_secs();
                Row::new(vec![
                    id.clone(),
                    format!("{:.1}", status.rate),
                    status.processed.to_string(),
                    status.cracked.to_string(),
                    status.in_flight.to_string(),
                    format!("{}s", ago),
                ])
            })
            .collect()
    };

    let widths = [
        Constraint::Percentage(30),
        Constraint::Percentage(15),
        Constraint::Percentage(15),
        Constraint::Percentage(15),
        Constraint::Percentage(15),
        Constraint::Percentage(10),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default().borders(Borders::ALL).title("Nodes"));

    f.render_widget(table, area);
}

fn footer_widget(state: &AppState) -> Paragraph<'static> {
    let mut spans = vec![
        Span::styled("q", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw(" quit  "),
        Span::styled("c", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw(" clear cracks  "),
        Span::styled("p", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw(" pause (local)"),
    ];

    if state.paused {
        spans.push(Span::raw("  "));
        spans.push(Span::styled(
            "PAUSED",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        ));
    }

    Paragraph::new(Line::from(spans)).block(Block::default().borders(Borders::ALL).title("Hotkeys"))
}
