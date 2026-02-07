use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::io::Write;
use std::io::{self};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use std::time::{SystemTime, UNIX_EPOCH};

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
use tokio::sync::mpsc::UnboundedSender;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UiCommand {
    SetPaused(bool),
    CancelStream,
}

pub struct UiOutcome {
    pub quit: bool,
    pub cancelled: bool,
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
    snapshot_base: Option<PathBuf>,
    total_sent: u64,
    input_done: bool,
    nodes: HashMap<String, NodeStatus>,
    recent_cracks: VecDeque<CrackEntry>,
    errors: VecDeque<String>,
    rate_history: Vec<u64>,
    paused: bool,
    quit: bool,
    cancelled: bool,
}

impl AppState {
    fn new(snapshot_base: Option<PathBuf>) -> Self {
        Self {
            start: Instant::now(),
            snapshot_base,
            total_sent: 0,
            input_done: false,
            nodes: HashMap::new(),
            recent_cracks: VecDeque::with_capacity(20),
            errors: VecDeque::with_capacity(5),
            rate_history: Vec::with_capacity(120),
            paused: false,
            quit: false,
            cancelled: false,
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

    fn handle_key(&mut self, key: KeyEvent) -> Option<UiCommand> {
        match key.code {
            KeyCode::Char('q') => {
                self.quit = true;
                None
            }
            KeyCode::Char('c') => {
                self.recent_cracks.clear();
                None
            }
            KeyCode::Char('p') => {
                self.paused = !self.paused;
                Some(UiCommand::SetPaused(self.paused))
            }
            KeyCode::Char('x') => {
                self.cancelled = true;
                self.quit = true;
                Some(UiCommand::CancelStream)
            }
            KeyCode::Char('s') => {
                match self.save_snapshot() {
                    Ok(path) => self.push_note(format!("snapshot saved: {}", path.display())),
                    Err(err) => self.push_note(format!("snapshot save failed: {err}")),
                }
                None
            }
            _ => None,
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

    fn push_note(&mut self, msg: String) {
        if self.errors.len() >= 5 {
            self.errors.pop_back();
        }
        self.errors.push_front(msg);
    }

    fn save_snapshot(&self) -> Result<PathBuf> {
        let path = snapshot_path(self.snapshot_base.as_deref());
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)?;
        }

        let mut file = File::create(&path)?;
        let totals = self.totals();
        writeln!(
            file,
            "flashaudit snapshot: sent={} processed={} cracked={} in_flight={} rate={:.1}H/s input_done={}",
            self.total_sent,
            totals.processed,
            totals.cracked,
            totals.in_flight,
            totals.rate,
            self.input_done
        )?;
        writeln!(file, "nodes:")?;
        for (id, status) in &self.nodes {
            writeln!(
                file,
                "  - {} rate={:.1} processed={} cracked={} in_flight={} last_seen={}s",
                id,
                status.rate,
                status.processed,
                status.cracked,
                status.in_flight,
                status.last_seen.elapsed().as_secs()
            )?;
        }
        writeln!(file, "recent_cracks:")?;
        for crack in &self.recent_cracks {
            let line = if crack.username.is_empty() {
                crack.plaintext.clone()
            } else {
                format!("{}:{}", crack.username, crack.plaintext)
            };
            writeln!(file, "  - {}", line)?;
        }
        Ok(path)
    }
}

struct Totals {
    processed: u64,
    cracked: u64,
    in_flight: u64,
    rate: f64,
}

pub async fn run(
    mut rx: UnboundedReceiver<AppEvent>,
    cmd_tx: UnboundedSender<UiCommand>,
    snapshot_base: Option<PathBuf>,
) -> Result<UiOutcome> {
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

    let mut state = AppState::new(snapshot_base);
    let mut tick = tokio::time::interval(Duration::from_millis(250));

    loop {
        tokio::select! {
            _ = tick.tick() => state.on_tick(),
            Some(ev) = rx.recv() => state.handle_event(ev),
            Some(key) = key_rx.recv() => {
                if let Some(cmd) = state.handle_key(key) {
                    let _ = cmd_tx.send(cmd);
                }
            }
            else => break,
        }

        terminal.draw(|f| draw_ui(f, &state))?;

        if state.quit {
            break;
        }
    }

    Ok(UiOutcome {
        quit: state.quit,
        cancelled: state.cancelled,
    })
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

    let status = if state.cancelled {
        "cancelled"
    } else if state.paused {
        "paused"
    } else if state.input_done {
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
        Span::raw(" pause/resume  "),
        Span::styled("s", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw(" save snapshot  "),
        Span::styled("x", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw(" cancel stream"),
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

fn snapshot_path(base: Option<&Path>) -> PathBuf {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    match base {
        Some(base) => {
            let parent = base.parent().unwrap_or_else(|| Path::new("."));
            let stem = base
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("flashaudit");
            let ext = base.extension().and_then(|s| s.to_str()).unwrap_or("txt");
            parent.join(format!("{stem}.snapshot-{ts}.{ext}"))
        }
        None => PathBuf::from(format!("flashaudit.snapshot-{ts}.txt")),
    }
}
