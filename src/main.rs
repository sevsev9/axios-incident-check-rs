use std::{
    collections::VecDeque,
    fs,
    io::{self, BufRead, Stdout, Write as _},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

use anyhow::{Context, Result};
use chrono::{DateTime, Local};
use dashmap::DashSet;
use parking_lot::Mutex as PlMutex;
use crossterm::{
    event::{Event as CEvent, EventStream, KeyCode, KeyEvent, KeyEventKind, MouseEventKind},
    execute,
    terminal::{
        disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
        DisableLineWrap, EnableLineWrap,
    },
};
use futures::{FutureExt, StreamExt};
use ignore::WalkBuilder;
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Margin, Rect},
    prelude::*,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{
        Block, Borders, Clear, Gauge, List, ListItem, ListState, Paragraph, Row, Scrollbar,
        ScrollbarOrientation, ScrollbarState, Table, Wrap,
    },
    Terminal,
};
use tokio::{
    select,
    sync::{mpsc, watch},
    task::JoinSet,
    time::{interval, MissedTickBehavior},
};

const IOC_DOMAIN: &str = "sfrclak.com";
const IOC_IP: &str = "142.11.206.73";
const IOC_URL_FRAGMENT: &str = "packages.npm.org/product";
const IOC_C2_CAMPAIGN_ID: &str = "6202033";
const IOC_USER_AGENT: &str = "mozilla/4.0 (compatible; msie 8.0; windows nt 5.1; trident/4.0)";
const IOC_FILE: &str = "/tmp/ld.py";
const SUSPICIOUS_DEPS: &[&str] = &["plain-crypto-js", "@shadanai/openclaw", "@qqbrowser/openclaw-qbot"];
const BAD_AXIOS_VERSIONS: &[&str] = &["1.14.1", "0.30.4"];

// Additional IOC file paths to check (Linux/macOS)
const IOC_FILES_EXTRA: &[&str] = &[
    "/tmp/ld.py",
    "/var/tmp/ld.py",
    "/Library/Caches/com.apple.act.mond",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum SectionKind {
    Environment,
    Lockfiles,
    NodeModules,
    IocFiles,
    UserLogs,
    SystemLogs,
    Processes,
}

impl SectionKind {
    const ALL: [SectionKind; 7] = [
        SectionKind::Environment,
        SectionKind::Lockfiles,
        SectionKind::NodeModules,
        SectionKind::IocFiles,
        SectionKind::UserLogs,
        SectionKind::SystemLogs,
        SectionKind::Processes,
    ];

    fn title(self) -> &'static str {
        match self {
            SectionKind::Environment => "Environment",
            SectionKind::Lockfiles => "Lockfiles / manifests",
            SectionKind::NodeModules => "node_modules suspicious dependency scan",
            SectionKind::IocFiles => "Known IOC files",
            SectionKind::UserLogs => "User logs / shell history",
            SectionKind::SystemLogs => "System logs",
            SectionKind::Processes => "Live process scan",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
enum Severity {
    Info,
    Ok,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    fn score(self) -> u64 {
        match self {
            Severity::Info | Severity::Ok => 0,
            Severity::Low => 5,
            Severity::Medium => 20,
            Severity::High => 50,
            Severity::Critical => 100,
        }
    }

    fn style(self) -> Style {
        match self {
            Severity::Info => Style::default().fg(Color::Cyan),
            Severity::Ok => Style::default().fg(Color::Green),
            Severity::Low => Style::default().fg(Color::Yellow),
            Severity::Medium => Style::default().fg(Color::LightYellow),
            Severity::High => Style::default().fg(Color::LightRed),
            Severity::Critical => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        }
    }

    fn label(self) -> &'static str {
        match self {
            Severity::Info => "INFO",
            Severity::Ok => "OK",
            Severity::Low => "LOW",
            Severity::Medium => "MED",
            Severity::High => "HIGH",
            Severity::Critical => "CRIT",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SectionStatus {
    Pending,
    Running,
    Done,
}

#[derive(Debug, Clone)]
struct Finding {
    ts: DateTime<Local>,
    severity: Severity,
    text: String,
}

impl Finding {
    fn new(severity: Severity, text: impl Into<String>) -> Self {
        Self {
            ts: Local::now(),
            severity,
            text: text.into(),
        }
    }
}

#[derive(Debug, Clone, Default)]
struct ProgressStats {
    visited: u64,
    matched: u64,
    #[allow(dead_code)]
    errors: u64,
}

#[derive(Debug, Clone)]
struct SectionState {
    kind: SectionKind,
    status: SectionStatus,
    stats: ProgressStats,
    findings: Vec<Finding>,
    expanded: bool,
}

impl SectionState {
    fn new(kind: SectionKind) -> Self {
        Self {
            kind,
            status: SectionStatus::Pending,
            stats: ProgressStats::default(),
            findings: Vec::new(),
            expanded: false,
        }
    }

    fn score(&self) -> u64 {
        self.findings.iter().map(|f| f.severity.score()).sum()
    }

    fn highest_severity(&self) -> Severity {
        self.findings
            .iter()
            .map(|f| f.severity)
            .max_by_key(|s| s.score())
            .unwrap_or(Severity::Ok)
    }
}

#[derive(Debug, Clone)]
struct Config {
    roots: Vec<PathBuf>,
    include_user_logs: bool,
    include_system_logs: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            roots: vec![std::env::var_os("HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("."))],
            include_user_logs: true,
            include_system_logs: true,
        }
    }
}

#[derive(Debug, Clone)]
struct App {
    started_at: DateTime<Local>,
    config: Config,
    sections: Vec<SectionState>,
    selected: usize,
    logs: VecDeque<Line<'static>>,
    done_sections: usize,
    total_sections: usize,
    quitting: bool,
    show_help: bool,
    log_scroll: u16,
}

impl App {
    fn new(config: Config) -> Self {
        let mut sections = SectionKind::ALL
            .iter()
            .copied()
            .map(SectionState::new)
            .collect::<Vec<_>>();
        if let Some(first) = sections.first_mut() {
            first.expanded = true;
        }
        Self {
            started_at: Local::now(),
            config,
            sections,
            selected: 0,
            logs: VecDeque::with_capacity(2000),
            done_sections: 0,
            total_sections: SectionKind::ALL.len(),
            quitting: false,
            show_help: false,
            log_scroll: 0,
        }
    }

    fn section_mut(&mut self, kind: SectionKind) -> &mut SectionState {
        self.sections
            .iter_mut()
            .find(|s| s.kind == kind)
            .expect("section exists")
    }

    fn section(&self, kind: SectionKind) -> &SectionState {
        self.sections
            .iter()
            .find(|s| s.kind == kind)
            .expect("section exists")
    }

    fn total_score(&self) -> u64 {
        self.sections.iter().map(SectionState::score).sum()
    }

    fn verdict(&self) -> (&'static str, Style) {
        let score = self.total_score();
        if score >= 100 {
            (
                "LIKELY COMPROMISED",
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            )
        } else if score >= 50 {
            (
                "HIGH RISK / STRONG INDICATORS",
                Style::default().fg(Color::LightRed),
            )
        } else if score >= 20 {
            (
                "SUSPICIOUS / NEEDS REVIEW",
                Style::default().fg(Color::Yellow),
            )
        } else {
            (
                "NO STRONG LOCAL INDICATORS FOUND",
                Style::default().fg(Color::Green),
            )
        }
    }

    fn progress_ratio(&self) -> f64 {
        if self.total_sections == 0 {
            0.0
        } else {
            self.done_sections as f64 / self.total_sections as f64
        }
    }

    fn push_log(&mut self, line: Line<'static>) {
        if self.logs.len() >= 2000 {
            self.logs.pop_front();
        }
        self.logs.push_back(line);
    }

    fn selected_kind(&self) -> SectionKind {
        self.sections[self.selected].kind
    }

    fn toggle_selected(&mut self) {
        if let Some(sec) = self.sections.get_mut(self.selected) {
            sec.expanded = !sec.expanded;
        }
    }

    fn expand_all(&mut self) {
        for sec in &mut self.sections {
            sec.expanded = true;
        }
    }

    fn collapse_all(&mut self) {
        for sec in &mut self.sections {
            sec.expanded = false;
        }
        if let Some(sec) = self.sections.get_mut(self.selected) {
            sec.expanded = true;
        }
    }
}

#[derive(Debug)]
enum ScanEvent {
    SectionStarted(SectionKind),
    Visited(SectionKind, u64),
    Finding(SectionKind, Finding),
    SectionFinished(SectionKind),
    Log(Line<'static>),
}

#[derive(Debug)]
enum UiEvent {
    Input(KeyEvent),
    Mouse(crossterm::event::MouseEvent),
    Resize(u16, u16),
    Tick,
    Scan(ScanEvent),
}

fn prompt_config() -> Result<Config> {
    let default_root = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));

    println!("╔══════════════════════════════════════════╗");
    println!("║      Axios Incident Scanner (v0.1.0)     ║");
    println!("╚══════════════════════════════════════════╝");
    println!();
    print!(
        "Scan directory [{}]: ",
        default_root.display()
    );
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().lock().read_line(&mut input)?;
    let input = input.trim();

    let root = if input.is_empty() {
        default_root
    } else {
        let p = PathBuf::from(shellexpand(input));
        if !p.is_dir() {
            anyhow::bail!("Not a directory: {}", p.display());
        }
        p
    };

    println!("Scanning: {}", root.display());
    println!();

    Ok(Config {
        roots: vec![root],
        include_user_logs: true,
        include_system_logs: true,
    })
}

/// Expand leading `~` to $HOME.
fn shellexpand(s: &str) -> String {
    if let Some(rest) = s.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return format!("{}/{rest}", home.to_string_lossy());
        }
    } else if s == "~" {
        if let Some(home) = std::env::var_os("HOME") {
            return home.to_string_lossy().into_owned();
        }
    }
    s.to_string()
}

#[tokio::main]
async fn main() -> Result<()> {
    let config = prompt_config()?;
    let (app_tx, app_rx) = watch::channel(App::new(config.clone()));
    let (ui_tx, ui_rx) = mpsc::channel::<UiEvent>(4096);
    let (scan_tx, mut scan_rx) = mpsc::channel::<ScanEvent>(4096);

    // Fan-in scan events into the UI queue.
    {
        let ui_tx = ui_tx.clone();
        tokio::spawn(async move {
            while let Some(ev) = scan_rx.recv().await {
                if ui_tx.send(UiEvent::Scan(ev)).await.is_err() {
                    break;
                }
            }
        });
    }

    // Async terminal input + tick loop.
    spawn_terminal_events(ui_tx.clone());

    // Scanner orchestration.
    tokio::spawn(run_scans(config.clone(), scan_tx));

    // TUI loop.
    let mut tui = Tui::enter()?;
    let result = run_app(&mut tui, app_rx, app_tx, ui_rx).await;
    Tui::exit(&mut tui)?;
    result
}

fn spawn_terminal_events(ui_tx: mpsc::Sender<UiEvent>) {
    tokio::spawn(async move {
        let mut reader = EventStream::new();
        let mut ticker = interval(Duration::from_millis(100));
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            select! {
                _ = ticker.tick() => {
                    if ui_tx.send(UiEvent::Tick).await.is_err() {
                        break;
                    }
                }
                maybe_event = reader.next().fuse() => {
                    match maybe_event {
                        Some(Ok(CEvent::Key(key))) if key.kind == KeyEventKind::Press => {
                            if ui_tx.send(UiEvent::Input(key)).await.is_err() {
                                break;
                            }
                        }
                        Some(Ok(CEvent::Mouse(mouse))) => {
                            if ui_tx.send(UiEvent::Mouse(mouse)).await.is_err() {
                                break;
                            }
                        }
                        Some(Ok(CEvent::Resize(w, h))) => {
                            if ui_tx.send(UiEvent::Resize(w, h)).await.is_err() {
                                break;
                            }
                        }
                        Some(Ok(_)) => {}
                        Some(Err(_)) => {}
                        None => break,
                    }
                }
            }
        }
    });
}

async fn run_app(
    tui: &mut Tui,
    mut app_rx: watch::Receiver<App>,
    app_tx: watch::Sender<App>,
    mut ui_rx: mpsc::Receiver<UiEvent>,
) -> Result<()> {
    while let Some(event) = ui_rx.recv().await {
        {
            let app = app_rx.borrow().clone();
            tui.draw(&app)?;
        }

        let mut app = app_rx.borrow().clone();

        match event {
            UiEvent::Tick => {}
            UiEvent::Resize(w, h) => {
                tui.terminal.resize(Rect::new(0, 0, w, h))?;
            }
            UiEvent::Mouse(mouse) => {
                if matches!(mouse.kind, MouseEventKind::ScrollDown) {
                    app.log_scroll = app.log_scroll.saturating_add(2);
                } else if matches!(mouse.kind, MouseEventKind::ScrollUp) {
                    app.log_scroll = app.log_scroll.saturating_sub(2);
                }
            }
            UiEvent::Input(key) => {
                handle_key(&mut app, key);
            }
            UiEvent::Scan(scan) => {
                apply_scan_event(&mut app, scan);
            }
        }

        let quitting = app.quitting;
        let _ = app_tx.send(app);
        let _ = app_rx.changed().await;

        if quitting {
            break;
        }
    }

    Ok(())
}

fn handle_key(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Char('q') | KeyCode::Esc => app.quitting = true,
        KeyCode::Down | KeyCode::Char('j') => {
            app.selected = (app.selected + 1).min(app.sections.len().saturating_sub(1));
        }
        KeyCode::Up | KeyCode::Char('k') => {
            app.selected = app.selected.saturating_sub(1);
        }
        KeyCode::Enter | KeyCode::Char(' ') => app.toggle_selected(),
        KeyCode::Char('a') => app.expand_all(),
        KeyCode::Char('c') => app.collapse_all(),
        KeyCode::Char('?') | KeyCode::Char('h') => app.show_help = !app.show_help,
        KeyCode::PageDown => app.log_scroll = app.log_scroll.saturating_add(10),
        KeyCode::PageUp => app.log_scroll = app.log_scroll.saturating_sub(10),
        _ => {}
    }
}

fn apply_scan_event(app: &mut App, ev: ScanEvent) {
    match ev {
        ScanEvent::SectionStarted(kind) => {
            let sec = app.section_mut(kind);
            sec.status = SectionStatus::Running;
            app.push_log(Line::from(vec![
                Span::styled("▶ ", Style::default().fg(Color::Cyan)),
                Span::raw(kind.title().to_string()),
            ]));
        }
        ScanEvent::Visited(kind, n) => {
            let sec = app.section_mut(kind);
            sec.stats.visited = n;
        }
        ScanEvent::Finding(kind, finding) => {
            let style = finding.severity.style();
            let log_line = Line::from(vec![
                Span::styled(
                    format!("[{}] ", finding.severity.label()),
                    style.add_modifier(Modifier::BOLD),
                ),
                Span::raw(finding.text.clone()),
            ]);
            app.push_log(log_line);
            let sec = app.section_mut(kind);
            sec.stats.matched += 1;
            sec.findings.push(finding);
        }
        ScanEvent::SectionFinished(kind) => {
            let sec = app.section_mut(kind);
            sec.status = SectionStatus::Done;
            app.done_sections += 1;
            app.push_log(Line::from(vec![
                Span::styled("✓ ", Style::default().fg(Color::Green)),
                Span::raw(kind.title().to_string()),
            ]));
        }
        ScanEvent::Log(line) => {
            app.push_log(line);
        }
    }
}

async fn run_scans(config: Config, tx: mpsc::Sender<ScanEvent>) -> Result<()> {
    let mut set: JoinSet<Result<()>> = JoinSet::new();

    // Environment: lightweight async task.
    {
        let tx = tx.clone();
        set.spawn(async move {
            send(&tx, ScanEvent::SectionStarted(SectionKind::Environment)).await;
            let host = hostname_fallback();
            let user = std::env::var("USER").unwrap_or_else(|_| "unknown".into());
            let cwd = std::env::current_dir()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| "?".into());

            send_finding(
                &tx,
                SectionKind::Environment,
                Severity::Info,
                format!("Hostname: {host}"),
            )
            .await;
            send_finding(
                &tx,
                SectionKind::Environment,
                Severity::Info,
                format!("User: {user}"),
            )
            .await;
            send_finding(
                &tx,
                SectionKind::Environment,
                Severity::Info,
                format!("Current directory: {cwd}"),
            )
            .await;

            send(&tx, ScanEvent::SectionFinished(SectionKind::Environment)).await;
            Ok(())
        });
    }

    // Heavy sections: offload to blocking thread pool.
    {
        let tx = tx.clone();
        let roots = config.roots.clone();
        set.spawn(async move {
            tokio::task::spawn_blocking(move || scan_lockfiles(roots, tx))
                .await
                .context("lockfiles worker join")??;
            Ok::<_, anyhow::Error>(())
        });
    }

    {
        let tx = tx.clone();
        let roots = config.roots.clone();
        set.spawn(async move {
            tokio::task::spawn_blocking(move || scan_node_modules(roots, tx))
                .await
                .context("node_modules worker join")??;
            Ok::<_, anyhow::Error>(())
        });
    }

    {
        let tx = tx.clone();
        set.spawn(async move {
            tokio::task::spawn_blocking(move || scan_ioc_files(tx))
                .await
                .context("ioc worker join")??;
            Ok::<_, anyhow::Error>(())
        });
    }

    if config.include_user_logs {
        let tx = tx.clone();
        set.spawn(async move {
            tokio::task::spawn_blocking(move || scan_user_logs(tx))
                .await
                .context("user logs worker join")??;
            Ok::<_, anyhow::Error>(())
        });
    } else {
        let tx = tx.clone();
        set.spawn(async move {
            send(&tx, ScanEvent::SectionStarted(SectionKind::UserLogs)).await;
            send_finding(
                &tx,
                SectionKind::UserLogs,
                Severity::Info,
                "Skipped by configuration",
            )
            .await;
            send(&tx, ScanEvent::SectionFinished(SectionKind::UserLogs)).await;
            Ok::<_, anyhow::Error>(())
        });
    }

    if config.include_system_logs {
        let tx = tx.clone();
        set.spawn(async move {
            tokio::task::spawn_blocking(move || scan_system_logs(tx))
                .await
                .context("system logs worker join")??;
            Ok::<_, anyhow::Error>(())
        });
    } else {
        let tx = tx.clone();
        set.spawn(async move {
            send(&tx, ScanEvent::SectionStarted(SectionKind::SystemLogs)).await;
            send_finding(
                &tx,
                SectionKind::SystemLogs,
                Severity::Info,
                "Skipped by configuration",
            )
            .await;
            send(&tx, ScanEvent::SectionFinished(SectionKind::SystemLogs)).await;
            Ok::<_, anyhow::Error>(())
        });
    }

    {
        let tx = tx.clone();
        set.spawn(async move {
            tokio::task::spawn_blocking(move || scan_processes(tx))
                .await
                .context("process worker join")??;
            Ok::<_, anyhow::Error>(())
        });
    }

    while let Some(res) = set.join_next().await {
        match res {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                let _ = tx
                    .send(ScanEvent::Log(Line::from(vec![
                        Span::styled("[ERR] ", Style::default().fg(Color::Red)),
                        Span::raw(err.to_string()),
                    ])))
                    .await;
            }
            Err(err) => {
                let _ = tx
                    .send(ScanEvent::Log(Line::from(vec![
                        Span::styled("[PANIC] ", Style::default().fg(Color::Red)),
                        Span::raw(err.to_string()),
                    ])))
                    .await;
            }
        }
    }

    Ok(())
}

fn scan_lockfiles(roots: Vec<PathBuf>, tx: mpsc::Sender<ScanEvent>) -> Result<()> {
    send_blocking(&tx, ScanEvent::SectionStarted(SectionKind::Lockfiles));
    let visited = Arc::new(AtomicU64::new(0));
    // DashSet to deduplicate findings by project root (avoid duplicate reports
    // when both package.json and lockfile match in the same directory tree).
    let seen_dirs: Arc<DashSet<PathBuf>> = Arc::new(DashSet::new());
    let walk_errors: Arc<PlMutex<u64>> = Arc::new(PlMutex::new(0));

    for root in roots {
        let tx_cloned = tx.clone();
        let visited_cloned = visited.clone();
        let seen_dirs_cloned = seen_dirs.clone();
        let walk_errors_cloned = walk_errors.clone();
        let threads = num_cpus::get().max(2).min(32);

        WalkBuilder::new(root)
            .hidden(false)
            .ignore(false)
            .git_ignore(false)
            .git_global(false)
            .git_exclude(false)
            .threads(threads)
            .build_parallel()
            .run(|| {
                let tx = tx_cloned.clone();
                let visited = visited_cloned.clone();
                let seen_dirs = seen_dirs_cloned.clone();
                let walk_errors = walk_errors_cloned.clone();
                Box::new(move |entry| {
                    let entry = match entry {
                        Ok(e) => e,
                        Err(_) => {
                            *walk_errors.lock() += 1;
                            return ignore::WalkState::Continue;
                        }
                    };

                    let path = entry.path();
                    if !entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
                        return ignore::WalkState::Continue;
                    }

                    let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
                        return ignore::WalkState::Continue;
                    };

                    let interesting = matches!(
                        name,
                        "package-lock.json"
                            | "pnpm-lock.yaml"
                            | "yarn.lock"
                            | "bun.lock"
                            | "bun.lockb"
                            | "package.json"
                    );

                    if !interesting {
                        return ignore::WalkState::Continue;
                    }

                    let now = visited.fetch_add(1, Ordering::Relaxed) + 1;
                    if now % 25 == 0 {
                        send_blocking(&tx, ScanEvent::Visited(SectionKind::Lockfiles, now));
                    }

                    if let Ok(contents) = fs::read_to_string(path) {
                        if contains_bad_axios(&contents) || contains_suspicious_dep(&contents) {
                            // Deduplicate by parent directory
                            let dir = path.parent().unwrap_or(path).to_path_buf();
                            if seen_dirs.insert(dir) {
                                send_blocking(
                                    &tx,
                                    ScanEvent::Finding(
                                        SectionKind::Lockfiles,
                                        Finding::new(
                                            Severity::Medium,
                                            format!("Affected dependency reference found in {}", path.display()),
                                        ),
                                    ),
                                );
                            }
                        }
                    }

                    ignore::WalkState::Continue
                })
            });
    }

    send_blocking(
        &tx,
        ScanEvent::Visited(
            SectionKind::Lockfiles,
            visited.load(Ordering::Relaxed),
        ),
    );
    let errs = *walk_errors.lock();
    if errs > 0 {
        send_blocking(
            &tx,
            ScanEvent::Finding(
                SectionKind::Lockfiles,
                Finding::new(Severity::Info, format!("{errs} directories were inaccessible during scan")),
            ),
        );
    }
    send_blocking(&tx, ScanEvent::SectionFinished(SectionKind::Lockfiles));
    Ok(())
}

fn scan_node_modules(roots: Vec<PathBuf>, tx: mpsc::Sender<ScanEvent>) -> Result<()> {
    send_blocking(&tx, ScanEvent::SectionStarted(SectionKind::NodeModules));
    let visited = Arc::new(AtomicU64::new(0));

    for root in roots {
        let tx_cloned = tx.clone();
        let visited_cloned = visited.clone();
        let threads = num_cpus::get().max(2).min(32);

        WalkBuilder::new(root)
            .hidden(false)
            .ignore(false)
            .git_ignore(false)
            .git_global(false)
            .git_exclude(false)
            .threads(threads)
            .build_parallel()
            .run(|| {
                let tx = tx_cloned.clone();
                let visited = visited_cloned.clone();
                Box::new(move |entry| {
                    let entry = match entry {
                        Ok(e) => e,
                        Err(_) => return ignore::WalkState::Continue,
                    };

                    let path = entry.path();
                    if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                        return ignore::WalkState::Continue;
                    }

                    let now = visited.fetch_add(1, Ordering::Relaxed) + 1;
                    if now % 50 == 0 {
                        send_blocking(&tx, ScanEvent::Visited(SectionKind::NodeModules, now));
                    }

                    // Check if this path matches any suspicious dep.
                    // For scoped packages (@scope/pkg), check the last two path components.
                    let path_str = path.to_string_lossy();
                    for dep in SUSPICIOUS_DEPS {
                        let matches = if dep.contains('/') {
                            // Scoped: look for /node_modules/@scope/pkg
                            path_str.ends_with(dep)
                        } else {
                            path.file_name().and_then(|s| s.to_str()) == Some(*dep)
                        };
                        if matches {
                            send_blocking(
                                &tx,
                                ScanEvent::Finding(
                                    SectionKind::NodeModules,
                                    Finding::new(
                                        Severity::High,
                                        format!("Suspicious dependency directory found: {}", path.display()),
                                    ),
                                ),
                            );
                            break;
                        }
                    }

                    ignore::WalkState::Continue
                })
            });
    }

    send_blocking(
        &tx,
        ScanEvent::Visited(
            SectionKind::NodeModules,
            visited.load(Ordering::Relaxed),
        ),
    );
    send_blocking(&tx, ScanEvent::SectionFinished(SectionKind::NodeModules));
    Ok(())
}

fn scan_ioc_files(tx: mpsc::Sender<ScanEvent>) -> Result<()> {
    send_blocking(&tx, ScanEvent::SectionStarted(SectionKind::IocFiles));

    // Check all known IOC file paths (Linux + macOS)
    for ioc_path in IOC_FILES_EXTRA {
        let p = Path::new(ioc_path);
        if p.exists() {
            send_blocking(
                &tx,
                ScanEvent::Finding(
                    SectionKind::IocFiles,
                    Finding::new(Severity::Critical, format!("Known IOC file present: {ioc_path}")),
                ),
            );
        } else {
            send_blocking(
                &tx,
                ScanEvent::Finding(
                    SectionKind::IocFiles,
                    Finding::new(Severity::Ok, format!("Known IOC file not present: {ioc_path}")),
                ),
            );
        }
    }

    // Check $TMPDIR for campaign artifacts (macOS)
    if let Ok(tmpdir) = std::env::var("TMPDIR") {
        let campaign_file = Path::new(&tmpdir).join(IOC_C2_CAMPAIGN_ID);
        if campaign_file.exists() {
            send_blocking(
                &tx,
                ScanEvent::Finding(
                    SectionKind::IocFiles,
                    Finding::new(
                        Severity::Critical,
                        format!("Campaign artifact found: {}", campaign_file.display()),
                    ),
                ),
            );
        }
    }

    // Check Windows-style paths (for WSL environments)
    if let Ok(programdata) = std::env::var("PROGRAMDATA") {
        for name in ["wt.exe", "system.bat"] {
            let p = Path::new(&programdata).join(name);
            if p.exists() {
                send_blocking(
                    &tx,
                    ScanEvent::Finding(
                        SectionKind::IocFiles,
                        Finding::new(
                            Severity::Critical,
                            format!("Windows IOC file found: {}", p.display()),
                        ),
                    ),
                );
            }
        }
    }
    if let Ok(temp) = std::env::var("TEMP") {
        for name in [
            &format!("{IOC_C2_CAMPAIGN_ID}.vbs"),
            &format!("{IOC_C2_CAMPAIGN_ID}.ps1"),
        ] {
            let p = Path::new(&temp).join(name);
            if p.exists() {
                send_blocking(
                    &tx,
                    ScanEvent::Finding(
                        SectionKind::IocFiles,
                        Finding::new(
                            Severity::Critical,
                            format!("Windows IOC script found: {}", p.display()),
                        ),
                    ),
                );
            }
        }
    }

    for dir in ["/tmp", "/var/tmp"] {
        if let Ok(read_dir) = fs::read_dir(dir) {
            let mut visited = 0_u64;
            for entry in read_dir.flatten() {
                visited += 1;
                if visited % 25 == 0 {
                    send_blocking(&tx, ScanEvent::Visited(SectionKind::IocFiles, visited));
                }
                let p = entry.path();
                if p.file_name().and_then(|s| s.to_str()) == Some("ld.py") && p != Path::new(IOC_FILE) {
                    send_blocking(
                        &tx,
                        ScanEvent::Finding(
                            SectionKind::IocFiles,
                            Finding::new(
                                Severity::High,
                                format!("Suspicious ld.py found: {}", p.display()),
                            ),
                        ),
                    );
                }
            }
        }
    }

    send_blocking(&tx, ScanEvent::SectionFinished(SectionKind::IocFiles));
    Ok(())
}

fn scan_user_logs(tx: mpsc::Sender<ScanEvent>) -> Result<()> {
    send_blocking(&tx, ScanEvent::SectionStarted(SectionKind::UserLogs));
    let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."));
    let targets = vec![
        home.join(".npm/_logs"),
        home.join(".config/yarn"),
        home.join(".pnpm-store"),
        home.join(".bash_history"),
        home.join(".zsh_history"),
        home.join(".local/share/fish/fish_history"),
    ];

    let mut visited = 0_u64;
    for target in targets {
        if target.is_file() {
            visited += 1;
            scan_text_file(
                SectionKind::UserLogs,
                &target,
                &tx,
                &mut visited,
                Severity::Medium,
            );
        } else if target.is_dir() {
            for entry in WalkBuilder::new(&target)
                .hidden(false)
                .ignore(false)
                .git_ignore(false)
                .git_global(false)
                .git_exclude(false)
                .build()
                .flatten()
            {
                let path = entry.path().to_path_buf();
                if path.is_file() {
                    visited += 1;
                    scan_text_file(
                        SectionKind::UserLogs,
                        &path,
                        &tx,
                        &mut visited,
                        Severity::Medium,
                    );
                }
            }
        }
    }

    send_blocking(&tx, ScanEvent::Visited(SectionKind::UserLogs, visited));
    send_blocking(&tx, ScanEvent::SectionFinished(SectionKind::UserLogs));
    Ok(())
}

fn scan_system_logs(tx: mpsc::Sender<ScanEvent>) -> Result<()> {
    send_blocking(&tx, ScanEvent::SectionStarted(SectionKind::SystemLogs));
    let targets = [
        PathBuf::from("/var/log/syslog"),
        PathBuf::from("/var/log/auth.log"),
        PathBuf::from("/var/log/messages"),
        PathBuf::from("/var/log/dpkg.log"),
    ];

    let mut visited = 0_u64;
    for path in targets {
        if path.is_file() {
            visited += 1;
            scan_text_file(
                SectionKind::SystemLogs,
                &path,
                &tx,
                &mut visited,
                Severity::High,
            );
        }
    }

    send_blocking(&tx, ScanEvent::Visited(SectionKind::SystemLogs, visited));
    send_blocking(&tx, ScanEvent::SectionFinished(SectionKind::SystemLogs));
    Ok(())
}

fn scan_processes(tx: mpsc::Sender<ScanEvent>) -> Result<()> {
    send_blocking(&tx, ScanEvent::SectionStarted(SectionKind::Processes));

    let output = std::process::Command::new("ps")
        .args(["auxww"])
        .output()
        .context("running ps auxww")?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut visited = 0_u64;
    for line in stdout.lines() {
        visited += 1;
        if visited % 100 == 0 {
            send_blocking(&tx, ScanEvent::Visited(SectionKind::Processes, visited));
        }

        let l = line.to_lowercase();
        if l.contains("ld.py")
            || l.contains("plain-crypto-js")
            || l.contains("sfrclak")
            || l.contains("com.apple.act.mond")
            || l.contains(IOC_C2_CAMPAIGN_ID)
            || (l.contains("python3") && l.contains("nohup"))
        {
            send_blocking(
                &tx,
                ScanEvent::Finding(
                    SectionKind::Processes,
                    Finding::new(
                        Severity::Critical,
                        format!("Suspicious live process indicator: {line}"),
                    ),
                ),
            );
        }
    }

    send_blocking(&tx, ScanEvent::Visited(SectionKind::Processes, visited));
    send_blocking(&tx, ScanEvent::SectionFinished(SectionKind::Processes));
    Ok(())
}

fn scan_text_file(
    section: SectionKind,
    path: &Path,
    tx: &mpsc::Sender<ScanEvent>,
    visited: &mut u64,
    severity: Severity,
) {
    if *visited % 25 == 0 {
        send_blocking(tx, ScanEvent::Visited(section, *visited));
    }

    if let Ok(contents) = fs::read_to_string(path) {
        let lower = contents.to_lowercase();
        if lower.contains(IOC_DOMAIN)
            || lower.contains(IOC_IP)
            || lower.contains(IOC_URL_FRAGMENT)
            || lower.contains(IOC_C2_CAMPAIGN_ID)
            || lower.contains(IOC_USER_AGENT)
            || SUSPICIOUS_DEPS.iter().any(|dep| lower.contains(&dep.to_lowercase()))
            || contains_bad_axios(&contents)
        {
            send_blocking(
                tx,
                ScanEvent::Finding(
                    section,
                    Finding::new(
                        severity,
                        format!("Relevant indicator found in {}", path.display()),
                    ),
                ),
            );
        }
    }
}

fn contains_bad_axios(contents: &str) -> bool {
    BAD_AXIOS_VERSIONS
        .iter()
        .any(|v| {
            contents.contains(&format!("axios@{v}"))
                || contents.contains(&format!("\"axios\": \"{v}\""))
                || contents.contains(&format!("\"axios\":\"{v}\""))
                || contents.contains(&format!("axios\": \"{v}\""))
                || contents.contains(&format!("axios\": \"^{v}\""))
                // pnpm-lock.yaml style
                || contents.contains(&format!("axios/{v}"))
                // yarn.lock style
                || contents.contains(&format!("axios@npm:{v}"))
        })
}

fn contains_suspicious_dep(contents: &str) -> bool {
    let lower = contents.to_lowercase();
    SUSPICIOUS_DEPS.iter().any(|dep| lower.contains(&dep.to_lowercase()))
}

async fn send(tx: &mpsc::Sender<ScanEvent>, ev: ScanEvent) {
    let _ = tx.send(ev).await;
}

async fn send_finding(
    tx: &mpsc::Sender<ScanEvent>,
    kind: SectionKind,
    severity: Severity,
    text: impl Into<String>,
) {
    let _ = tx
        .send(ScanEvent::Finding(kind, Finding::new(severity, text)))
        .await;
}

fn send_blocking(tx: &mpsc::Sender<ScanEvent>, ev: ScanEvent) {
    let _ = tx.blocking_send(ev);
}

fn hostname_fallback() -> String {
    std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".into())
}

struct Tui {
    terminal: Terminal<CrosstermBackend<Stdout>>,
}

impl Tui {
    fn enter() -> Result<Self> {
        enable_raw_mode().context("enable raw mode")?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen, DisableLineWrap).context("enter alt screen")?;
        let backend = CrosstermBackend::new(stdout);
        let terminal = Terminal::new(backend).context("create terminal")?;
        Ok(Self { terminal })
    }

    fn exit(this: &mut Self) -> Result<()> {
        disable_raw_mode().context("disable raw mode")?;
        execute!(
            this.terminal.backend_mut(),
            LeaveAlternateScreen,
            EnableLineWrap
        )
        .context("leave alt screen")?;
        this.terminal.show_cursor().context("show cursor")?;
        Ok(())
    }

    fn draw(&mut self, app: &App) -> Result<()> {
        self.terminal.draw(|f| draw_ui(f, app)).context("draw frame")?;
        Ok(())
    }
}

fn draw_ui(frame: &mut Frame, app: &App) {
    let root = frame.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(14),
            Constraint::Length(9),
        ])
        .split(root);

    draw_header(frame, chunks[0], app);

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(42), Constraint::Percentage(58)])
        .split(chunks[1]);

    draw_sections(frame, body[0], app);
    draw_detail(frame, body[1], app);

    draw_logs(frame, chunks[2], app);

    if app.show_help {
        draw_help(frame, centered_rect(72, 60, root));
    }
}

fn draw_header(frame: &mut Frame, area: Rect, app: &App) {
    let (verdict, verdict_style) = app.verdict();
    let score = app.total_score();
    let total_scanned: u64 = app.sections.iter().map(|s| s.stats.visited).sum();
    let gauge = Gauge::default()
        .block(Block::default().borders(Borders::ALL).title("Overall progress"))
        .gauge_style(Style::default().fg(Color::Cyan).bg(Color::Black))
        .ratio(app.progress_ratio())
        .label(format!(
            "{}/{} sections  |  {} total scanned",
            app.done_sections, app.total_sections, total_scanned
        ));

    let header_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(40),
            Constraint::Min(30),
            Constraint::Length(26),
        ])
        .split(area);

    let started = app.started_at.format("%Y-%m-%d %H:%M:%S").to_string();
    let left = Paragraph::new(vec![
        Line::from(vec![
            Span::styled("Axios Incident Scanner", Style::default().add_modifier(Modifier::BOLD)),
        ]),
        Line::from(vec![
            Span::raw("Started: "),
            Span::styled(started, Style::default().fg(Color::Gray)),
        ]),
    ])
    .block(Block::default().borders(Borders::ALL).title("Session"));

    let right = Paragraph::new(vec![
        Line::from(vec![
            Span::raw("Verdict: "),
            Span::styled(verdict, verdict_style),
        ]),
        Line::from(vec![
            Span::raw("Risk score: "),
            Span::styled(score.to_string(), Style::default().fg(Color::Yellow)),
        ]),
    ])
    .block(Block::default().borders(Borders::ALL).title("Assessment"));

    frame.render_widget(left, header_chunks[0]);
    frame.render_widget(gauge, header_chunks[1]);
    frame.render_widget(right, header_chunks[2]);
}

const SPINNER_FRAMES: &[&str] = &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

fn draw_sections(frame: &mut Frame, area: Rect, app: &App) {
    // Use elapsed time to drive the spinner animation.
    let elapsed_ms = Local::now()
        .signed_duration_since(app.started_at)
        .num_milliseconds()
        .unsigned_abs() as usize;
    let spinner_idx = (elapsed_ms / 80) % SPINNER_FRAMES.len();

    let items = app
        .sections
        .iter()
        .map(|sec| {
            let arrow = if sec.expanded { "▾" } else { "▸" };
            let sev = sec.highest_severity();

            let (status_icon, status_label) = match sec.status {
                SectionStatus::Pending => (
                    Span::styled("○ ", Style::default().fg(Color::DarkGray)),
                    Span::styled("PENDING", Style::default().fg(Color::DarkGray)),
                ),
                SectionStatus::Running => (
                    Span::styled(
                        format!("{} ", SPINNER_FRAMES[spinner_idx]),
                        Style::default().fg(Color::Cyan),
                    ),
                    Span::styled("RUNNING", Style::default().fg(Color::Cyan)),
                ),
                SectionStatus::Done => (
                    Span::styled("● ", Style::default().fg(Color::Green)),
                    Span::styled("DONE", Style::default().fg(Color::Green)),
                ),
            };

            // Show scanned count inline for running/done sections.
            let progress_span = if sec.stats.visited > 0 {
                let count_style = match sec.status {
                    SectionStatus::Running => Style::default().fg(Color::Cyan),
                    _ => Style::default().fg(Color::DarkGray),
                };
                Span::styled(
                    format!("  {:>6} scanned", sec.stats.visited),
                    count_style,
                )
            } else {
                Span::raw("")
            };

            let findings_span = if sec.stats.matched > 0 {
                Span::styled(
                    format!("  {} found", sec.stats.matched),
                    sev.style(),
                )
            } else {
                Span::raw("")
            };

            ListItem::new(vec![
                Line::from(vec![
                    Span::styled(format!("{arrow} "), Style::default().fg(Color::Gray)),
                    status_icon,
                    Span::styled(sec.kind.title(), Style::default().add_modifier(Modifier::BOLD)),
                    Span::raw("  "),
                    status_label,
                ]),
                Line::from(vec![
                    Span::raw("     "),
                    Span::styled(
                        format!("score {}", sec.score()),
                        sev.style().add_modifier(Modifier::BOLD),
                    ),
                    progress_span,
                    findings_span,
                ]),
            ])
        })
        .collect::<Vec<_>>();

    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title("Sections"))
        .highlight_style(
            Style::default()
                .bg(Color::Rgb(28, 28, 40))
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("❯ ");

    let mut state = ListState::default();
    state.select(Some(app.selected));
    frame.render_stateful_widget(list, area, &mut state);
}

fn draw_detail(frame: &mut Frame, area: Rect, app: &App) {
    let sec = app.section(app.selected_kind());
    let split = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(8), Constraint::Min(8)])
        .split(area);

    let visited_str = format!("{} files/entries", sec.stats.visited);
    let matched_str = sec.stats.matched.to_string();
    let findings_str = sec.findings.len().to_string();
    let status_str = match sec.status {
        SectionStatus::Pending => "⏳ Pending",
        SectionStatus::Running => "🔄 Running",
        SectionStatus::Done => "✅ Done",
    };
    let root_str = app.config.roots.iter()
        .map(|r| r.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let stats = Table::new(
        vec![
            Row::new(vec!["Scan root", root_str.as_str()]),
            Row::new(vec!["Scanned", visited_str.as_str()]),
            Row::new(vec!["Matches", matched_str.as_str()]),
            Row::new(vec!["Findings", findings_str.as_str()]),
            Row::new(vec!["Status", status_str]),
        ],
        [Constraint::Length(14), Constraint::Min(10)],
    )
    .block(Block::default().borders(Borders::ALL).title(format!("Details — {}", sec.kind.title())))
    .column_spacing(2)
    .row_highlight_style(Style::default().bg(Color::Rgb(22, 22, 30)));

    frame.render_widget(stats, split[0]);

    let findings = if sec.findings.is_empty() {
        vec![ListItem::new(Line::from(Span::styled(
            "No findings yet",
            Style::default().fg(Color::DarkGray),
        )))]
    } else {
        sec.findings
            .iter()
            .rev()
            .map(|f| {
                ListItem::new(vec![
                    Line::from(vec![
                        Span::styled(format!("[{}] ", f.severity.label()), f.severity.style()),
                        Span::styled(
                            f.ts.format("%H:%M:%S").to_string(),
                            Style::default().fg(Color::Gray),
                        ),
                    ]),
                    Line::from(f.text.clone()),
                ])
            })
            .collect::<Vec<_>>()
    };

    let findings = List::new(findings)
        .block(Block::default().borders(Borders::ALL).title("Findings"));

    frame.render_widget(findings, split[1]);
}

fn draw_logs(frame: &mut Frame, area: Rect, app: &App) {
    let lines = app.logs.iter().cloned().collect::<Vec<_>>();
    let logs = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Live event stream")
                .title_bottom(Line::from(vec![
                    Span::styled(" q ", Style::default().fg(Color::Black).bg(Color::Gray)),
                    Span::raw(" quit  "),
                    Span::styled(" ↑/↓ ", Style::default().fg(Color::Black).bg(Color::Gray)),
                    Span::raw(" move  "),
                    Span::styled(" enter ", Style::default().fg(Color::Black).bg(Color::Gray)),
                    Span::raw(" toggle  "),
                    Span::styled(" a ", Style::default().fg(Color::Black).bg(Color::Gray)),
                    Span::raw(" expand all  "),
                    Span::styled(" c ", Style::default().fg(Color::Black).bg(Color::Gray)),
                    Span::raw(" collapse all  "),
                    Span::styled(" ? ", Style::default().fg(Color::Black).bg(Color::Gray)),
                    Span::raw(" help "),
                ])),
        )
        .wrap(Wrap { trim: false })
        .scroll((app.log_scroll, 0));

    frame.render_widget(logs, area);

    let mut scrollbar_state = ScrollbarState::default()
        .content_length(app.logs.len().max(1))
        .position(app.log_scroll as usize);
    frame.render_stateful_widget(
        Scrollbar::default().orientation(ScrollbarOrientation::VerticalRight),
        area.inner(Margin {
            vertical: 1,
            horizontal: 0,
        }),
        &mut scrollbar_state,
    );
}

fn draw_help(frame: &mut Frame, area: Rect) {
    frame.render_widget(Clear, area);
    let text = Paragraph::new(vec![
        Line::from(Span::styled(
            "Keyboard",
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from("q / Esc        Quit"),
        Line::from("↑ / ↓ or j / k Navigate sections"),
        Line::from("Enter / Space  Expand or collapse selected section"),
        Line::from("a              Expand all"),
        Line::from("c              Collapse all"),
        Line::from("? / h          Toggle help"),
        Line::from("PgUp / PgDn    Scroll live log"),
    ])
    .block(Block::default().borders(Borders::ALL).title("Help"))
    .wrap(Wrap { trim: true });

    frame.render_widget(text, area);
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(vertical[1])[1]
}