use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use libafl::prelude::{current_time, format_duration_hms};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    io::{self, Stdout},
    path::Path,
    time::{Duration, Instant, UNIX_EPOCH},
};
use tui::{
    backend::{Backend, CrosstermBackend},
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    symbols,
    text::Span,
    widgets::{Axis, Block, Borders, Chart, Dataset, GraphType, List, ListItem},
    Frame, Terminal,
};

pub const FUZZING_CAUSE_DIR_VAR: &'static str = "FUZZING_CAUSE_DIR";

pub struct FuzzUIData {
    pub max_coverage: Vec<(f64, f64)>,
    // idiotic libafl folks decided that time point = duration (???)
    start_time: std::time::Duration,
    messages: VecDeque<String>,
}

impl FuzzUIData {
    pub fn add_max_coverage(&mut self, value: f64) {
        if self.max_coverage.is_empty() || self.max_coverage.last().unwrap().1 < value {
            self.max_coverage.push((self.rel_time_secs(), value))
        }
        // Only keep the last 200 messages as we won't be able to display
        // more than that with any reasonable terminal size.
        self.max_coverage.shrink_to(200);
    }

    pub fn add_message(&mut self, value: String) {
        self.messages.push_front(value);
    }

    fn rel_time_secs(&self) -> f64 {
        (current_time() - self.start_time).as_secs_f64()
    }
}

pub struct FuzzUI {
    terminal: Option<Terminal<CrosstermBackend<Stdout>>>,
    last_tick: Instant,
    data: FuzzUIData,
}

impl FuzzUI {
    pub fn new(simple_ui: bool) -> FuzzUI {
        let data = FuzzUIData {
            max_coverage: Vec::<(f64, f64)>::new(),
            start_time: current_time(),
            messages: VecDeque::<String>::new(),
        };
        if !simple_ui {
            // setup terminal
            enable_raw_mode().expect("Failed to enable raw terminal mode");
            let mut stdout = io::stdout();
            execute!(stdout, EnterAlternateScreen, EnableMouseCapture)
                .expect("Failed to enable terminal mode");
            let backend = CrosstermBackend::new(stdout);
            let terminal = Terminal::new(backend).expect("Failed to create terminal wrapper");
            FuzzUI {
                terminal: Some(terminal),
                last_tick: Instant::now(),
                data,
            }
        } else {
            FuzzUI {
                terminal: None,
                last_tick: Instant::now(),
                data,
            }
        }
    }

    pub fn data(&mut self) -> &mut FuzzUIData {
        &mut self.data
    }

    fn on_tick(&mut self) {
        if let Some(term) = self.terminal.as_mut() {
            term.draw(|f| ui(f, &self.data)).unwrap();
        } else {
            if !self.data.messages.is_empty() {
                println!("{}", self.data.messages.front().unwrap());
            }
        }

        let timeout = Duration::from_millis(1);
        if crossterm::event::poll(timeout).unwrap() {
            if let Event::Key(key) = event::read().unwrap() {
                if let KeyCode::Char('q') = key.code {
                    panic!("Exiting");
                }
            }
        }
    }

    pub fn try_tick(&mut self) {
        let tick_rate = Duration::from_millis(250);

        if self.last_tick.elapsed() >= tick_rate {
            self.on_tick();
            self.last_tick = Instant::now();
        }
    }
}

impl Drop for FuzzUI {
    fn drop(&mut self) {
        if let Some(term) = self.terminal.as_mut() {
            // restore terminal
            disable_raw_mode().unwrap();
            execute!(
                term.backend_mut(),
                LeaveAlternateScreen,
                DisableMouseCapture
            )
            .unwrap();
            term.show_cursor().unwrap();
        }
    }
}

struct TestCaseData {
    cause: String,
    time_to_exposure: Duration,
}

fn summarize_findings(data: &FuzzUIData) -> Vec<String> {
    let cause_dir =
        std::env::var(FUZZING_CAUSE_DIR_VAR).expect("Driver failed to set cause env var?");

    let causes = std::fs::read_dir(Path::new(&cause_dir)).expect("Failed to read causes dir");

    let mut case_list = Vec::<TestCaseData>::new();
    for cause_or_err in causes {
        let cause = cause_or_err.unwrap();
        let creation_time = cause.metadata().unwrap().created().unwrap();
        let creation_unix_time = creation_time.duration_since(UNIX_EPOCH).unwrap();
        let diff_time = creation_unix_time - data.start_time;

        let filename = cause.file_name().into_string().unwrap();
        let cause_str = filename.split("%").nth(0);

        case_list.push(TestCaseData {
            cause: cause_str.or(Some("Bad cause name")).unwrap().to_string(),
            time_to_exposure: diff_time,
        })
    }

    let mut dupes = HashMap::<String, u64>::new();
    for case in &case_list {
        dupes.insert(
            case.cause.clone(),
            dupes.get(&case.cause).or(Some(&0)).unwrap() + 1,
        );
    }

    case_list.sort_by_key(|t| t.time_to_exposure);

    let mut emitted_causes = HashSet::<String>::new();

    let mut result = Vec::<String>::new();
    for case in &case_list {
        if !emitted_causes.insert(case.cause.clone()) {
            break;
        }
        let res = format!(
            "{} (TTE: {}) Dupes: {}",
            case.cause,
            format_duration_hms(&case.time_to_exposure),
            dupes.get(&case.cause).unwrap()
        );
        result.push(res);
    }
    result
}

fn ui<B: Backend>(f: &mut Frame<B>, data: &FuzzUIData) {
    let size = f.size();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(size);

    let top_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Min(10), Constraint::Length(60)])
        .split(chunks[0]);

    let cause_list = summarize_findings(data);

    let findings: Vec<ListItem> = cause_list
        .iter()
        .map(|i| ListItem::new(i.as_str()).style(Style::default()))
        .collect();
    let findings_list =
        List::new(findings).block(Block::default().borders(Borders::ALL).title("Findings"));

    f.render_widget(findings_list, top_chunks[1]);

    // Iterate through all elements in the `items` app and append some debug text to it.
    let items: Vec<ListItem> = data
        .messages
        .iter()
        .map(|i| ListItem::new(i.as_str()).style(Style::default()))
        .collect();

    let items = List::new(items).block(Block::default().borders(Borders::ALL).title("Messages"));

    // We can now render the item list
    f.render_widget(items, top_chunks[0]);

    let last_slot = data
        .max_coverage
        .last()
        .or(Some(&(1.0 as f64, 10.0 as f64)))
        .unwrap()
        .clone();

    let mut coverage = data.max_coverage.clone();
    coverage.push((data.rel_time_secs(), last_slot.1));

    let max_time = format_duration_hms(&(current_time() - data.start_time));

    let datasets = vec![Dataset::default()
        .name("")
        .marker(symbols::Marker::Braille)
        .style(Style::default().fg(Color::Yellow))
        .graph_type(GraphType::Line)
        .data(coverage.as_slice())];

    let chart = Chart::new(datasets)
        .block(
            Block::default()
                .title(Span::styled(
                    "Coverage",
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ))
                .borders(Borders::ALL),
        )
        .x_axis(
            Axis::default()
                .title("Elapsed time (s)")
                .style(Style::default().fg(Color::Gray))
                .bounds([0.0, data.rel_time_secs()])
                .labels(vec![
                    Span::styled("0", Style::default().add_modifier(Modifier::BOLD)),
                    Span::styled(
                        format!("{}", max_time),
                        Style::default().add_modifier(Modifier::BOLD),
                    ),
                ]),
        )
        .y_axis(
            Axis::default()
                .title("Coverage")
                .style(Style::default().fg(Color::Gray))
                .bounds([0.0, last_slot.1 * 1.2])
                .labels(vec![
                    Span::styled("0", Style::default().add_modifier(Modifier::BOLD)),
                    Span::styled(
                        format!("{:0}", last_slot.1),
                        Style::default().add_modifier(Modifier::BOLD),
                    ),
                ]),
        );
    f.render_widget(chart, chunks[1]);
}
