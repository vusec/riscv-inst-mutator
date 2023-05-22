use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use libafl::prelude::{current_time, format_duration_hms};
use std::{
    collections::VecDeque,
    io::{self, Stdout},
    time::{Duration, Instant},
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

pub struct FuzzUIData {
    pub max_coverage: Vec<(f64, f64)>,
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
    simple_ui: bool,
}

impl FuzzUI {
    pub fn new(simple_ui : bool) -> FuzzUI {
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
                simple_ui
            }
        } else {
            FuzzUI {
                terminal: None,
                last_tick: Instant::now(),
                data,
                simple_ui
            }
        }
    }

    pub fn data(&mut self) -> &mut FuzzUIData {
        &mut self.data
    }

    fn on_tick(&mut self) {
        if self.terminal.is_some() {
            self.terminal.draw(|f| ui(f, &self.data)).unwrap();
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
        if self.terminal.is_some() {
            // restore terminal
            disable_raw_mode().unwrap();
            execute!(
                self.terminal.backend_mut(),
                LeaveAlternateScreen,
                DisableMouseCapture
            )
            .unwrap();
            self.terminal.show_cursor().unwrap();
        }
    }
}

fn ui<B: Backend>(f: &mut Frame<B>, data: &FuzzUIData) {
    let size = f.size();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Ratio(1, 2), Constraint::Ratio(1, 2)].as_ref())
        .split(size);

    // Iterate through all elements in the `items` app and append some debug text to it.
    let items: Vec<ListItem> = data
        .messages
        .iter()
        .map(|i| ListItem::new(i.as_str()).style(Style::default()))
        .collect();

    let items = List::new(items).block(Block::default().borders(Borders::ALL).title("Messages"));

    // We can now render the item list
    f.render_widget(items, chunks[0]);

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
        .name("Coverage")
        .marker(symbols::Marker::Braille)
        .style(Style::default().fg(Color::Yellow))
        .graph_type(GraphType::Line)
        .data(coverage.as_slice())];

    let chart = Chart::new(datasets)
        .block(
            Block::default()
                .title(Span::styled(
                    "Maximum reached coverage",
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
                .title("Number of bytes in coverage map")
                .style(Style::default().fg(Color::Gray))
                .bounds([0.0, last_slot.1 * 1.1])
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
