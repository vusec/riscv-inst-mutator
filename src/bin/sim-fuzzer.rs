use core::time::Duration;
use std::{
    collections::HashMap,
    fs::{self, OpenOptions},
    io::Write,
    path::PathBuf,
    process,
    sync::{Arc, Mutex},
};

use clap::Parser;
use libafl::{
    bolts::{
        current_nanos,
        rands::StdRand,
        shmem::{ShMem, ShMemProvider, UnixShMemProvider},
        tuples::tuple_list,
        AsMutSlice,
    },
    corpus::{InMemoryOnDiskCorpus, OnDiskCorpus},
    executors::forkserver::{ForkserverExecutor, TimeoutForkserverExecutor},
    feedback_or,
    feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    mutators::StdScheduledMutator,
    observers::{HitcountsMapObserver, StdMapObserver, TimeObserver},
    prelude::current_time,
    schedulers::{
        powersched::PowerSchedule, IndexesLenTimeMinimizerScheduler, StdWeightedScheduler,
    },
    stages::power::StdPowerMutationalStage,
    state::StdState,
    Error, Evaluator,
};
use libafl::{
    events::ProgressReporter,
    prelude::{Cores, EventConfig, Launcher, LlmpRestartingEventManager},
};
use libafl::{
    prelude::{ondisk::OnDiskMetadataFormat, CoreId},
    stages::{MapEqualityFactory, StdTMinMutationalStage},
};
use nix::sys::signal::Signal;
use riscv_mutator::{
    calibration::DummyCalibration,
    causes::{list_causes, FUZZING_CAUSE_DIR_VAR},
    fuzz_ui::FuzzUI,
    instructions::{
        riscv::{
            args,
            rv64_i::LD,
            rv_i::{ADDI, AUIPC},
        },
        Argument, Instruction,
    },
    monitor::HWFuzzMonitor,
    mutator::{all_riscv_mutations, reducing_mutations},
    program_input::ProgramInput,
};

use log::{LevelFilter, Metadata, Record};

struct FuzzLogger;

pub const FUZZING_LOG_DIR_VAR: &'static str = "FUZZING_LOG_DIR";

impl log::Log for FuzzLogger {
    fn enabled(&self, _metadata: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &Record) {
        let log_dir = std::env::var(FUZZING_LOG_DIR_VAR).unwrap_or(".".to_owned());
        let logfile = format!("{}/fuzzer-pid_{}.log", log_dir, process::id());
        let mut dd = OpenOptions::new()
            .append(true)
            .create(true)
            .open(logfile)
            .expect("Failed to open log");
        dd.write_all(format!("{:?}\n", record).as_bytes())
            .expect("Failed to write log");
    }

    fn flush(&self) {}
}
static LOGGER: FuzzLogger = FuzzLogger;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    arguments: Vec<String>,
    #[arg(short, long, default_value = "in")]
    input: String,
    #[arg(short, long, default_value = "out")]
    out: String,
    #[arg(short, long, default_value_t = 60000)]
    timeout: u64,
    #[arg(short, long, default_value = "all")]
    cores: String,
    #[arg(long, default_value_t = false)]
    log: bool,
    #[arg(long, default_value_t = false)]
    save_inputs: bool,
    #[arg(short, long, default_value_t = false)]
    simple_ui: bool,
    #[arg(short, long, default_value_t = false)]
    minimize: bool,
    #[arg(long, default_value = "explore")]
    scheduler: String,
    #[arg(long, default_value = "default")]
    mutations: String,
    #[arg(long, default_value_t = 0)]
    port: u16,
}

pub fn main() {
    let args = Args::parse();
    let out_dir = PathBuf::from(args.out);

    let mut log_dir = out_dir.clone();
    log_dir.push("logs");
    std::fs::create_dir_all(log_dir.clone()).expect("Failed to create 'logs' directory.");
    std::env::set_var(FUZZING_LOG_DIR_VAR, log_dir.as_os_str());

    let fuzzing_level = if args.log {
        LevelFilter::Info
    } else {
        LevelFilter::Warn
    };
    log::set_logger(&LOGGER)
        .map(|()| log::set_max_level(fuzzing_level))
        .expect("Failed to setup logger.");

    if fs::create_dir(&out_dir).is_err() {
        if !out_dir.is_dir() {
            println!("Out dir at {:?} is not a valid directory!", &out_dir);
            return;
        }
    }
    let mut crashes = out_dir.clone();
    crashes.push("found");

    let mut cause_dir = out_dir.clone();
    cause_dir.push("causes");
    std::fs::create_dir_all(cause_dir.clone()).expect("Failed to create 'causes' directory.");

    let mut start_time_marker = out_dir.clone();
    start_time_marker.push("start_time_marker");
    std::fs::File::create(start_time_marker).expect("Failed to create start time marker");

    std::env::set_var(FUZZING_CAUSE_DIR_VAR, cause_dir.as_os_str());

    // If asked to save inputs, set the environment variable so the driver can
    // save the inputs for us. Also see the FuzzerAPI.h header.
    if args.save_inputs {
        let mut inputs_dir = out_dir.clone();
        inputs_dir.push("inputs");
        std::fs::create_dir_all(inputs_dir.clone())
            .expect("Failed to create 'inputs' subdirectory directory.");
        std::env::set_var("INPUT_STORAGE", inputs_dir.as_os_str());
    }

    let mut queue_dir = out_dir.clone();
    queue_dir.push("queue");

    let in_dir = PathBuf::from(args.input);
    if !in_dir.is_dir() {
        println!("In dir at {:?} is not a valid directory!", &in_dir);
        return;
    }

    let timeout = Duration::from_millis(args.timeout);
    let executable = args.arguments.first().unwrap();
    let debug_child = false;
    let simple_ui = args.simple_ui;
    let cores = Cores::from_cmdline(&args.cores.to_string()).expect("Failed to parse --cores arg");
    let signal = str::parse::<Signal>("SIGKILL").unwrap();
    let arguments = &args.arguments[1..];

    let scheduler_map: HashMap<String, PowerSchedule> = HashMap::from([
        ("explore".to_owned(), PowerSchedule::EXPLORE),
        ("fast".to_owned(), PowerSchedule::FAST),
        ("exploit".to_owned(), PowerSchedule::EXPLOIT),
    ]);
    let scheduler = scheduler_map.get(&args.scheduler);
    if scheduler.is_none() {
        println!(
            "Unknown scheduler {:?}. Supported schedulers: {:?}",
            args.scheduler,
            scheduler_map.keys()
        );
        return;
    }

    let port = if args.port == 0 {
        None
    } else {
        Some(args.port)
    };

    fuzz(
        out_dir,
        queue_dir,
        crashes,
        &in_dir,
        timeout,
        executable,
        debug_child,
        signal,
        &arguments,
        cores,
        simple_ui,
        scheduler.copied(),
        port,
        args.minimize,
    )
    .expect("An error occurred while fuzzing");
}

/// The actual fuzzer
fn fuzz(
    out_dir: PathBuf,
    base_corpus_dir: PathBuf,
    base_objective_dir: PathBuf,
    _seed_dir: &PathBuf, // Currently unused because seed parsing not implemented.
    timeout: Duration,
    executable: &String,
    debug_child: bool,
    signal: Signal,
    arguments: &[String],
    cores: Cores,
    simple_ui: bool,
    schedule: Option<PowerSchedule>,
    port: Option<u16>,
    minimize: bool,
) -> Result<(), Error> {
    let ui: Arc<Mutex<FuzzUI>> = Arc::new(Mutex::new(FuzzUI::new(simple_ui)));
    const MAP_SIZE: usize = 2_621_440;
    let start_time = current_time();

    let monitor = HWFuzzMonitor::new(
        ui,
        out_dir
            .to_str()
            .expect("Out dir is not valid utf-8?")
            .to_owned(),
    );

    let shmem_provider = UnixShMemProvider::new().expect("Failed to init shared memory");
    let mut shmem_provider_client = shmem_provider.clone();

    let mut run_client =
        |_state: Option<_>, mut mgr: LlmpRestartingEventManager<_, _>, core_id: CoreId| {
            // The coverage map shared between observer and executor
            let mut shmem = shmem_provider_client.new_shmem(MAP_SIZE).unwrap();

            // let the forkserver know the shmid
            shmem.write_to_env("__AFL_SHM_ID").unwrap();
            let shmem_buf = shmem.as_mut_slice();

            // To let know the AFL++ binary that we have a big map
            std::env::set_var("AFL_MAP_SIZE", format!("{}", MAP_SIZE));

            // Create an observation channel using the hitcounts map of AFL++
            let edges_observer =
                unsafe { HitcountsMapObserver::new(StdMapObserver::new("shared_mem", shmem_buf)) };

            // Create an observation channel to keep track of the execution time
            let time_observer = TimeObserver::new("time");

            let map_feedback = MaxMapFeedback::tracking(&edges_observer, true, false);

            let calibration = DummyCalibration::new(&map_feedback);

            // Feedback to rate the interestingness of an input
            // This one is composed by two Feedbacks in OR
            let mut feedback = feedback_or!(
                // New maximization map feedback linked to the edges observer and the feedback state
                map_feedback,
                // Time feedback, this one does not need a feedback state
                TimeFeedback::with_observer(&time_observer)
            );

            // Create client specific directories to avoid race conditions when
            // writing the corpus to disk.
            let mut corpus_dir = base_corpus_dir.clone();
            corpus_dir.push(format!("{}", core_id.0));
            let mut objective_dir = base_objective_dir.clone();
            objective_dir.push(format!("{}", core_id.0));

            // A feedback to choose if an input is a solution or not
            let mut objective = CrashFeedback::new();

            // Create the fuzz state.
            let mut state = StdState::new(
                StdRand::with_seed(current_nanos()),
                InMemoryOnDiskCorpus::<ProgramInput>::with_meta_format(
                    corpus_dir,
                    OnDiskMetadataFormat::Postcard,
                )
                .unwrap(),
                OnDiskCorpus::new(objective_dir).unwrap(),
                &mut feedback,
                &mut objective,
            )
            .unwrap();

            let mutator = StdScheduledMutator::new(all_riscv_mutations());

            let power = StdPowerMutationalStage::new(mutator);

            let min_mutator = StdScheduledMutator::new(reducing_mutations());
            let min_runs = if minimize { 100 } else { 1 };
            let factory = MapEqualityFactory::with_observer(&edges_observer);
            let minimizer = StdTMinMutationalStage::new(min_mutator, factory, min_runs);

            // A minimization+queue policy to get testcasess from the corpus
            let scheduler = IndexesLenTimeMinimizerScheduler::new(
                StdWeightedScheduler::with_schedule(&mut state, &edges_observer, schedule),
            );

            // A fuzzer with feedbacks and a corpus scheduler
            let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

            let forkserver = ForkserverExecutor::builder()
                .program(executable.clone())
                .debug_child(debug_child)
                .parse_afl_cmdline(arguments)
                .coverage_map_size(MAP_SIZE)
                .is_persistent(false)
                .build_dynamic_map(edges_observer, tuple_list!(time_observer))
                .unwrap();

            let mut executor = TimeoutForkserverExecutor::with_signal(forkserver, timeout, signal)
                .expect("Failed to create the executor.");

            // Load the initial seeds from the user directory.
            // state
            //     .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &[seed_dir.clone()])
            //     .unwrap_or_else(|_| {
            //         println!("Failed to load initial corpus at {:?}", &seed_dir);
            //         process::exit(0);
            //     });

            // Always add at least one dummy seed otherwise LibAFL crashes...
            // Do this after loading the seed folder as LibAFL otherwise also crashes...
            // We have to do at least one load in the initial seed otherwise our
            // feedback somehow causes libafl to break...
            let auipc = Instruction::new(&AUIPC, vec![Argument::new(&args::RD, 1u32)]);
            let load = Instruction::new(
                &LD,
                vec![
                    Argument::new(&args::RD, 2u32),
                    Argument::new(&args::RS1, 1u32),
                ],
            );
            // Add some random instructions to the seed.
            let pad_inst1 = Instruction::new(
                &ADDI,
                vec![
                    Argument::new(&args::RD, 3u32),
                    Argument::new(&args::RS1, 1u32),
                    Argument::new(&args::IMM20, 8u32),
                ],
            );
            let pad_inst2 = Instruction::new(
                &ADDI,
                vec![
                    Argument::new(&args::RD, 2u32),
                    Argument::new(&args::RS1, 3u32),
                    Argument::new(&args::IMM20, 4u32),
                ],
            );

            let init = ProgramInput::new([auipc, load, pad_inst1, pad_inst2].to_vec());
            fuzzer
                .add_input(&mut state, &mut executor, &mut mgr, init)
                .expect("Failed to load initial inputs");

            // First calibrate the initial seed and then mutate.
            let mut stages = tuple_list!(calibration, power, minimizer);

            // Main fuzzing loop.
            let mut last = current_time();
            let monitor_timeout = Duration::from_secs(1);

            loop {
                let fuzz_err = fuzzer.fuzz_one(&mut stages, &mut executor, &mut state, &mut mgr);
                if fuzz_err.is_err() {
                    log::error!("fuzz_one error: {}", fuzz_err.err().unwrap());
                }
                let last_err = mgr.maybe_report_progress(&mut state, last, monitor_timeout);
                if last_err.is_err() {
                    log::error!("last_err error: {}", last_err.err().unwrap());
                } else {
                    last = last_err.ok().unwrap()
                }

                // If we have a simple UI, we need to manually list all causes
                // to check if we found all bugs.
                if simple_ui {
                    list_causes(start_time);
                }
            }
        };

    let conf = EventConfig::from_build_id();

    let random_port = 8000u16 + cores.ids.first().unwrap().0 as u16;
    let actual_port = port.or(Some(random_port)).unwrap();

    if simple_ui {
        println!("Using Port: {:#?}", actual_port);
    }

    let launcher = Launcher::builder()
        .shmem_provider(shmem_provider)
        .configuration(conf)
        .cores(&cores)
        .monitor(monitor)
        .serialize_state(false)
        .broker_port(actual_port)
        .run_client(&mut run_client);

    let mut launcher_log_file = out_dir.clone();
    launcher_log_file.push("launch_log");

    let launcher = launcher.stdout_file(Some(launcher_log_file.to_str().unwrap()));
    match launcher.build().launch() {
        Ok(()) => (),
        Err(Error::ShuttingDown) => {
            println!("\nShutting down Fuzzer.")
        }
        Err(err) => panic!("Fuzzer error: {err:?}"),
    }
    Ok(())
}
