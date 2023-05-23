use core::time::Duration;
use std::{
    env,
    fs::{self, OpenOptions},
    io::Write,
    path::PathBuf,
    process,
    sync::{Arc, Mutex},
};

use clap::{Arg, ArgAction, Command};
use libafl::{
    bolts::{
        current_nanos,
        rands::StdRand,
        shmem::{ShMem, ShMemProvider, UnixShMemProvider},
        tuples::tuple_list,
        AsMutSlice,
    },
    corpus::{InMemoryCorpus},
    executors::forkserver::{ForkserverExecutor, TimeoutForkserverExecutor},
    feedback_or,
    feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    mutators::StdScheduledMutator,
    observers::{HitcountsMapObserver, StdMapObserver, TimeObserver},
    prelude::{current_time, InMemoryOnDiskCorpus, OnDiskCorpus, CoreId},
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
use nix::{sys::signal::Signal};
use riscv_mutator::{
    calibration::DummyCalibration,
    fuzz_ui::FuzzUI,
    instructions::{
        riscv::{args, rv_i::ADD},
        Argument, Instruction,
    },
    monitor::HWFuzzMonitor,
    mutator::all_riscv_mutations,
    program_input::ProgramInput,
};

use log::{LevelFilter, Metadata, Record};
use libafl::prelude::CalibrationStage;

struct FuzzLogger;

impl log::Log for FuzzLogger {
    fn enabled(&self, _metadata: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &Record) {
        let logfile = format!("fuzzer-pid_{}.log", process::id());
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

pub fn main() {
    let res = match Command::new(env!("CARGO_PKG_NAME"))
        .version(env!("CARGO_PKG_VERSION"))
        .arg(
            Arg::new("out")
                .short('o')
                .long("output")
                .help("The directory to place finds in ('corpus')"),
        )
        .arg(
            Arg::new("in")
                .short('i')
                .long("input")
                .help("The directory to read initial inputs from ('seeds')"),
        )
        .arg(
            Arg::new("timeout")
                .short('t')
                .long("timeout")
                .help("Timeout for each individual execution, in milliseconds")
                .default_value("60000"),
        )
        .arg(
            Arg::new("cores")
                .short('c')
                .long("cores")
                .help("Which cores to use ('all', or '1', or '1-2,3-4'")
                .default_value("all"),
        )
        .arg(
            Arg::new("exec")
                .help("The instrumented binary we want to fuzz")
                .required(true),
        )
        .arg(
            Arg::new("debug-child")
                .short('d')
                .long("debug-child")
                .help("If not set, the child's stdout and stderror will be redirected to /dev/null")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("simple-ui")
                .short('s')
                .long("no-tui")
                .help("Use a simple log-based user interace.")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("log")
                .short('l')
                .long("log")
                .help("Create log files (which will be very large).")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("signal")
                .short('k')
                .long("signal")
                .help("Signal used to stop child")
                .default_value("SIGKILL"),
        )
        .arg(Arg::new("arguments"))
        .try_get_matches()
    {
        Ok(res) => res,
        Err(err) => {
            println!(
                "Syntax: {}, [-x dictionary] -o corpus_dir -i seed_dir\n{:?}",
                env::current_exe()
                    .unwrap_or_else(|_| "fuzzer".into())
                    .to_string_lossy(),
                err,
            );
            return;
        }
    };

    // For fuzzbench, crashes and finds are inside the same `corpus` directory, in the "queue" and "crashes" subdir.
    let mut out_dir = PathBuf::from(
        res.get_one::<String>("out")
            .expect("The --output parameter is missing")
            .to_string(),
    );
    if fs::create_dir(&out_dir).is_err() {
        if !out_dir.is_dir() {
            println!("Out dir at {:?} is not a valid directory!", &out_dir);
            return;
        }
    }
    let mut crashes = out_dir.clone();
    crashes.push("crashes");
    out_dir.push("queue");

    let in_dir = PathBuf::from(
        res.get_one::<String>("in")
            .expect("The --input parameter is missing")
            .to_string(),
    );
    if !in_dir.is_dir() {
        println!("In dir at {:?} is not a valid directory!", &in_dir);
        return;
    }

    let timeout = Duration::from_millis(
        res.get_one::<String>("timeout")
            .unwrap()
            .to_string()
            .parse()
            .expect("Could not parse timeout in milliseconds"),
    );

    let executable = res
        .get_one::<String>("exec")
        .expect("The executable is missing")
        .to_string();

    let debug_child = res.get_flag("debug-child");

    let simple_ui = res.get_flag("simple-ui");

    if res.get_flag("log") {
        log::set_logger(&LOGGER).map(|()| log::set_max_level(LevelFilter::Info))
            .expect("Failed to enable log.");
    }

    let cores = Cores::from_cmdline(
        res.get_one::<String>("cores")
            .expect("Failed to retrieve --cores arg"),
    )
    .expect("Failed to parse --cores arg");

    let signal = str::parse::<Signal>(
        &res.get_one::<String>("signal")
            .expect("The --signal parameter is missing")
            .to_string(),
    )
    .unwrap();

    let arguments = res
        .get_many::<String>("arguments")
        .map(|v| v.map(std::string::ToString::to_string).collect::<Vec<_>>())
        .unwrap_or_default();

    fuzz(
        out_dir,
        crashes,
        &in_dir,
        timeout,
        executable,
        debug_child,
        signal,
        &arguments,
        cores,
        simple_ui,
    )
    .expect("An error occurred while fuzzing");
}

/// The actual fuzzer
fn fuzz(
    base_corpus_dir: PathBuf,
    base_objective_dir: PathBuf,
    seed_dir: &PathBuf,
    timeout: Duration,
    executable: String,
    debug_child: bool,
    signal: Signal,
    arguments: &[String],
    cores: Cores,
    simple_ui: bool
) -> Result<(), Error> {
    let ui: Arc<Mutex<FuzzUI>> = Arc::new(Mutex::new(FuzzUI::new(simple_ui)));
    const MAP_SIZE: usize = 2_621_440;

    // 'While the monitor are state, they are usually used in the broker - which is likely never restarted
    let monitor = HWFuzzMonitor::new(ui);

    let shmem_provider = UnixShMemProvider::new().expect("Failed to init shared memory");
    let mut shmem_provider_client = shmem_provider.clone();

    let mut run_client = |_state: Option<_>,
                          mut mgr: LlmpRestartingEventManager<_, _>,
                          core_id : CoreId | {
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

        // A feedback to choose if an input is a solution or not
        let mut objective = CrashFeedback::new();

        // Create client specific directories to avoid race conditions when
        // writing the corpus to disk.
        let mut corpus_dir = base_corpus_dir.clone();
        corpus_dir.push(format!("{}", core_id.0));
        let mut objective_dir = base_objective_dir.clone();
        objective_dir.push(format!("{}", core_id.0));

        // create a State from scratch
        let mut state = StdState::new(
            StdRand::with_seed(current_nanos()),
            InMemoryOnDiskCorpus::<ProgramInput>::new(corpus_dir).unwrap(),
            OnDiskCorpus::new(objective_dir).unwrap(),
            &mut feedback,
            &mut objective,
        )
        .unwrap();

        let mutator = StdScheduledMutator::new(all_riscv_mutations());

        let power = StdPowerMutationalStage::new(mutator);

        // A minimization+queue policy to get testcasess from the corpus
        let scheduler = IndexesLenTimeMinimizerScheduler::new(StdWeightedScheduler::with_schedule(
            &mut state,
            &edges_observer,
            Some(PowerSchedule::EXPLORE),
        ));

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

        state
            .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &[seed_dir.clone()])
            .unwrap_or_else(|_| {
                println!("Failed to load initial corpus at {:?}", &seed_dir);
                process::exit(0);
            });

        // The order of the stages matter!
        let mut stages = tuple_list!(calibration, power);

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
        }
    };

    let conf = EventConfig::from_build_id();

    let launcher = Launcher::builder()
        .shmem_provider(shmem_provider)
        .configuration(conf)
        .cores(&cores)
        .monitor(monitor)
        .serialize_state(false)
        .run_client(&mut run_client);

    let launcher = launcher.stdout_file(Some("/dev/null"));
    match launcher.build().launch() {
        Ok(()) => (),
        Err(Error::ShuttingDown) => println!("\nFuzzing stopped by user. Good Bye."),
        Err(err) => panic!("Fuzzing failed {err:?}"),
    }
    Ok(())
}
