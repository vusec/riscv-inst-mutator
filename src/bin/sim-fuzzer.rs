use core::{cell::RefCell, time::Duration};
use std::{
    env,
    fs::{self, OpenOptions},
    io::Write,
    path::PathBuf,
    process,
};

use clap::{Arg, ArgAction, Command};
use libafl::{
    bolts::{
        current_nanos,
        rands::StdRand,
        shmem::{ShMem, ShMemProvider, UnixShMemProvider},
        tuples::{tuple_list},
        AsMutSlice,
    },
    corpus::{Corpus, InMemoryOnDiskCorpus, OnDiskCorpus},
    events::SimpleEventManager,
    executors::forkserver::{ForkserverExecutor, TimeoutForkserverExecutor},
    feedback_or,
    feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    mutators::{
        StdScheduledMutator,
    },
    observers::{HitcountsMapObserver, StdMapObserver, TimeObserver},
    schedulers::{
        powersched::PowerSchedule, IndexesLenTimeMinimizerScheduler, StdWeightedScheduler,
    },
    stages::{
        calibrate::CalibrationStage, power::StdPowerMutationalStage,
    },
    state::{HasCorpus, StdState},
    Error, Evaluator, prelude::{tui::TuiMonitor, SimpleMonitor, current_time},
};
use nix::sys::signal::Signal;
use riscv_mutator::{program_input::ProgramInput, instructions::{Instruction, Argument, riscv::{rv_i::ADD, args}}, mutator::all_riscv_mutations, calibration::DummyCalibration};
use libafl::events::ProgressReporter;

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
            Arg::new("logfile")
                .short('l')
                .long("logfile")
                .help("Duplicates all output to this file")
                .default_value("libafl.log"),
        )
        .arg(
            Arg::new("timeout")
                .short('t')
                .long("timeout")
                .help("Timeout for each individual execution, in milliseconds")
                .default_value("20000"),
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
            Arg::new("signal")
                .short('s')
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

    println!(
        "Workdir: {:?}",
        env::current_dir().unwrap().to_string_lossy().to_string()
    );

    // For fuzzbench, crashes and finds are inside the same `corpus` directory, in the "queue" and "crashes" subdir.
    let mut out_dir = PathBuf::from(
        res.get_one::<String>("out")
            .expect("The --output parameter is missing")
            .to_string(),
    );
    if fs::create_dir(&out_dir).is_err() {
        println!("Out dir at {:?} already exists.", &out_dir);
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
    )
    .expect("An error occurred while fuzzing");
}

/// The actual fuzzer
fn fuzz(
    corpus_dir: PathBuf,
    objective_dir: PathBuf,
    seed_dir: &PathBuf,
    timeout: Duration,
    executable: String,
    debug_child: bool,
    signal: Signal,
    arguments: &[String],
) -> Result<(), Error> {
    const MAP_SIZE: usize = 2_621_440;

    let logfile = "fuzz.log";

    let log = RefCell::new(OpenOptions::new().append(true).create(true).open(logfile)?);

    // 'While the monitor are state, they are usually used in the broker - which is likely never restarted
    let monitor = TuiMonitor::new("HWFuzzer".to_string(), true);
    // let monitor = SimpleMonitor::new(|s| {
    //     println!("LOG: '{s}'");
    //     writeln!(log.borrow_mut(), "{:?} {}", current_time(), s).unwrap();
    // });


    // The event manager handle the various events generated during the fuzzing loop
    // such as the notification of the addition of a new item to the corpus
    let mut mgr = SimpleEventManager::new(monitor);

    // The unix shmem provider for shared memory, to match AFL++'s shared memory at the target side
    let mut shmem_provider = UnixShMemProvider::new().unwrap();

    // The coverage map shared between observer and executor
    let mut shmem = shmem_provider.new_shmem(MAP_SIZE).unwrap();
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
        .program(executable)
        .debug_child(debug_child)
        .shmem_provider(&mut shmem_provider)
        .parse_afl_cmdline(arguments)
        .coverage_map_size(MAP_SIZE)
        .is_persistent(true)
        .build_dynamic_map(edges_observer, tuple_list!(time_observer))
        .unwrap();

    let mut executor = TimeoutForkserverExecutor::with_signal(forkserver, timeout, signal)
        .expect("Failed to create the executor.");

    let add_inst = Instruction::new(&ADD, vec![Argument::new(&args::RD, 1u32)]);
    let init = ProgramInput::new([add_inst].to_vec());
    fuzzer.add_input(&mut state, &mut executor, &mut mgr, init).expect("Failed to run empty input?");

    state
        .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &[seed_dir.clone()])
        .unwrap_or_else(|_| {
            println!("Failed to load initial corpus at {:?}", &seed_dir);
            process::exit(0);
        });

    // The order of the stages matter!
    let mut stages = tuple_list!(calibration, power);

    loop {
        let mut last = current_time();
        let monitor_timeout = Duration::from_secs(1);

        loop {
            fuzzer.fuzz_one(&mut stages, &mut executor, &mut state, &mut mgr)?;
            last = mgr.maybe_report_progress(&mut state, last, monitor_timeout)?;
        }
    }
}