use core::{cell::RefCell, time::Duration};
use std::{
    env,
    fs::{self, OpenOptions},
    path::PathBuf,
    process,
};

use clap::{Arg, ArgAction, Command};
use libafl::{events::ProgressReporter, prelude::{ClientStats, Monitor, format_duration_hms, ClientId, Launcher, LlmpRestartingEventManager, EventConfig, Cores}};
use libafl::{
    bolts::{
        current_nanos,
        rands::StdRand,
        shmem::{ShMem, ShMemProvider, UnixShMemProvider},
        tuples::tuple_list,
        AsMutSlice,
    },
    corpus::{InMemoryOnDiskCorpus, OnDiskCorpus},
    events::SimpleEventManager,
    executors::forkserver::{ForkserverExecutor, TimeoutForkserverExecutor},
    feedback_or,
    feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    mutators::StdScheduledMutator,
    observers::{HitcountsMapObserver, StdMapObserver, TimeObserver},
    prelude::{current_time},
    schedulers::{
        powersched::PowerSchedule, IndexesLenTimeMinimizerScheduler, StdWeightedScheduler,
    },
    stages::power::StdPowerMutationalStage,
    state::StdState,
    Error, Evaluator,
};
use nix::sys::signal::Signal;
use riscv_mutator::{
    calibration::DummyCalibration,
    instructions::{
        riscv::{args, rv_i::ADD},
        Argument, Instruction,
    },
    mutator::all_riscv_mutations,
    program_input::ProgramInput,
};

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


/// Tracking monitor during fuzzing.
#[derive(Clone)]
pub struct HWFuzzMonitor
{
    start_time: Duration,
    client_stats: Vec<ClientStats>,
}

impl Monitor for HWFuzzMonitor
{
    /// the client monitor, mutable
    fn client_stats_mut(&mut self) -> &mut Vec<ClientStats> {
        &mut self.client_stats
    }

    /// the client monitor
    fn client_stats(&self) -> &[ClientStats] {
        &self.client_stats
    }

    /// Time this fuzzing run stated
    fn start_time(&mut self) -> Duration {
        self.start_time
    }

    fn display(&mut self, event_msg: String, sender_id: ClientId) {
        print!(
            "time: {}, clients: {}, interesting programs: {}, found taint violations: {}, execs: {}, exec/sec: {}",
            format_duration_hms(&(current_time() - self.start_time)),
            self.client_stats().len(),
            self.corpus_size(),
            self.objective_size(),
            self.total_execs(),
            self.execs_per_sec_pretty(),
        );
        let client = self.client_stats_mut_for(sender_id);
        for (key, val) in &client.user_monitor {
            print!(", {key}: {val}");
        }
        println!("");
    }
}

impl HWFuzzMonitor
{
    /// Creates the monitor, using the `current_time` as `start_time`.
    pub fn new() -> Self {
        Self {
            start_time: current_time(),
            client_stats: vec![],
        }
    }
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

    let _log = RefCell::new(OpenOptions::new().append(true).create(true).open(logfile)?);

    // 'While the monitor are state, they are usually used in the broker - which is likely never restarted
    //let monitor = HWFuzzTUI::new("HWFuzzer".to_string(), true);
    let monitor = HWFuzzMonitor::new();

    let shmem_provider = UnixShMemProvider::new().expect("Failed to init shared memory");
    
    let mut run_client = |state: Option<_>,
                          mut mgr: LlmpRestartingEventManager<_, _>,
                          _core_id| {
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
            InMemoryOnDiskCorpus::<ProgramInput>::new(corpus_dir.clone()).unwrap(),
            OnDiskCorpus::new(objective_dir.clone()).unwrap(),
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
        fuzzer
            .add_input(&mut state, &mut executor, &mut mgr, init)
            .expect("Failed to run empty input?");

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
            fuzzer.fuzz_one(&mut stages, &mut executor, &mut state, &mut mgr)?;
            last = mgr.maybe_report_progress(&mut state, last, monitor_timeout)?;
        }
    };

    let conf = EventConfig::AlwaysUnique;
    let cores = Cores::all()?;

    let launcher = Launcher::builder()
    .shmem_provider(shmem_provider)
    .configuration(conf)
    .cores(&cores)
    .monitor(monitor)
    .run_client(&mut run_client);

    let launcher = launcher.stdout_file(Some("/dev/null"));
    match launcher.build().launch() {
        Ok(()) => (),
        Err(Error::ShuttingDown) => println!("\nFuzzing stopped by user. Good Bye."),
        Err(err) => panic!("Fuzzing failed {err:?}"),
    }
    Ok(())
}
