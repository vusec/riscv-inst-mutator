use std::ptr::write;

use libafl::monitors::SimpleMonitor;
// rustc workaround below causes this.
#[allow(unused_imports)]
use libafl::{
    bolts::{current_nanos, rands::StdRand, tuples::tuple_list, AsSlice},
    corpus::InMemoryCorpus,
    events::SimpleEventManager,
    executors::{inprocess::InProcessExecutor, ExitKind},
    feedbacks::{CrashFeedback, MaxMapFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    generators::RandPrintablesGenerator,
    inputs::{BytesInput, HasTargetBytes},
    mutators::scheduled::StdScheduledMutator,
    observers::StdMapObserver,
    schedulers::QueueScheduler,
    stages::mutational::StdMutationalStage,
    state::StdState,
};
use riscv_mutator::instructions::riscv::args;
use riscv_mutator::instructions::riscv::rv_i::{ADD, ADDI};
use riscv_mutator::instructions::{self, Argument, Instruction};
// rustc workaround below causes this.
#[allow(unused_imports)]
use riscv_mutator::mutator::all_riscv_mutations;
use riscv_mutator::parser::parse_instructions;

/// Coverage map with explicit assignments due to the lack of instrumentation
static mut SIGNALS: [u8; 16] = [0; 16];
static mut SIGNALS_PTR: *mut u8 = unsafe { SIGNALS.as_mut_ptr() };

/// Assign a signal to the signals map
fn signals_set(idx: usize) {
    unsafe { write(SIGNALS_PTR.add(idx), 1) };
}

#[allow(clippy::similar_names, clippy::manual_assert)]
#[test]
pub fn integration_test() {
    // The closure that we want to fuzz.
    let mut harness = |input: &BytesInput| {
        let inst1 = Instruction::new(
            &ADD,
            vec![
                Argument::new(&args::RD, 1),
                Argument::new(&args::RS1, 2),
                Argument::new(&args::RS2, 4),
            ],
        );
        let inst2 = Instruction::new(
            &ADDI,
            vec![
                Argument::new(&args::RD, 3),
                Argument::new(&args::RS1, 5),
                Argument::new(&args::IMM12, 11),
            ],
        );

        let target = input.target_bytes();
        let buf = target.as_slice();

        let insts = parse_instructions(&buf.to_vec(), &instructions::sets::riscv_g());
        if insts.len() >= 2 {
            signals_set(0);
            if insts[0].template() == inst1.template() {
                signals_set(1);
                if insts[0] == inst1 {
                    signals_set(2);
                    if insts[1].template() == inst2.template() {
                        signals_set(3);
                        if insts[1] == inst2 {
                            signals_set(4);
                            #[cfg(unix)]
                            panic!("Artificial bug triggered =)");
                        }
                    }
                }
            }
        }

        ExitKind::Ok
    };

    let observer = unsafe { StdMapObserver::from_mut_ptr("signals", SIGNALS_PTR, SIGNALS.len()) };

    let mut feedback = MaxMapFeedback::new(&observer);

    let mut objective = CrashFeedback::new();

    let mut state = StdState::new(
        StdRand::with_seed(123),
        InMemoryCorpus::new(),
        InMemoryCorpus::new(),
        &mut feedback,
        &mut objective,
    )
    .unwrap();

    let mon = SimpleMonitor::new(|s| println!("{s}"));

    let mut mgr = SimpleEventManager::new(mon);

    let scheduler = QueueScheduler::new();

    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    let mut executor = InProcessExecutor::new(
        &mut harness,
        tuple_list!(observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
    )
    .expect("Failed to create the Executor");

    let mut generator = RandPrintablesGenerator::new(32);

    state
        .generate_initial_inputs(&mut fuzzer, &mut executor, &mut generator, &mut mgr, 100)
        .expect("Failed to generate the initial corpus");

    // Breaks rustc...
    #[cfg(None)]
    let mutator = StdScheduledMutator::new(all_riscv_mutations());

    // Breaks rustc...
    #[cfg(None)]
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    // Breaks rustc...
    #[cfg(None)]
    fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .expect("Error in the fuzzing loop");
}
