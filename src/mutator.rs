use std::cmp::max;

use libafl::prelude::*;

use crate::{
    assembler::assemble_instructions,
    generator::InstGenerator,
    instructions::{self, Instruction},
    parser::parse_instructions, program_input::HasProgramInput,
};

/// Supported mutation strategies.
#[derive(Clone, Copy)]
pub enum Mutation {
    // Adds a new instruction.
    Add,
    // Replaces an instruction with a different new instruction.
    Replace,
    // Replaces an argument of an instruction with a different one.
    ReplaceArg,
    // Repeats one instruction several times.
    RepeatOne,
    // Repeats one instruction several times.
    RepeatSeveral,
    // Swaps two single instructions.
    SwapTwo,
    // Removes a single instruction.
    Remove,
}

/// Mutator for RISC-V instructions.
/// Operates on byte vectors that are parsed as RISC-V vectors.
/// Invalid instructions are just filtered from the input.
pub struct RiscVInstructionMutator {
    /// This should be a const generic argument but Rust doesn't support that.
    mutation: Mutation,
}

impl<I, S> Mutator<I, S> for RiscVInstructionMutator
where
    S: HasRand,
    I: HasProgramInput,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        self.mutate_impl(state.rand_mut(), input.insts_mut())
    }
}

impl Named for RiscVInstructionMutator {
    fn name(&self) -> &str {
        "RiscVInstructionMutator"
    }
}

pub struct EmptyProgramNotSupported;

impl RiscVInstructionMutator {
    pub fn new(mutation: Mutation) -> Self {
        Self { mutation }
    }

    /// Generates a random instruction.
    fn gen_inst<Rng: Rand>(&self, program: &Vec<Instruction>, rng: &mut Rng) -> Instruction {
        let mut generator = InstGenerator::new();

        for inst in program {
            generator.forward_args(inst.arguments())
        }

        generator.generate_instruction::<Rng>(rng, &instructions::sets::riscv_g())
    }

    /// Interprets the input bytes as RISC-V opcodes and mutates them.
    fn mutate_impl<Rng: Rand>(
        &self,
        rng: &mut Rng,
        program: &mut Vec<Instruction>,
    ) -> Result<MutationResult, Error> {
        if self.mutate_with(program, rng, self.mutation).is_none() {
            return Ok(MutationResult::Skipped);
        }

        Ok(MutationResult::Mutated)
    }

    /// Interprets the input bytes as RISC-V opcodes and mutates them.
    fn mutate_bytes<Rng: Rand>(
        &self,
        rng: &mut Rng,
        input: &mut Vec<u8>,
    ) -> Result<MutationResult, Error> {
        let mut program = parse_instructions(input, &instructions::sets::riscv_g());

        if self.mutate_with(&mut program, rng, self.mutation).is_none() {
            return Ok(MutationResult::Skipped);
        }

        *input = assemble_instructions(&program);
        Ok(MutationResult::Mutated)
    }

    ///
    fn mutate_with<Rng: Rand>(
        &self,
        program: &mut Vec<Instruction>,
        rng: &mut Rng,
        mutation: Mutation,
    ) -> Option<()> {
        let program_empty = program.is_empty();
        let program_len = program.len();
        let add_pos = |rng: &mut Rng| -> Option<usize> {
            if program_empty {
                return None;
            }
            Some(rng.below(max(program_len as u64, 1)) as usize)
        };

        let valid_pos = |rng: &mut Rng| -> Option<usize> {
            if program_empty {
                return None;
            }
            Some(rng.below(program_len as u64) as usize)
        };

        match mutation {
            Mutation::Add => {
                program.insert(add_pos(rng)?, self.gen_inst(program, rng));
            }
            Mutation::Replace => {
                // Keep replacing until we actually changed something.
                loop {
                    let pos = add_pos(rng)?;
                    let old_inst = program[pos].clone();
                    let new_inst = self.gen_inst(program, rng);
                    if new_inst != old_inst {
                        program[pos] = new_inst;
                        break;
                    }
                }
            }
            Mutation::ReplaceArg => {
                let pos = valid_pos(rng)?;
                let mut inst = program[pos].clone();
                if inst.arguments().is_empty() {
                    return None;
                }
                let old_arg = rng.choose(inst.arguments());
                let arg_spec = old_arg.spec();
                // Keep generating arguments until we find a new one.
                loop {
                    let new_arg = InstGenerator::new().generate_argument(rng, arg_spec);
                    if &new_arg == old_arg {
                        continue;
                    }
                    inst.set_arg(new_arg);
                    break;
                }
                program[pos] = inst;
            }
            Mutation::SwapTwo => {
                let pos = valid_pos(rng)?;
                let pos2 = valid_pos(rng)?;
                let backup = program[pos].clone();
                program[pos] = program[pos2].clone();
                program[pos2] = backup;
            }
            Mutation::RepeatOne => {
                let pos = valid_pos(rng)?;
                program.insert(pos, program[pos].clone());
            }
            Mutation::RepeatSeveral => {
                let pos = valid_pos(rng)?;
                for _ in 0..(rng.below(32) + 1) {
                    program.insert(pos, program[pos].clone());
                }
            }
            Mutation::Remove => {
                program.remove(valid_pos(rng)?);
            }
        }
        Some(())
    }
}

/// All the types of the function below repeated.
/// (A memorial to Rust's generic programming capabilities).
pub type RiscVMutationList = tuple_list_type!(
    RiscVInstructionMutator,
    RiscVInstructionMutator,
    RiscVInstructionMutator,
    RiscVInstructionMutator,
    RiscVInstructionMutator,
    RiscVInstructionMutator,
);

/// Provides a list of all supported RISC-V instruction mutators.
pub fn all_riscv_mutations() -> RiscVMutationList {
    tuple_list!(
        RiscVInstructionMutator::new(Mutation::Add),
        RiscVInstructionMutator::new(Mutation::Remove),
        RiscVInstructionMutator::new(Mutation::ReplaceArg),
        RiscVInstructionMutator::new(Mutation::Replace),
        RiscVInstructionMutator::new(Mutation::RepeatOne),
        RiscVInstructionMutator::new(Mutation::SwapTwo),
    )
}

#[cfg(test)]
mod tests {
    use std::cmp::min;

    use libafl::prelude::MutationResult;
    use libafl::prelude::Rand;
    use libafl::prelude::Xoshiro256StarRand;

    use crate::assembler::assemble_instructions;
    use crate::generator::InstGenerator;
    use crate::instructions;
    use crate::instructions::Instruction;
    use crate::instructions::InstructionTemplate;
    use crate::parser::parse_instructions;

    use super::Mutation;
    use super::RiscVInstructionMutator;

    /// The test harness.
    /// Contains all the data for the tests below and some utility code.
    struct TestSetup {
        /// The RNG used in the test.
        rng: Xoshiro256StarRand,
        /// Our mutator which operates on the data below.
        mutator: RiscVInstructionMutator,
        /// The current set of bytes we're mutating.
        data: Vec<u8>,
        /// The previous set of bytes before the last mutation.
        old_data: Vec<u8>,
        /// How many instructions have changed during the last mutation.
        changed_insts: u32,
    }

    impl TestSetup {
        fn new(mutation: Mutation) -> Self {
            Self {
                rng: Xoshiro256StarRand::default(),
                mutator: RiscVInstructionMutator::new(mutation),
                data: Vec::<u8>::new(),
                old_data: Vec::<u8>::new(),
                changed_insts: 0,
            }
        }

        /// Calculates how many instructions have changed.
        fn update_changed(&mut self) {
            self.changed_insts = 0;
            let new_insts = parse_instructions(&self.data, &instructions::sets::riscv_g());
            let old_insts = parse_instructions(&self.old_data, &instructions::sets::riscv_g());
            for i in 0..min(new_insts.len(), old_insts.len()) {
                if new_insts[i] != old_insts[i] {
                    self.changed_insts += 1;
                }
            }
        }

        /// Perform one mutation step and updates all relevant data.
        /// Returns true when mutation changed the data buffer.
        fn mutate(&mut self) -> bool {
            self.old_data = self.data.clone();
            let result = self.mutator.mutate_bytes(&mut self.rng, &mut self.data);
            self.update_changed();

            if result.is_ok() && result.unwrap() == MutationResult::Skipped {
                assert_eq!(self.data, self.old_data);
                return false;
            }
            true
        }

        /// Fill the byte vector with one specific encoded instruction.
        fn fill_one_inst(&mut self, template: &'static InstructionTemplate) {
            let inst = InstGenerator::new().generate_instruction(&mut self.rng, &vec![template]);
            self.data = assemble_instructions(&vec![inst]);
        }

        /// Fill the byte vector with random instructions.
        /// Does not guarantee that it generates any instructions.
        fn fill_random_inst(&mut self) {
            let generator = InstGenerator::new();
            let num_insts = self.rng.below(40) as u32;
            self.data = assemble_instructions(&generator.generate_instructions(
                &mut self.rng,
                &instructions::sets::riscv_g(),
                num_insts,
            ));
        }

        /// Returns the parsed instructions in the current buffer.
        fn parsed_insts(&self) -> Vec<Instruction> {
            parse_instructions(&self.data, &instructions::sets::riscv_g())
        }
    }

    const TRIES: u32 = 1000;

    #[test]
    fn mutate_add() {
        // Test that the 'Add' mutation only adds one instruction.
        let mut setup = TestSetup::new(Mutation::Add);

        for _ in 0..TRIES {
            if setup.mutate() {
                // Mutation should have added exactly one argument.
                assert_eq!(setup.data.len(), setup.old_data.len() + 4);
            }
        }
    }

    #[test]
    fn mutate_remove() {
        // Test that the 'Remove' mutation removes only one instruction.
        let mut setup = TestSetup::new(Mutation::Remove);

        for _ in 0..TRIES {
            setup.fill_random_inst();
            if setup.mutate() {
                // We should have removed exactly one instruction.
                assert_eq!(setup.data.len() + 4, setup.old_data.len());
            }
        }
    }

    #[test]
    fn mutate_remove_empty_input() {
        // Test that the 'Remove' mutation works on empty inputs.
        let mut setup = TestSetup::new(Mutation::Remove);

        for _ in 0..TRIES {
            // Should never succeed on empty inputs.
            assert!(!setup.mutate());
        }
    }

    #[test]
    fn mutate_replace() {
        // Test that replace only changes one instruction.
        let mut setup = TestSetup::new(Mutation::Replace);

        for _ in 0..TRIES {
            setup.fill_random_inst();
            if setup.mutate() {
                // One single instruction should have changed.
                assert_eq!(setup.data.len(), setup.old_data.len());
                assert_eq!(setup.changed_insts, 1);
            }
        }
    }

    #[test]
    fn mutate_replace_empty_input() {
        // Test that replace works on empty inputs.
        let mut setup = TestSetup::new(Mutation::Replace);

        for _ in 0..TRIES {
            // Should never succeed on empty inputs.
            assert!(!setup.mutate());
        }
    }

    #[test]
    fn mutate_replace_arg_single_instruction() {
        // Test that 'ReplaceArg' only replaces arguments.

        let mut setup = TestSetup::new(Mutation::ReplaceArg);

        for _ in 0..TRIES {
            setup.fill_one_inst(&instructions::riscv::rv_i::ADD);
            let original_inst = setup.parsed_insts()[0].clone();
            if setup.mutate() {
                // This mutation does not add new instructions.
                assert_eq!(setup.data.len(), setup.old_data.len());
                // Parse the new instruction we generated.
                let new_inst = setup.parsed_insts()[0].clone();

                // The instruction should still be the ADD we created.
                assert_eq!(
                    setup.parsed_insts()[0].template(),
                    &instructions::riscv::rv_i::ADD
                );
                // The arguments must have changed.
                assert_ne!(original_inst.arguments(), new_inst.arguments());
            }
        }
    }

    #[test]
    fn mutate_replace_arg_multiple_instructions() {
        // Test that 'ReplaceArg' doesn't add instructions and doesn't change
        // more than one.
        let mut setup = TestSetup::new(Mutation::ReplaceArg);

        for _ in 0..TRIES {
            setup.fill_random_inst();
            if setup.mutate() {
                // This mutation does not add/remove instructions.
                assert_eq!(setup.data.len(), setup.old_data.len());
                // This mutation changes only one instruction at a time.
                assert_eq!(setup.changed_insts, 1);
            }
        }
    }

    #[test]
    fn mutate_repeat() {
        // Test that 'RepeatOne' only adds instructions.
        let mut setup = TestSetup::new(Mutation::RepeatOne);

        for _ in 0..TRIES {
            setup.fill_random_inst();
            if setup.mutate() {
                // This mutation always adds instructions.
                assert!(setup.data.len() > setup.old_data.len());
            }
        }
    }

    #[test]
    fn mutate_repeat_empty() {
        // Test that 'RepeatOne' doesn't do anything on empty inputs.
        let mut setup = TestSetup::new(Mutation::RepeatOne);

        for _ in 0..TRIES {
            // Should never succeed on empty inputs.
            assert!(!setup.mutate());
        }
    }
}
