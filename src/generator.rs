use crate::instructions::{Argument, ArgumentSpec, Instruction, InstructionTemplate};

/// Generates random RISC-V instructions.
#[derive(Default)]
pub struct InstGenerator {
    /// List of known arguments the generator should try to reuse.
    known_args: Vec<Argument>,
}

impl InstGenerator {
    pub fn new() -> Self {
        Self {
            known_args: Vec::<Argument>::new(),
        }
    }

    pub fn forward_args(&mut self, args: &[Argument]) {
        self.known_args.append(&mut args.to_vec())
    }

    pub fn generate_argument<R: libafl::prelude::Rand>(
        &self,
        rand: &mut R,
        arg: &'static ArgumentSpec,
    ) -> Argument {
        if rand.below(100) < 30 {
            let filtered = self.known_args.iter().filter(|x| x.spec() == arg);
            let options = filtered.collect::<Vec<&Argument>>();
            if !options.is_empty() {
                return *rand.choose(options);
            }
        }

        Argument::new(arg, rand.below(arg.max_value() as u64) as u32)
    }

    pub fn generate_instruction<R: libafl::prelude::Rand>(
        &self,
        rand: &mut R,
        insts: &Vec<&'static InstructionTemplate>,
    ) -> Instruction {
        assert!(!insts.is_empty());
        let template = rand.choose(insts.iter());

        let mut arguments = Vec::<Argument>::new();
        for arg in template.operands() {
            arguments.push(self.generate_argument(rand, arg));
        }
        Instruction::new(template, arguments)
    }

    pub fn generate_instructions<R: libafl::prelude::Rand>(
        &self,
        rand: &mut R,
        insts: &Vec<&'static InstructionTemplate>,
        number: u32,
    ) -> Vec<Instruction> {
        let mut result = Vec::<Instruction>::new();
        for _ in 0..number {
            result.push(self.generate_instruction(rand, insts));
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use libafl::prelude::{Rand, Xoshiro256StarRand};

    use crate::instructions::{self, Argument};

    use super::InstGenerator;

    #[test]
    fn generate_random_instructions() {
        for i in 0..10000 {
            let mut rng = Xoshiro256StarRand::default();
            rng.set_seed(i);

            let generator = InstGenerator::new();
            let _inst = generator.generate_instruction::<Xoshiro256StarRand>(
                &mut rng,
                &instructions::sets::riscv_g(),
            );
        }
    }

    #[test]
    fn generate_instructions_and_reuse_arguments() {
        for i in 0..20 {
            let mut rng = Xoshiro256StarRand::default();
            rng.set_seed(i);

            let mut generator = InstGenerator::new();

            // Tell the generator that there it should try emit instructions
            // that use x35 as RD.
            let magic_value: u32 = 35;
            generator.forward_args(&vec![Argument::new(
                &instructions::riscv::args::RD,
                magic_value,
            )]);

            let mut found = false;
            // Generate 100 instructions and check that one of them actually
            // use x35 as RD.
            for _ in 0..100 {
                let inst = generator.generate_instruction::<Xoshiro256StarRand>(
                    &mut rng,
                    &instructions::sets::riscv_g(),
                );
                for arg in inst.arguments() {
                    if arg.spec() == &instructions::riscv::args::RD && arg.value() == magic_value {
                        found = true;
                    }
                }
            }

            assert!(found);
        }
    }
}
