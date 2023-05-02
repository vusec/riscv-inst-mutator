use crate::instructions::{Instruction, InstructionTemplate};

pub fn parse_instructions(
    input: &Vec<u8>,
    insts: &Vec<&'static InstructionTemplate>,
) -> Vec<Instruction> {
    let mut result = Vec::<Instruction>::new();

    for i in (0..input.len()).step_by(4) {
        if i + 4 > input.len() {
            continue;
        }
        let data = u32::from_ne_bytes(input[i..i + 4].try_into().unwrap());

        for inst in insts {
            let maybe_parsed = inst.decode(data);
            if let Some(..) = maybe_parsed {
                result.push(maybe_parsed.unwrap());
            }
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use libafl::prelude::{Rand, Xoshiro256StarRand};

    use crate::instructions;

    use super::parse_instructions;

    #[test]
    fn parse_random_bytes() {
        for i in 0..10000 {
            let mut rng = Xoshiro256StarRand::default();
            rng.set_seed(i);

            let mut input = Vec::<u8>::new();
            for _ in 0..rng.below(100) {
                input.push((rng.next() % 256) as u8);
            }

            let parsed = parse_instructions(&input, &instructions::sets::riscv_g());
            assert!(parsed.len() * 4 <= input.len());
        }
    }
}
