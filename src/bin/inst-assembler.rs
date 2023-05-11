use std::env;
use std::fs::File;
use std::io::{self, BufRead, BufReader};

use riscv_mutator::instructions::{self, Argument, Instruction, InstructionTemplate};

fn read_lines(filename: String) -> io::Lines<BufReader<File>> {
    let file = File::open(filename).unwrap();
    return io::BufReader::new(file).lines();
}

fn findTemplate(name: String) -> Result<&'static InstructionTemplate, String> {
    for inst in instructions::riscv::all() {
        if inst.name() == name {
            return Ok(inst);
        }
    }
    return Err("Could not find instruction with name ".to_owned() + &name);
}

fn parse_arg(inst: &'static InstructionTemplate, arg_str: String) -> Result<Argument, String> {
    let mut parts = arg_str.split("=");
    eprintln!("ERR: {}", parts.clone().collect::<String>().len());
    if parts.clone().count() != 2 {
        return Err(format!("Invalid ARG=VALUE pair: '{}'", arg_str));
    }

    let name = parts.nth(0).clone();
    let value_str = parts.nth(1).clone();

    if value_str.is_none() || value_str.unwrap().is_empty() {
        return Err(format!("Missing value in arg: {}", arg_str));
    }

    let spec = inst.op_with_name(name.unwrap().to_string());
    if spec.is_none() {
        return Err("Failed to find operand with value ".to_owned() + name.unwrap());
    }

    let value = u32::from_str_radix(value_str.unwrap().trim_start_matches("0x"), 16);
    if value.is_err() {
        return Err("Failed to parse hex value ".to_owned() + value_str.unwrap());
    }
    Ok(Argument::new(&spec.unwrap(), value.unwrap()))
}

fn parse_inst(line: String) -> Result<Instruction, String> {
    let mut parts = line.split(" ").clone();
    let name = parts.nth(0).clone();
    let inst = findTemplate(name.unwrap().to_string())?;

    let mut args = Vec::<Argument>::new();

    for arg_str in parts.skip(1) {
        let arg = parse_arg(inst, arg_str.to_string());
        if arg.is_err() {
            return Err("Failed to parse '".to_owned()
                + arg_str
                + "'. Reason: "
                + &arg.err().unwrap());
        }
        args.push(arg.unwrap());
    }

    Ok(Instruction::new(inst, args))
}

fn main() {
    let args: Vec<String> = env::args().collect();

    let filename = &args[1];

    let lines = read_lines(filename.to_string());
    for lineOrErr in lines {
        let line = lineOrErr.unwrap();
        let inst = parse_inst(line);
    }
}

#[cfg(test)]
mod tests {
    use riscv_mutator::instructions::Instruction;

    use crate::parse_inst;

    fn dump_inst(inst: &Instruction) -> String {
        let mut result = inst.template().name().to_string();
        for op in inst.arguments() {
            result += op.spec().name();
            result += " ";
            result += op.spec().name();
            result += "=";
            result += &format!("{:#x}", op.value()).to_string();
        }
        result
    }

    #[test]
    fn assembly_random_bytes() {
        let input = "addi rd=0x1 rs1=0x1 imm12=0x3";
        let inst = parse_inst(input.to_string()).unwrap();
        assert_eq!(dump_inst(&inst), input);
    }
}
