use std::collections::HashSet;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
use std::{env, fs};

use riscv_mutator::assembler::assemble_instructions;
use riscv_mutator::instructions::{self, Argument, Instruction, InstructionTemplate};

fn read_lines(filename: String) -> io::Lines<BufReader<File>> {
    let file = File::open(filename).unwrap();
    return io::BufReader::new(file).lines();
}

fn find_template(name: String) -> Result<&'static InstructionTemplate, String> {
    for inst in instructions::riscv::all() {
        if inst.name() == name {
            return Ok(inst);
        }
    }
    return Err("Could not find instruction with name ".to_owned() + &name);
}

fn parse_arg(inst: &'static InstructionTemplate, arg_str: String) -> Result<Argument, String> {
    let parts = arg_str.split("=");

    if parts.clone().count() != 2 {
        return Err(format!("Not in ARG=VALUE format: '{}'", arg_str));
    }

    let name = parts.clone().nth(0).clone();
    let value_str = parts.clone().nth(1).clone();

    if value_str.is_none() || value_str.unwrap().is_empty() {
        return Err(format!("Missing value in arg: {}", arg_str));
    }

    let spec = inst.op_with_name(name.unwrap().to_string());
    if spec.is_none() {
        return Err(format!(
            "Failed to find operand with name {}",
            name.unwrap()
        ));
    }

    if !value_str.unwrap().starts_with("0x") {
        return Err(format!("Missing '0x' prefix: {}", value_str.unwrap()));
    }

    let value = u32::from_str_radix(value_str.unwrap().trim_start_matches("0x"), 16);
    if value.is_err() {
        return Err(format!("Invalid hex value: {}", value_str.unwrap()));
    }
    Ok(Argument::new(&spec.unwrap(), value.unwrap()))
}

fn parse_inst(line: String) -> Result<Instruction, String> {
    let mut parts = line.split(" ").clone();
    let name = parts.nth(0).clone();
    let inst = find_template(name.unwrap().to_string())?;

    let mut args = Vec::<Argument>::new();

    let mut seen_ops = HashSet::<String>::new();

    for arg_str in parts {
        let arg = parse_arg(inst, arg_str.to_string());
        if arg.is_err() {
            return Err(format!(
                "Failed to parse '{}'. Reason: {}",
                arg_str,
                arg.err().unwrap()
            ));
        }
        let arg_name = arg.as_ref().unwrap().spec().name().to_string();
        if seen_ops.contains(&arg_name) {
            return Err(format!("Duplicate operand '{}'", arg_name));
        }
        seen_ops.insert(arg_name);
        args.push(arg.unwrap());
    }

    Ok(Instruction::new(inst, args))
}

fn main() {
    let args: Vec<String> = env::args().collect();

    let input = &args[1];
    let output = &args[2];

    let mut file = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .open(output)
        .expect("Failed to open output file.");

    let lines = read_lines(input.to_string());
    for line_or_err in lines {
        let line = line_or_err.unwrap();
        let inst = parse_inst(line);
        if inst.is_err() {
            eprintln!("error: {}", inst.err().unwrap());
            continue;
        }

        let out = assemble_instructions(&vec![inst.unwrap()]);

        file.write_all(&out).expect("Failed to write output file.");
    }
}

#[cfg(test)]
mod tests {
    use riscv_mutator::instructions::Instruction;

    use crate::parse_inst;

    fn dump_inst(inst: &Instruction) -> String {
        let mut result = inst.template().name().to_string();
        for op in inst.arguments() {
            result += " ";
            result += op.spec().name();
            result += "=";
            result += &format!("{:#x}", op.value()).to_string();
        }
        result
    }

    #[test]
    fn assembly_add() {
        let input = "addi rd=0x1 rs1=0x1 imm12=0x3";
        let inst = parse_inst(input.to_string()).unwrap();
        assert_eq!(dump_inst(&inst), input);
    }

    #[test]
    fn assembly_invalid_inst() {
        let parse = parse_inst("addasdf".to_string());
        assert!(parse.is_err_and(|s| s.contains("Could not find instruction")));
    }

    #[test]
    fn assembly_double_op() {
        let parse = parse_inst("addi rd=0x1 rd=0x1 rs1=0x1 imm12=0x3".to_string());
        assert!(parse.is_err_and(|s| s.contains("Duplicate operand")));
    }

    #[test]
    fn assembly_invalid_format() {
        let parse = parse_inst("addi rd==0x1 rs1=0x1 imm12=0x3".to_string());
        assert!(parse.is_err_and(|s| s.contains("Not in ARG=VALUE")));
    }

    #[test]
    fn assembly_invalid_op() {
        let parse = parse_inst("addi rERR=0x1 rs1=0x1 imm12=0x3".to_string());
        assert!(parse.is_err_and(|s| s.contains("Failed to find operand with name")));
    }

    #[test]
    fn assembly_no_value() {
        let parse = parse_inst("addi rd= rs1=0x1 imm12=0x3".to_string());
        assert!(parse.is_err_and(|s| s.contains("Missing value in arg")));
    }

    #[test]
    fn assembly_non_hex_prefix() {
        let parse = parse_inst("addi rd=1 rs1=0x1 imm12=0x3".to_string());
        assert!(parse.is_err_and(|s| s.contains("Missing '0x' prefix")));
    }

    #[test]
    fn assembly_non_hex_value() {
        let parse = parse_inst("addi rd=0xU rs1=0x1 imm12=0x3".to_string());
        assert!(parse.is_err_and(|s| s.contains("Invalid hex value")));
    }
}
