use clap::Parser;
use colored::Colorize;
use crossterm::style::Stylize;
use riscv_mutator::instructions::Instruction;
use riscv_mutator::program_input::ProgramInput;
use riscv_mutator::{instructions, parser};
use std::fs;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    input: Vec<String>,
}

fn main() {
    let args = Args::parse();

    let multiple_files = args.input.len() != 1;
    for filename in args.input {
        // Print the file name when printing multiple files.
        if multiple_files {
            println!("{}:", filename.clone().bold().blue());
        }

        let buffer = fs::read(filename).expect("Failed to read file");
        let input = postcard::from_bytes::<ProgramInput>(buffer.as_slice());

        let program: Vec<Instruction>;

        if input.is_err() {
            eprintln!(
                "Note: Input file not in internal serialized format, assuming plain instructions"
            );
            program = parser::parse_instructions(&buffer, &instructions::sets::riscv_g())
                .expect("Failed to parse instructions");
        } else {
            program = input.unwrap().insts().to_vec();
        }

        for inst in program {
            print!(" {}", Colorize::bold(inst.template().name()));
            for op in inst.arguments() {
                print!(
                    " {}={}",
                    Colorize::cyan(op.spec().name()),
                    format!("{:#x}", op.value()).red()
                );
            }
            println!("");
        }
    }
}
