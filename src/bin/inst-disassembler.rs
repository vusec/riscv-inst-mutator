use std::env;
use std::{
    fs::{self, File},
    io::Read,
};

use riscv_mutator::instructions;
use riscv_mutator::parser;

use colored::Colorize;

fn main() {
    let args: Vec<String> = env::args().collect();

    let filename = &args[1];

    let mut f = File::open(&filename).expect("no file found");

    let metadata = fs::metadata(&filename).expect("unable to read metadata");
    let mut buffer = Vec::<u8>::new();
    buffer.resize(metadata.len() as usize, 0);

    f.read(&mut buffer).expect("buffer overflow");

    let program = parser::parse_instructions(&buffer, &instructions::sets::riscv_g());

    for inst in program {
        print!("{}", inst.template().name().bold());
        for op in inst.arguments() {
            print!(
                " {}={}",
                op.spec().name().cyan(),
                format!("{:#x}", op.value()).red()
            );
        }
        println!("");
    }
}
