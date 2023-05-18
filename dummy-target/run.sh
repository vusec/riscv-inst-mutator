#!/bin/bash

set -e

mkdir -p in
mkdir -p out

../../AFL/afl-clang-fast++ -fsanitize=dataflow -O1 -g target.cpp -o target
cargo build # --release
clear
../target/debug/sim-fuzzer -i in -o out ./target @@
