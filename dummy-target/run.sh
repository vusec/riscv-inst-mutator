#!/bin/bash

set -e

mkdir -p in
mkdir -p out

cargo build # --release
../../AFL/afl-clang-fast++ -fsanitize=dataflow -O1 target.cpp -o target
clear
../target/debug/sim-fuzzer -i in -o out -c 1 ./target @@
