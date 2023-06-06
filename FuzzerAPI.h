#ifndef FUZZER_API
#define FUZZER_API

#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <sstream>
#include <fstream>
#include <string>

#include <unistd.h>

/// Saves the given test case and annotates it with the given reason string
/// that will be displayed in the fuzzing interface.
/// @param reason A string that will be displayed in the fuzzing interface.
/// @param pathToTestCase Path to the test case on disk.
[[noreturn]]
void reportFuzzingIssue(std::string reason, std::string pathToTestCase) {
    // Read the env var set by the fuzzer to figure out where to store the
    // failure reason.
    const char *causeDirVar = "FUZZING_CAUSE_DIR";
    const char *causeDir = std::getenv(causeDirVar);
    std::cerr << "Found issue: " << reason << "\n";
    if (!causeDir) {
        std::cerr << "  Note: " << causeDirVar << " env var not set.\n";
        std::cerr << "  This is fine if you're running the target manually.\n";
        abort();
    }

    // Hash the test case file to always give the output an unique name.
    // The unique name is only necessary to record duplicates.
    std::ifstream testCase(pathToTestCase);
    if (testCase.bad()) {
        std::cerr << "Failed to read test case: " << pathToTestCase << "\n";
        abort();
    }
    // Read the test case.
    std::stringstream buffer;
    buffer << testCase.rdbuf();

    // Now hash the test case contents.
    std::uint64_t testCaseHashVal = std::hash<std::string>()(buffer.str());

    // Create a he string of the contents.
    std::stringstream testCaseHash;
    testCaseHash << std::hex << testCaseHashVal;

    std::string savedFileName = std::string(causeDir) + "/" + reason + "%";
    // Use only the first 16 bytes of the hash to avoid too long file names.
    const unsigned hashSize = 16;
    savedFileName += testCaseHash.str().substr(0, hashSize);

    // Copy the original test case to the cause dir.
    // This should probably move the file instead, but there is little
    // contention and it's not clear how AFL reacts to the input file being
    // moved.
    std::filesystem::copy(pathToTestCase, savedFileName);
    abort();
}

#endif // FUZZER_API