#ifndef FUZZER_COVERAGE
#define FUZZER_COVERAGE

#include <cstdlib>
#include <cstdint>
#include <dlfcn.h>

extern "C" {
extern uint32_t __afl_map_size;
}

__attribute__((no_sanitize("memory")))
inline uint32_t getCurrentCoverage() {
  // Find the coverage map via dlsym.
  void *f = dlopen(nullptr, RTLD_NOW);
  if (f == nullptr) {
    std::cerr << "Failed to dlopen current process\n";
    std::abort();
  }

  void *obj = dlsym(f, "__afl_area_ptr");
  if (obj == nullptr) {
    std::cerr << "Failed to find __afl_area_ptr\n";
    std::abort();
  }

  // We got a pointer (because dlsym returns pointers) to the coverage map
  // pointer.
  char **ptr = (char **) obj;
  char *map_ptr = *ptr;
  if (map_ptr == nullptr) {
    std::cerr << "coverage map ptr is null?\n";
    std::abort();
  }

  uint32_t result = 0;
  for (uint32_t i = 0; i < __afl_map_size; ++i) {
      if (map_ptr[i])
        ++result;
  }
  return result;
}

inline double getCurrentCoveragePercent() {
  return getCurrentCoverage() / (double)__afl_map_size;
}

#endif // FUZZER_COVERAGE
