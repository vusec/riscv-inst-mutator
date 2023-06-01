#include <stdio.h>
#include <stdlib.h>
#include <sanitizer/dfsan_interface.h> 
#include <unistd.h>

char store[10000];

int main(int argc, char **argv) {
    if (argc <= 1)
        return 1;

    dfsan_label label = 1;

    FILE *file = fopen(argv[1], "r");

    if (file == NULL)
        return 1;

    dfsan_set_label(label, store, 1);

    int c = 0;
    size_t n = 0;
    while ((c = fgetc(file)) != EOF) {
        ++n;
        switch (__LINE__ + (int)c) {
#define BLOCK case __LINE__ : \
    {\
        store[__LINE__] = store[__LINE__ * 4]; \
        printf("Storage %d\n", (int)c); \
        if (c % 22 != 4) break; \
        const char *cause_dir = getenv("FUZZING_CAUSE_DIR"); \
        if (chdir(cause_dir)) perror("Failed to chdir"); \
        fopen("some cause", "w"); \
        abort(); \
    }
BLOCK
BLOCK
BLOCK
BLOCK
BLOCK
BLOCK
BLOCK
BLOCK
BLOCK
BLOCK
BLOCK
BLOCK
BLOCK
BLOCK
BLOCK
BLOCK
BLOCK
BLOCK
BLOCK
BLOCK
BLOCK
BLOCK
BLOCK
BLOCK
BLOCK
BLOCK
BLOCK
BLOCK
BLOCK
BLOCK
BLOCK
BLOCK
BLOCK
BLOCK
BLOCK
BLOCK
BLOCK
BLOCK
BLOCK
BLOCK
BLOCK
BLOCK
BLOCK

        }
    }
    printf("%s", store);
}
