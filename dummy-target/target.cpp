#include <stdio.h>
#include <stdlib.h>
#include <sanitizer/dfsan_interface.h> 

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
#define BLOCK case __LINE__ : { store[__LINE__] = store[__LINE__ * 4]; printf("Storage\n"); break; }
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
