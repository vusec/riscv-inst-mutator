#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    if (argc <= 1)
        return 1;

    FILE *file = fopen(argv[1], "r");

    if (file == NULL)
        return 1;

    int c = 0;
    size_t n = 0;
    while ((c = fgetc(file)) != EOF) {
        ++n;
        switch ((__LINE__ + c) % n) {
#define BLOCK case __LINE__ : printf(__PRETTY_FUNCTION__ + __LINE__); break;
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
}