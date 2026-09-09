"""Test target - intentionally vulnerable C program."""

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

// Parse a simple binary format: [size:1 byte][data:size bytes]
void parse_input(unsigned char* input, int input_size) {
    if (input_size < 1) {
        return;
    }

    unsigned char size = input[0];
    unsigned char buffer[32];  // OVERFLOW VULNERABILITY: buffer too small

    // Stack buffer overflow when size > 32
    if (size > 0) {
        memcpy(buffer, input + 1, size);
    }
}

void use_after_free_test(unsigned char* input, int input_size) {
    if (input_size < 1) {
        return;
    }

    int* ptr = (int*)malloc(sizeof(int));
    *ptr = 42;

    if (input[0] == 0xFF) {
        free(ptr);
        // USE-AFTER-FREE VULNERABILITY: accessing after free
        *ptr = 100;
    }
}

void undefined_behavior_test(unsigned char* input, int input_size) {
    if (input_size < 1) {
        return;
    }

    int* ptr = NULL;
    if (input[0] == 0xAA) {
        // NULL DEREFERENCE VULNERABILITY
        *ptr = input[1];
    }
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
        return 1;
    }

    FILE* f = fopen(argv[1], "rb");
    if (!f) {
        fprintf(stderr, "Cannot open file\n");
        return 1;
    }

    unsigned char buffer[256];
    int size = fread(buffer, 1, sizeof(buffer), f);
    fclose(f);

    parse_input(buffer, size);
    use_after_free_test(buffer, size);
    undefined_behavior_test(buffer, size);

    return 0;
}
