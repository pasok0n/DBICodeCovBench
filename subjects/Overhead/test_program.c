// test_program.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "test_lib.h"

int main(void) {
    sleep(1);
    // Print the PID so you know which process to target for injection.
    pid_t pid = getpid();
    printf("Test program started (PID: %d)\n", pid);

    foo();

    // Loop with a conditional branch.
    for (int i = 0; i < 10; i++) {
        if (i % 2 == 0) {
            printf("Even iteration %d\n", i);
        } else {
            printf("Odd iteration %d\n", i);
        }
    }
    Hello();
    Hello2();
    bar(3);

    const char *input = "Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, sed diam voluptua. At vero eos et accusam et justo duo dolores et ea rebum. Stet clita kasd gubergren, no sea takimata sanctus est Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, sed diam voluptua. At vero eos et accusam et justo duo dolores et ea rebum. Stet clita kasd gubergren, no sea takimata sanctus est Lorem ipsum dolor sit amet.";  // Hardcoded input string
    unsigned char hash[SHA256_DIGEST_LENGTH];

    calculate_sha256(input, hash);

    print_sha256(hash);

    printf("Test program finished\n");
    return 0;
}