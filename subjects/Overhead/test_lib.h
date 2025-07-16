#ifndef TEST_LIB_H
#define TEST_LIB_H

#include <stdio.h>
#include <unistd.h>
#include <openssl/sha.h>

void foo(void) {
    printf("Inside foo\n");
}

void bar(int n) {
    for (int i = 0; i < n; i++) {
        printf("Inside bar: iteration %d\n", i);
        //sleep(1);
    }
}

#if defined(_MSC_VER)
#define EXPORT __declspec(dllexport)
#else // _MSC_VER
#define EXPORT __attribute__((visibility("default")))
#endif

EXPORT int Secret(char *str) {
  int i;
  unsigned char XOR[] = {0x51, 0x42, 0x44, 0x49, 0x46, 0x72, 0x69, 0x64, 0x61};
  size_t len = strlen(str);

  //printf("Input string is : %s\nEncrypted string is : \n", str);

  for (i = 0; i < len; i++) {
    printf("0x%x,", str[i] ^ XOR[i % sizeof(XOR)]);
  }
  printf("\n");
  fflush(stdout);
  return 0;
}

void Hello() { Secret("Hello world ! Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, sed diam voluptua. At vero eos et accusam et justo duo dolores et ea rebum. Stet clita kasd gubergren, no sea takimata sanctus est Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, sed diam voluptua. At vero eos et accusam et justo duo dolores et ea rebum. Stet clita kasd gubergren, no sea takimata sanctus est Lorem ipsum dolor sit amet."); }

void encrypt(char *text, int shift) {
    int i = 0;
    
    while (text[i] != '\0') {
        // Handle uppercase letters
        if (text[i] >= 'A' && text[i] <= 'Z') {
            text[i] = ((text[i] - 'A' + shift) % 26) + 'A';
        }
        // Handle lowercase letters
        else if (text[i] >= 'a' && text[i] <= 'z') {
            text[i] = ((text[i] - 'a' + shift) % 26) + 'a';
        }
        // Non-alphabetic characters remain unchanged
        i++;
    }
}

void Hello2(){
    char text[] = "Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, sed diam voluptua. At vero eos et accusam et justo duo dolores et ea rebum. Stet clita kasd gubergren, no sea takimata sanctus est Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, sed diam voluptua. At vero eos et accusam et justo duo dolores et ea rebum. Stet clita kasd gubergren, no sea takimata sanctus est Lorem ipsum dolor sit amet.";
    int shift = 13;

    //printf("Original text: %s\n", text);
    
    // Ensure shift is in valid range
    shift = shift % 26;
    if (shift < 0) {
        shift += 26;
    }

    encrypt(text, shift);
    //printf("Encrypted text: %s\n", text);
}

void calculate_sha256(const char *input, unsigned char output[SHA256_DIGEST_LENGTH]) {
    // Perform the SHA-256 hash calculation
    SHA256((unsigned char *)input, strlen(input), output);
}

void print_sha256(unsigned char hash[SHA256_DIGEST_LENGTH]) {
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        printf(" ");
    }
    printf("\n");
}

#endif // TEST_LIB_H