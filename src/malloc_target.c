#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFSIZE 256

int main(int argc, char *argv[]) {
    printf("Hello from malloc_target!\n");
    printf("malloc_target: malloc lives at %p, while main is at %p\n", malloc, main);
    fflush(stdout);
    char *buf = malloc(BUFSIZE);
    memset(buf, 0, BUFSIZE);
    sprintf(buf, "Hello world!");
    printf("The buffer says \"%s\".\n", buf);
    fflush(stdout);
    free(buf);
    printf("Goodbye from malloc_target!\n");
    fflush(stdout);
    return 0;
}
