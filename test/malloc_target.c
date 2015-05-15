#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFSIZE 256

int main(int argc, char *argv[]) {
    char *buf = malloc(BUFSIZE);
    memset(buf, 0, BUFSIZE);
    sprintf(buf, "Hello world!");
    printf("The buffer says \"%s\".\n", buf);
    free(buf);
    return 0;
}
