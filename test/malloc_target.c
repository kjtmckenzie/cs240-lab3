#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFSIZE 256

int main(int argc, char *argv[]) {
    char *buf = malloc(BUFSIZE);
    if(buf) {
      memset(buf, 0, BUFSIZE);
      sprintf(buf, "Hello world!");
      printf("The buffer says \"%s\".\n", buf);
      fflush(stdout);
      free(buf);
    } else { 
      printf("Buffer NULL\n");
      fflush(stdout);
    }

    buf = malloc(BUFSIZE);
    printf("%c\n", *buf);
    return 0;
}
