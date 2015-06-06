#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFSIZE 256

int main(int argc, char *argv[]) {
  printf("\tmalloc_target: Started\n");
  fflush(stdout);

  char *buf = malloc(BUFSIZE);
  printf("\tmalloc_target: Oh, a buffer! Let's write to it, shall we?\n");
  fflush(stdout);

  if(buf) {
    memset(buf, 0, BUFSIZE);
    sprintf(buf, "Hello world!");
    printf("\tmalloc_target: The buffer says \"%s\".\n", buf);
    fflush(stdout);
    free(buf);
  } else { 
    printf("\tmalloc_target: Blargh! Buffer was NULL and I am dead :(\n");
    sprintf(buf, "Goodbye cruel world!");
    fflush(stdout);
  }

  return 0;
}
