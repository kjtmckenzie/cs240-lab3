/*
 * getuid_target.c
 *
 * Trivial: prints its UID and exits. Used to test interception of syscalls.
 */

#include <stdio.h>
#include <unistd.h>

int main() {
  printf( "user id: %d\n", getuid() );
  return 0;
}
