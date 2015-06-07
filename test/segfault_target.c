/*
 * segfault_target.c
 *
 * Dereferences a NULL pointer, causing a segfault. Used to test backtrace
 * functionality.
 *
 * How to use:
 *   $ bin/backtrace_sample bin/segfault_target
 */

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <sys/reg.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

void bar() {
  int *pointer = NULL;
  *pointer = 1;
}

void foo() {
  return bar();
}

int main() {
  foo();
  return 0;
}
