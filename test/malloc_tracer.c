/*
 * malloc_tracer.c
 *
 * Not part of the main injector: a driver to test our interception of
 * libc function calls, like malloc().
 */

#define _XOPEN_SOURCE 500
#define _GNU_SOURCE

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
#include <stdbool.h>
#include "utils.h"
#include "breakfast.h"

#define BUFLEN 4096
#define MAX_TARGET_LEN 255
#define NUM_ARGS 5

void print_usage_and_exit() {
  printf("Usage: injector fn retval target callnum\n");
  printf("Where:\n");
  printf("        fn  = function to inject, e.g. 'malloc'\n");
  printf("    retval  = return value to inject, e.g. '0'\n");
  printf("    target  = statically-compiled target executable, e.g. 'bin/malloc_target'\n");
  printf("    callnum = callnum_th call will be intercepted\n");
  printf("Example:\n");
  printf("    bin/malloc_tracer malloc 0 bin/malloc_target 1\n");
  exit(1);
}

int main(int argc, char *argv[]) {
  if(argc != NUM_ARGS) {
    printf("Wrong number of arguments: %d for %d.\n", argc, NUM_ARGS);
    print_usage_and_exit();
  } else if (strlen(argv[3]) > MAX_TARGET_LEN) {
    printf("Target name cannot be longer than 255.\n");
    return -1;
  }

  // TODO: replace w/ argparse
  const char *fn = argv[1];
  long long int retval = atoll(argv[2]);
  char target[MAX_TARGET_LEN + 1];
  strncpy(target, argv[3], MAX_TARGET_LEN);
  int callnum = atoi (argv[4]);

  // TODO: replace w/ state
  int status = 0;
  int last_signum = 0;
  struct user_regs_struct regs;

  // TODO: add to state struct
  // Get all addrs where fn is called in target
  size_t n_addrs = 0;
  target_addr_t *addrs = get_fn_call_addrs(fn, target, &n_addrs);
  if (!addrs) {
    printf("get_fn_call_addrs failed\n");
    exit(-1);
  }

  // TODO: replace w/ start_target
  int pid = fork();
  if ( !pid ) {
    // Child: register as tracee and run target process
    printf("Child: execing %s!\n", target);
    fflush(stdout);
    ptrace(PTRACE_TRACEME, 0, 0, 0);
    execlp(target, target, NULL);  // never returns
  }

  wait( &status );
  printf("malloc_tracer: after outer wait\n");
  fflush(stdout);

  breakpoint_t *last_break = NULL;
  void *last_ip;

  // TODO: need "run_until_main" helper
  // Run until main is caught
  target_addr_t main_addr = get_fn_address("main", target);
  breakpoint_t *main_break = breakfast_create(pid, (target_addr_t) main_addr);
  printf("malloc_tracer: Skip preprocess. Main function should be called.\n");
  fflush(stdout);
  while(breakfast_run(pid, last_break)) {
    last_ip = breakfast_get_ip(pid);
    if(last_ip == main_addr) {
      last_break = main_break;
      break;
    }
  }
  printf("Main is called. Now our breakpoint is to be set.\n");
  fflush(stdout);

  // TODO: add breakpoints to state struct
  // Insert (enabled) breakpoints at all call sites of malloc()
  breakpoint_t **breakpoints = (breakpoint_t **) (malloc(n_addrs * sizeof(breakpoint_t *)));
  for(int i = 0; i < n_addrs; i++) {
    breakpoints[i] = breakfast_create(pid, addrs[i]);
  }

  ptrace(PTRACE_CONT, pid, 0, 0); 
  while ( 1 ) {
    printf("malloc_tracer: loop\n");
    fflush(stdout);
    wait( &status );

    if (WIFEXITED(status) || WIFSIGNALED(status)) {
      printf("malloc_tracer: breaking\n");
      fflush(stdout);
      break;
    }

    // TODO: add "state_get_breakpoint" helper
    last_ip = breakfast_get_ip(pid);
    int j;
    for(j = 0; j < n_addrs; j++) {
      if(last_ip == addrs[j]) {
        // Stopped at a breakpoint of ours?
        printf("malloc_tracer: last_ip=%p was in addrs\n", last_ip);
        fflush(stdout);
        break;
      }
    }

    if(j == n_addrs) {
      printf("Unknown trap at %p\n", last_ip);
      fflush(stdout);
      // Continue tracing by forwarding the same signal we intercepted
      last_signum = WSTOPSIG(status);
      ptrace(PTRACE_CONT, pid, 0, last_signum);
    } else {
      printf("malloc() breakpoint\n");
      fflush(stdout);
      last_break = breakpoints[j];

      // TODO: add "fault_function" helper
      ptrace(PTRACE_GETREGS, pid, 0, &regs);
      // "callq" is a 5 byte instruction, so this jumps over it and malloc()
      // is never called, and we fake the return value in %rax.
      // This is gross - surely there is a more robust way to skip the call?
      regs.rip += 5;
      regs.rax = retval;
      ptrace(PTRACE_SETREGS, pid, 0, &regs);

      // Set to original data and move one step
      breakfast_disable(pid, last_break);

      // TODO: Reset trap at address if we want to break there again!

      ptrace(PTRACE_CONT, pid, 0, 0);
    }

  }

  printf("malloc_tracer: All done!\n");
  free(main_break);
  free(breakpoints);
  free(addrs);

  return 0;
}
