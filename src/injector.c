/*
 * injector.c
 *
 * The fault injector itself.
 */

// Debug flag to generate debug output. comment out to disable.
#define DEBUG 

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <sys/reg.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <search.h>
#include "argparse.h"
#include "state.h"
#include "breakfast.h"
#include "backtrace.h"
#include "debug_utils.h"

// A few interesting syscall numbers
#define READ 0
#define WRITE 1
#define OPEN 2
#define CLOSE 3
#define GETPID 39
#define CLONE 56
#define FSYNC 74
#define MKDIR 83
#define OPENAT 257

// A return value indicating we reached past the end of executable.
// Chosen larger than 256 so that it won't clash with most POSIX exit codes.
#define END_OF_EXECUTABLE 400

// Maximum # of iterations to support in the main tracing loop.
// TODO: is there a more robust way to enforce timeouts?
#define MAX_ITERS 1000000

/* A simple int comparison functions for checking against syscall numbers. Used for lfind. */
int cmp_sys_num(const void* num_a, const void* num_b) {
  return (*(int*)num_a) - (*(int*)num_b);
}

/* Get PID of cloned process, if there was a clone, and update state.
 * Do nothing if no clone, and return false on failure. */
bool trace_clones(state_t *state) {
  long newpid, trace;
  int syscall_n;
  struct user_regs_struct regs;
  ptrace( PTRACE_GETREGS, state->pid, 0, &regs );
  syscall_n = regs.orig_rax;
  if (syscall_n == CLONE) {
    if (state->clone_entering) {
      // We start tracing again at the exit of the clone() call
      state->clone_entering = false;
    } else {
      // clone() is exiting - start tracing the new guy
      state->clone_entering = true;
      newpid = regs.rax;
      trace = ptrace( PTRACE_ATTACH, newpid, NULL, NULL);
      ptrace( PTRACE_SYSCALL, newpid, 0, 0 );
      if(trace == 0) {
        state->pid = newpid;
        // IAW FIXME: need to update the backtracer here!
        return true;
      } else {
        debug("Could not attach to the child, trace = %ld\n", trace);
        fflush(stdout);
        return false;
      }
    }
  }

  // No clone? No problem!
  return true;
}

  // Start the target process - the child process never returns from this
static void start_target(args_t *args, state_t *state, const char *target) {
  int pid = fork();
  if ( !pid ) {
    debug("start_target: child now execing '%s'...\n", target);
    ptrace( PTRACE_TRACEME, 0, 0, 0 );
    execvp( target, args->target_argv );
  } else {
    state->pid = pid;
    // Print status message concerning the run.
    debug("\nRunning ptrace injector on %s for syscalls: ", target);
    for (int i = 0; i < args->n_syscalls; i++) {
      debug("%d, ", args->syscall_nos[i]);
    }
    debug("with num_to_skip %lld\n", args->num_ops);

    state_prep_backtrace(state, target, pid);
  }
}

// Track state related to directory file descriptors the tracee opens
static void trace_open_dirs(state_t *state) {
  int flags;
  if (state->open_entering) {
    if ( state->syscall_n == OPEN) {
      state->open_entering = false;

      flags = state->regs.rsi;
      if (flags & O_DIRECTORY) {
        state->found_directory = true;
      }
    } else if ( state->syscall_n == OPENAT) {
      state->open_entering = false;

      flags = state->regs.rdx;
      if (flags & O_DIRECTORY) {
        state->found_directory = true;
      }
    }
  } else {
    state->open_entering = true;

    if ( state->syscall_n == OPEN && state->found_directory) {
      state_add_dir(state, (int) state->regs.rax);
    } else if ( state->syscall_n == OPENAT && state->found_directory) {
      state_add_dir(state, (int) state->regs.rax);
    }

    state->found_directory = false;
  }
}

// True iff this syscall is a WRITE to stdout or stderr: don't intercept those!
static bool is_std_write(state_t *state) {
  return state->syscall_n == WRITE && state->regs.rdi <= STDERR_FILENO;
}

/**
 * Intercept the current syscall (state->syscall_n) iff
 *     - We've registered to intercept this call
 *   OR
 *     - We're in the "entry intercepted" state, meaning that we just saw the
 *   start of a syscall to intercept, and this iteration should be it exiting.
 *
 * @param args injector command line arguments
 * @param state injector_state struct
 * @param syscall_idx pointer to int*, set to the result of lfind
 *
 * @return true iff we should intercept this syscall
 */
static bool should_intercept_syscall(args_t *args, state_t *state, int **syscall_idx) {
  size_t n_syscalls_idx = args->n_syscalls;
  // syscall_idx will be Not-NULL if this a syscall we've registered to trace
  *syscall_idx = lfind(&(state->syscall_n), args->syscall_nos, &n_syscalls_idx, sizeof(int), cmp_sys_num);
  return (*syscall_idx) || state->entry_intercepted;
}

/**
 * Handle interception for the case where the syscall is entering.
 *
 * @param args injector command line arguments
 * @param state injector_state struct
 * @param syscall_idx pointer to the syscall no. in args we're intercepting
 */
static void intercept_entering(args_t *args, state_t *state, int *syscall_idx) {
  // Entering the syscall. Might only want to change retval on exit, though
  state->entering = false;
  state->syscall_count++;

  if ( state->syscall_count > args->num_ops && args->fail_on_entry
       && !is_std_write(state)) {
    // We've skipped enough calls, we're supposed to fail on entry,
    // and we're not stopping a write to stdout or stderr

    if (!args->fail_only_dirs || state_is_dir(state, state->regs.rdi)) {
      // The actual injection: replace the syscall # on the tracee's stack
      // with a dummy # of our choice (GETPID), effectively aborting the call
      ptrace( PTRACE_GETREGS, state->pid, 0, &(state->regs) );
      state->regs.orig_rax = GETPID;
      ptrace( PTRACE_SETREGS, state->pid, 0, &(state->regs) );
      state->entry_intercepted = true;
      state->intercepted_retval = args->syscall_retvals[syscall_idx - args->syscall_nos];
    }
  }
}

/**
 * Handle interception where the syscall is exiting.
 *
 * @param args injector command line arguments
 * @param state injector_state struct
 * @param syscall_idx pointer to the syscall no. in args we're intercepting
 */
static void intercept_exiting(args_t *args, state_t *state, int *syscall_idx) {
  // Reset entering/exiting state for next entry
  state->entering = true;
  state->entry_intercepted = false;

  if (state->syscall_count > args->num_ops && !is_std_write(state)) {
    // We've skipped enough calls, and this isn't a WRITE to stdout or stderr;

    if (!args->fail_only_dirs || state_is_dir(state, state->regs.rdi)) {
      ptrace( PTRACE_GETREGS, state->pid, 0, &(state->regs) );
      if ( args->fail_on_entry ) {
        // We failed it on entry; just restore the original retval now
        state->regs.rax = state->intercepted_retval;
      } else {
        // Replace the return value with the one specified in args
        state->regs.rax = args->syscall_retvals[syscall_idx - args->syscall_nos];
      }

      // Set the return value of the syscall
      ptrace( PTRACE_SETREGS, state->pid, 0, &(state->regs) );
    }
  }
}

/* Makes a breakpoint at the main function of child process, continues execution 
   until it is hit.  */
void run_until_main (const char* target, state_t *state, 
                     void **last_ip, breakpoint_t *last_break) {

  // Run until main is caught
  target_addr_t main_addr = get_fn_address("main", target);
  breakpoint_t *main_break = breakfast_create(state->pid, (target_addr_t) main_addr);
  debug("malloc_tracer: Skip preprocess. Main function should be called.\n");
  while(breakfast_run(state->pid, last_break)) {
    *last_ip = breakfast_get_ip(state->pid);
    if(*last_ip == main_addr) {
      last_break = main_break;
      break;
    }
  }
  debug("Main is called. Now our breakpoint is to be set.\n");
  fflush(stderr);
}

/* Perform a single run of tracing, skipping the first num_to_skip syscalls and injecting a fault in all those 
   that follow. */
int single_injection_run_syscall(args_t *args, state_t *state) {
  debug("single_injection_run_syscall: beginning\n");
  fflush(stdout);

  // Start the target, begin tracing it, and wait for the first stop
  const char *target = args->target_argv[0];
  start_target(args, state, target);
  ptrace( PTRACE_SYSCALL, state->pid, 0, 0 );
  wait( &(state->status) );

  breakpoint_t *last_break = NULL;
  void *last_ip;

  if (args->after_main == true) {
    /* Wait till main gets called */
    run_until_main (target, state, &last_ip, last_break);
    free(last_break);
  } 

  // The primary tracer loop: register PTRACE_SYSCALL, wait for signal, and
  // then find out what happened
  size_t loop_counter = 0; 
  while ( 1 ) {
    ptrace( PTRACE_SYSCALL, state->pid, 0, 0 );
    wait( &(state->status) );
    fflush(stdout);

    if ( WIFEXITED( state->status ) ) {
      // If the tracee has exited, don't continue tracing
      backtrace_execute(state->bt);
      break;
    }

    // Enforce a maximum # of iterations in case tracee never terminates
    loop_counter ++; 
    if (loop_counter > MAX_ITERS) {
      printf("TIMEOUT: Ptrace is taking too long on %s for syscall %d\n", target, state->syscall_n);
      backtrace_execute(state->bt);
      exit(-1);
    }

    // If we're supposed to follow cloned processes, check if that happened
    if (args->follow_clones) {
      if (!trace_clones(state)) {
        fprintf(stderr, "Target %s clone()d but we couldn't follow the child!\n", target);
        exit(1);
      }
    }

    // Get syscall number & verify it's one we're interested in intercepting
    ptrace( PTRACE_GETREGS, state->pid, 0, &(state->regs) );
    state->syscall_n = state->regs.orig_rax;
    int* syscall_idx = NULL;

    // Track state related to tracee OPEN syscalls
    trace_open_dirs(state);

    if (should_intercept_syscall(args, state, &syscall_idx)) {
      if ( state->entering ) {
        intercept_entering(args, state, syscall_idx);
      } else {
        intercept_exiting(args, state, syscall_idx);
      }
    }
  }  // END while (1)

  if (state->syscall_count <= args->num_ops) {
    // If num_to_skip was so high no faults were injected, we're done
    return END_OF_EXECUTABLE; 
  }

  return 0;
}

/* Perform a single run of tracing, skipping the first num_to_skip function calls and injecting a fault in all those 
   that follow. */
int single_injection_run_fn(args_t *args, state_t *state, int fn_idx) {
  const char *fn = args->fn_names[fn_idx];
  debug("single_injection_run_fn: beginning for %s\n", fn);
  fflush(stdout);

  int last_signum = 0;
  struct user_regs_struct regs;
  const char *target = args->target_argv[0];

  state->pid = fork();
  if ( !state->pid ) {
    // Child: register as tracee and run target process
    debug("Child: execing %s!\n", target);
    fflush(stdout);
    ptrace(PTRACE_TRACEME, 0, 0, 0);
    execlp(target, target, NULL);  // never returns
  }

  wait( &state->status );

  breakpoint_t *last_break = NULL;
  void *last_ip;

  if (args->after_main == true) {
    /* Wait till main gets called */
    run_until_main (target, state, &last_ip, last_break);
  } 

  // TODO: add breakpoints to state struct
  // Insert (enabled) breakpoints at all call sites of malloc()
  breakpoint_t **breakpoints = (breakpoint_t **) (malloc(state->n_calls[0] * sizeof(breakpoint_t *)));
  for(int i = 0; i < state->n_calls[fn_idx]; i++) {
    breakpoints[i] = breakfast_create(state->pid, state->fn_call_addrs[0][i]);
  }

  ptrace(PTRACE_CONT, state->pid, 0, 0); 
  while ( 1 ) {
    debug("injector: loop\n");
    fflush(stdout);
    wait( &state->status );

    if (WIFEXITED(state->status) || WIFSIGNALED(state->status)) {
      debug("injector: breaking\n");
      fflush(stdout);
      break;
    }

    // TODO: add "state_get_breakpoint" helper
    last_ip = breakfast_get_ip(state->pid);
    int j;
    for(j = 0; j < state->n_calls[fn_idx]; j++) {
      if(last_ip == state->fn_call_addrs[fn_idx][j]) {
        // Stopped at a breakpoint of ours?
        debug("injector: last_ip=%p was in addrs\n", last_ip);
        fflush(stdout);
        break;
      }
    }

    if(j == state->n_calls[fn_idx]) {
      debug("Unknown trap at %p\n", last_ip);
      // Continue tracing by forwarding the same signal we intercepted
      last_signum = WSTOPSIG(state->status);
      ptrace(PTRACE_CONT, state->pid, 0, last_signum);
    } else {
      debug("breakpoint\n");
      last_break = breakpoints[j];

      // TODO: add "fault_function" helper
      ptrace(PTRACE_GETREGS, state->pid, 0, &regs);
      // "callq" is a 5 byte instruction, so this jumps over it and malloc()
      // is never called, and we fake the return value in %rax.
      // This is gross - surely there is a more robust way to skip the call?
      regs.rip += 5;
      regs.rax = args->fn_retvals[fn_idx];
      ptrace(PTRACE_SETREGS, state->pid, 0, &regs);

      // Set to original data and move one step
      breakfast_disable(state->pid, last_break);

      // TODO: Reset trap at address if we want to break there again!

      ptrace(PTRACE_CONT, state->pid, 0, 0);
    }
  }

  free(last_break);
  free(breakpoints);

  return 0;  
}

/* Run injections progressing from faulting the first syscall, to the second, third, etc... until 
   the runs have faulted every syscall in the execution once. */
int full_injection_run_syscall(args_t *args, state_t *state) {
  printf("full_injection_run_syscall: beginning\n");
  fflush(stdout);
  long long int current_skip = 0;

  int res = 0;
  while (res == 0) {
    args->num_ops = current_skip;
    state_reset(state);

    res = single_injection_run_syscall(args, state);
    current_skip++;
  }
  return res;
}

/* Run injections progressing from faulting the first syscall to the second, third, etc... until
   either all syscall in the execution have been faulted or all syscalls up to the input num_ops have been 
   faulted, whichever comes first. */
int multi_injection_run_syscall(args_t *args, state_t *state) {
  printf("multi_injection_run_syscall: beginning\n");
  fflush(stdout);
  for (long long int i = 0; i <= args->num_ops; i++) {
    state_reset(state);

    int res = single_injection_run_syscall(args, state);
    if (res) {
      // End early if an error w.r.t the injector's end occurs
      // or we reach past the end of the executable.
      return res;
    }
  }
  return 0;
}

/* Launch the program. */
int main(int argc, char *argv[]) {
  args_t* args = argparse_parse(argc, argv);
  if (!args) {
    // argparse prints its own (extremely verbose) failure message
    return -1;
  }

  state_t *state = state_init(args);
  //state_dump(state, stdout);
  if (!state) {
    fprintf(stderr, "Failed to initialize state\n");
    return -1;
  }

  // Dispatch the run(s).
  int rval = 0;
  if (args->r_type == r_syscall) {
    if (args->mode == run_all) {
      rval = full_injection_run_syscall(args, state);
    } else if (args->mode == run_n) {
      rval = multi_injection_run_syscall(args, state);
    } else {
      rval = single_injection_run_syscall(args, state);
    }
  } else {
    rval = 0;
    for (int i = 0; i < state->n_functions; i ++) {
      rval = single_injection_run_fn (args, state, i);
      if (rval) break;
    }
  }

  // Free dynamic memory used for syscall numbers and injected values.
  argparse_destroy(args);

  // Free resources for tracking injector state
  state_destroy(state);

  // END_OF_EXECUTABLE is an internal signal, not an external one.
  if (rval == END_OF_EXECUTABLE) {
    return 0;
  } else {
    return rval;
  }
}
