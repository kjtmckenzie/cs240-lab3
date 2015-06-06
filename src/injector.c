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
        return true;
      } else {
        printf("Could not attach to the child, trace = %ld\n", trace);
        fflush(stdout);
        return false;
      }
    }
  }

  // No clone? No problem!
  return true;
}

  // Start the target process - the child process never returns 
static void start_target(args_t *args, state_t *state, const char *target) {
  int pid = fork();
  if ( !pid ) {
    printf("start_target: child now execing '%s'...\n", target);
    ptrace( PTRACE_TRACEME, 0, 0, 0 );
    execvp( target, args->target_argv );
  } else {
    state->pid = pid;
    // Print status message concerning the run.
    printf("\nRunning ptrace injector on %s for syscalls: ", target);
    for (int i = 0; i < args->n_syscalls; i++) {
      printf("%d, ", args->syscall_nos[i]);
    }
    printf("with num_to_skip %lld\n", args->num_ops);
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

/* Perform a single run of tracing, skipping the first num_to_skip syscalls and injecting a fault in all those 
   that follow. */
int single_injection_run(args_t *args, state_t *state) {
  char *target = args->target_argv[0];
  int cloned_pid;
  int flags;

  printf("single_injection_run: beginning\n");
  fflush(0);

  // Start the target, begin tracing it, and wait for it to stop at the
  // first syscall
  start_target(args, state, target);
  ptrace( PTRACE_SYSCALL, state->pid, 0, 0 );
  wait( &(state->status) );

  printf("single_injection_run: before primary loop\n");
  fflush(0);

  // The primary tracer loop: register PTRACE_SYSCALL, wait for signal, and
  // then find out what happened
  size_t loop_counter = 0; 
  while ( 1 ) {
    ptrace( PTRACE_SYSCALL, state->pid, 0, 0 );
    wait( &(state->status) );
    fflush(stdout);

    if ( WIFEXITED( state->status ) ) {
      // If the tracee has exited, don't continue tracing
      break;
    }

    // Enforce a maximum # of iterations in case tracee never terminates
    /* I'm not sure this code works as intended */
    //sleep(1);
    fflush(stdout);
    loop_counter ++; 
    if (loop_counter > MAX_ITERS) {
      printf("TIMEOUT: Ptrace is taking too long on %s for syscall %d\n", target, state->syscall_n);
      exit(-1);
    }

    // If we're supposed to follow cloned processes, check if that happened
    if (args->follow_clones) {
      if (trace_clones(state)) {
        printf("Target %s clone()d; we're now tracing the child pid=%d\n", target, state->pid);
        fflush(0);
      } else {
        fprintf(stderr, "Target %s clone()d but we couldn't follow the child!\n", target);
        exit(1);
      }
    }

    ptrace( PTRACE_GETREGS, state->pid, 0, &(state->regs) );

    // Get syscall number & verify it's one we're interested in intercepting
    state->syscall_n = state->regs.orig_rax;
    int* syscall_idx = NULL;
    size_t n_syscalls_idx = args->n_syscalls;

    // Track state related to tracee OPEN syscalls
    trace_open_dirs(state);

    if ( (syscall_idx = lfind(&(state->syscall_n), args->syscall_nos, &n_syscalls_idx, sizeof(int), cmp_sys_num)) ||
         state->entry_intercepted ) {
      // The syscall # was one we were trying to intercept!

      if ( state->entering ) {
        // Entering the syscall. Only want to change retval on exit, though
        state->entering = false;
        state->syscall_count++;

        // TODO: need a comment clarifying this condition! My head hurts!
        if ( state->syscall_count > args->num_ops  && 
             args->fail_on_entry && 
             !(state->syscall_n == WRITE && state->regs.rdi < 3)) {
          if (!args->fail_only_dirs || state_is_dir(state, state->regs.rdi)) {
            ptrace( PTRACE_GETREGS, state->pid, 0, &(state->regs) );
            // set it to a dummy syscall getpid
            state->regs.orig_rax = GETPID;
            ptrace( PTRACE_SETREGS, state->pid, 0, &(state->regs) );
            state->entry_intercepted = true;
            state->intercepted_retval = args->syscall_retvals[syscall_idx - args->syscall_nos];
          }
        }
      } else {
        // Exiting the syscall. Now we'll fake the return value if we're at
        // the proper count (as determined by the 'skip N' argument)

        state->entering = true;
        state->entry_intercepted = false;
        if (state->syscall_count > args->num_ops && !(state->syscall_n == WRITE && state->regs.rdi < 3)) {
          // We've skipped enough calls and this isn't a WRITE to stdout or stderr;
          // so we proceed with modifying the return value

          if (!args->fail_only_dirs || state_is_dir(state, state->regs.rdi)) {
            ptrace( PTRACE_GETREGS, state->pid, 0, &(state->regs) );
            if ( args->fail_on_entry ) {
              state->regs.rax = state->intercepted_retval;
            } else {
              state->regs.rax = args->syscall_retvals[syscall_idx - args->syscall_nos];
            }

            // set the return value of the syscall
            ptrace( PTRACE_SETREGS, state->pid, 0, &(state->regs) );
          }
        }
      }
    }
  }  // END while (1)

  if (state->syscall_count <= args->num_ops) {
    // If num_to_skip was so high no faults were injected, we're done
    return END_OF_EXECUTABLE; 
  }

  return 0;
}

/* Run injections progressing from faulting the first syscall, to the second, third, etc... until 
   the runs have faulted every syscall in the execution once. */
int full_injection_run(args_t *args, state_t *state) {
  long long int current_skip = 0;
  
  int res = 0;
  while (res == 0) {
    args->num_ops = current_skip;
    state_reset(state);

    res = single_injection_run(args, state);
    current_skip++;
  }
  return res;
}

/* Run injections progressing from faulting the first syscall to the second, third, etc... until
   either all syscall in the execution have been faulted or all syscalls up to the input num_ops have been 
   faulted, whichever comes first. */
int multi_injection_run(args_t *args, state_t *state) {
  printf("multi_injection_run\n");
  fflush(0);
  for (long long int i = 0; i <= args->num_ops; i++) {
    state_reset(state);

    int res = single_injection_run(args, state);
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
  if (args == NULL) {
    return -1;
  }

  state_t *state = state_init(args);
  if (state == NULL) {
    fprintf(stderr, "Failed to initialize state\n");
    return -1;
  }

  printf("main: after state_init\n");
  fflush(0);

  // Dispatch the run(s).
  int rval = 0;
  if (args->mode == run_all) {
    rval = full_injection_run(args, state);
  } else if (args->mode == run_n) {
    rval = multi_injection_run(args, state);
  } else {
    rval = single_injection_run(args, state);
  }

  // Free dynamic memory used for syscall numbers and injected values.
  argparse_destroy(args);

  // Free resources for tracking injector state
  state_destroy(state);

  // END_OF_EXECUTABLE is an internal signal, not an external one.
  if (rval == END_OF_EXECUTABLE) {
    return 0;
  }
  return rval;
}
