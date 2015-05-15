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

#define MAX_TARGET_LEN 255

#define MAX_ARGS 6
#define MIN_ARGS 4

#define FULL_RUN_MODE 0
#define RUN_MODE 1
#define SKIP_MODE 2

//A return value indicating we reached past the end of executable. Chosen larger than 256 so that it 
//won't clash with most POSIX exit codes.
#define END_OF_EXECUTABLE 400

void print_usage_and_exit() {
  printf("Usage: tracer_sample signum retval [ -s num_to_skip || -r num_of_runs ] target\n");
  printf("    signum: Signal # to intercept\n");
  printf("    retval: Return value to insert\n");
  printf("    num_to_skip: Number of syscalls to skip before injection\n");
  printf("    num_of_runs: Runs in multi-run mode, skipping first 0 syscalls before fault injection, then 1, 2, etc.. up to num_of_runs\n");
  printf("    target: Path to target executable\n");
  printf("Default behavior for skip/runs is to run until no faults are injected.\n");
  exit(1);
}

/* Perform a single run of tracing, skipping the first num_to_skip syscalls and injecting a fault in all those 
   that follow. */
int single_injection_run(int target_syscall, long long int retval, long long int num_to_skip,
			 char* target) {
  int status = 0;
  int syscall_n = 0;
  int entering = 1;
  long long int syscall_count = 0;
  struct user_regs_struct regs;
  int pid = fork();

  if ( !pid ) {
    ptrace( PTRACE_TRACEME, 0, 0, 0 );
    execlp( target, target, NULL );
  }
  else {
    wait( &status );

    while ( 1 ) {
      ptrace( PTRACE_SYSCALL, pid, 0, 0 );
      wait( &status );

      if ( WIFEXITED( status ) ) break;

      ptrace( PTRACE_GETREGS, pid, 0, &regs );

      // get syscall number
      syscall_n = regs.orig_rax;

      // only intercept the syscall we want to intercept
      if ( syscall_n == target_syscall ) {
        if ( entering ) {
          // we only want to change the return value on syscall exit
          entering = 0;
        }
        else {
          syscall_count++;
          if (syscall_count > num_to_skip) {
            ptrace( PTRACE_GETREGS, pid, 0, &regs );
	    regs.rax = retval;
            // set the return value of the syscall
            ptrace( PTRACE_SETREGS, pid, 0, &regs );
            entering = 1;
          }
        }
      }
    }
  }
  if (syscall_count <= num_to_skip) { // If num_to_skip was so high no faults were injected.
    return END_OF_EXECUTABLE; 
  }

  return 0;
}

/* Run injections progressing from faulting the first syscall, to the second, third, etc... until 
   the runs have faulted every syscall in the execution once. */
int full_injection_run(int target_syscall, long long int retval, char* target) {
  long long int current_skip = 0;
  
  int res = 0;
  while (res == 0) {
    res = single_injection_run(target_syscall, retval, current_skip, target);
    current_skip++;
  }
  return res;
}

/* Run injections progressing from faulting the first syscall to the second, third, etc... until
   either all syscall in the execution have been faulted or all syscalls up to the input num_ops have been 
   faulted, whichever comes first. */
int multi_injection_run(int target_syscall, long long int retval, long long int num_ops, char* target) {
  for (long long int i = 0; i <= num_ops; i++) {
    int res = single_injection_run(target_syscall, retval, i, target);
    if (res) { //End if an error w.r.t the injector's end occurs or we reach past the end of the executable.
      return res;
    }
  }
  return 0;
}

/* Launch the program. */
int main(int argc, char *argv[]) {
  // Validate argc
  if((argc != MIN_ARGS) && (argc != MAX_ARGS)) {
    print_usage_and_exit();
  }

  // Validate target name
  char* target_inp;
  if (argc == MIN_ARGS) {
    target_inp = argv[3];
  } else {
    target_inp = argv[5];
  }
  if(strlen(target_inp) > MAX_TARGET_LEN) {
    printf("Target name cannot be longer than 255.\n");
    return 1;
  }

  int target_syscall = atoi(argv[1]);
  long long int retval = atoll(argv[2]);

  int mode = FULL_RUN_MODE;
  long long int num_ops;

  // Determine the mode of operation and the number of skips/runs if applicable.
  if (argc == MAX_ARGS) {
    num_ops = atoll(argv[4]);
    if (!strcmp(argv[3], "-s")) {
      mode = SKIP_MODE;
    } else if (!strcmp(argv[3], "-r")) {
      mode = RUN_MODE;
    } else {
      print_usage_and_exit();
    }
  }

  // Create a buffer to store the target name.
  char target[strlen(target_inp) + 1];
  strcpy(target, target_inp);

  int rval = 0;

  // Dispatch the runs.
  if (mode == FULL_RUN_MODE) {
    rval = full_injection_run(target_syscall, retval, target);
  } else if (mode == RUN_MODE) {
    rval = multi_injection_run(target_syscall, retval, num_ops, target);
  } else {
    rval = single_injection_run(target_syscall, retval, num_ops, target);
  }

  // END_OF_EXECUTABLE is an internal signal, not an external one.
  if (rval == END_OF_EXECUTABLE) {
    return 0;
  }
  return rval;
}
