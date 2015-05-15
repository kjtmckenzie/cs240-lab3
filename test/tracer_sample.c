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

#define NUM_ARGS 5

void print_usage_and_exit() {
  printf("Usage: tracer_sample signum retval prob target\n");
  printf("    signum: Signal # to intercept\n");
  printf("    retval: Return value to insert\n");
  printf("    num_to_skip: Number of syscalls to skip before injection\n");
  printf("    target: Path to target executable\n");
  exit(1);
}

int main(int argc, char *argv[]) {
  if(argc != NUM_ARGS) {
    printf("Wrong number of arguments: %d for %d.\n", argc, NUM_ARGS);
    print_usage_and_exit();
  }

  if(strlen(argv[4]) > MAX_TARGET_LEN) {
    printf("Target name cannot be longer than 255.\n");
    return 1;
  }

  int target_syscall = atoi(argv[1]);
  long long int retval = atoll(argv[2]);
  long long int num_to_skip = atoll(argv[3]);
  char target[MAX_TARGET_LEN + 1];
  strncpy(target, argv[4], MAX_TARGET_LEN);
  
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
            //printf("Target syscall %d caught.\n", target_syscall);
            //printf("Current return value is 0x%016llx.\n", regs.rax);
            //printf("Type the return value you want to change in hex.\n");
            //scanf("%llx", &regs.rax);
            regs.rax = retval;

            // set the return value of the syscall
            ptrace( PTRACE_SETREGS, pid, 0, &regs );
            entering = 1;
          }
        }
      }
    }
  }

  return 0;
}
