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

#define TARGET "./malloc_target"

#define MAX_TARGET_LEN 255

#define NUM_ARGS 5

/*void print_usage_and_exit() {
  printf("Usage: tracer_sample signum retval prob target\n");
  printf("    signum: Signal # to intercept\n");
  printf("    retval: Return value to insert\n");
  printf("      prob: Probability of fault insertion\n");
  printf("    target: Path to target executable\n");
  exit(1);
}*/

int main(int argc, char *argv[]) {
/*  if(argc != NUM_ARGS) {
    printf("Wrong number of arguments: %d for %d.\n", argc, NUM_ARGS);
    print_usage_and_exit();
  }

  if(strlen(argv[4]) > MAX_TARGET_LEN) {
    printf("Target name cannot be longer than 255.\n");
    return 1;
  }

  int target_syscall = atoi(argv[1]);
  long long int retval = atoll(argv[2]);
  double prob = atof(argv[3]);
  char target[MAX_TARGET_LEN + 1];
  strncpy(target, argv[4], MAX_TARGET_LEN);

  srand(time(NULL));
*/
  int status = 0;
  int syscall_n = 0;
  int entering = 1;
  int signum;
  unsigned long long addr = 0x414514;

  struct user_regs_struct regs;
  int pid = fork();

  if ( !pid ) {
    ptrace( PTRACE_TRACEME, 0, 0, 0 );
    execlp( TARGET, TARGET, NULL );
  }
  else {
    wait( &status );
    unsigned long long data = ptrace(PTRACE_PEEKTEXT, pid, (void *)addr, 0);
    unsigned long long data_with_trap = (data & 0xFFFFFFFFFFFFFF00) | 0xcc;
    ptrace(PTRACE_POKETEXT, pid, (void *)addr, (void *)data_with_trap);
    ptrace(PTRACE_CONT, pid, 0, 0); 

    while ( 1 ) {
      wait( &status );
      if ( WIFEXITED( status ) ) break;
      else if (WIFSIGNALED(status)) {
        if(WTERMSIG(status) == SIGSEGV) printf("SEGFAULT!\n");
        break;
      }

      ptrace(PTRACE_GETREGS, pid, 0, &regs );
      printf("rip: 0x%llx, rax: 0x%llx\n", regs.rip, regs.rax);
      if(regs.rip == addr + 1) {
        regs.rip -= 1;
        //regs.rax = 0;
        ptrace(PTRACE_POKETEXT, pid, (void *)addr, (void *)data);
        ptrace(PTRACE_SETREGS, pid, 0, &regs);
        ptrace(PTRACE_CONT, pid, 0, 0);

      } else {
        signum = WSTOPSIG(status);
        ptrace(PTRACE_CONT, pid, NULL, signum);
      }
    }
  }

  return 0;
}
