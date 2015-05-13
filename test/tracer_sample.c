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

//#define TARGET "/home/vagrant/lab3/test/target_sample"
//#define NEW_UID 0
// syscall SYS_getuid == 102
//#define TARGET_SYSCALL 102

int target_syscall;
long long int retval;
double prob;
char target[MAX_TARGET_LEN + 1];

int main(int argc, char *argv[]) {
  if(argc != 5) {
    printf("Insufficient number of argument.\n");
    //print_usage();
    return 1;
  }

  if(strlen(argv[4]) > MAX_TARGET_LEN) {
    printf("Target name cannot be longer than 255.\n");
    return 1;
  }

  target_syscall = atoi(argv[1]);
  retval = atoll(argv[2]);
  prob = atof(argv[3]);
  strncpy(target, argv[4], MAX_TARGET_LEN);

  srand(time(NULL));

  int status = 0;
  int syscall_n = 0;
  int entering = 1;
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
      //printf("Syscall is %d\n", syscall_n);
     
      // only intercept the syscall we want to intercept
      if ( syscall_n == target_syscall ) {
        if ( entering ) {
          // we only want to change the return value on syscall exit
          entering = 0;
        }
        else {
          ptrace( PTRACE_GETREGS, pid, 0, &regs );
          //printf("Target syscall %d caught.\n", target_syscall);
          //printf("Current return value is 0x%016llx.\n", regs.rax);
          //printf("Type the return value you want to change in hex.\n");
          //scanf("%llx", &regs.rax);

          if(((double)rand() / RAND_MAX) < prob)
            regs.rax = retval;

          // set the return value of the syscall
          ptrace( PTRACE_SETREGS, pid, 0, &regs );
          entering = 1;
        }
      }
    }
  }

  return 0;
}
