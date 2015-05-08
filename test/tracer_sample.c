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

#define TARGET "/home/vagrant/lab3/test/target_sample"
#define NEW_UID 0

// syscall SYS_getuid == 102
#define TARGET_SYSCALL 102


int main() {
  int status = 0;
  int syscall_n = 0;
  int entering = 1;
  struct user_regs_struct regs;
  int pid = fork();

  if ( !pid ) {
    ptrace( PTRACE_TRACEME, 0, 0, 0 );
    execlp( TARGET, TARGET, NULL );
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
      if ( syscall_n == TARGET_SYSCALL ) {
        if ( entering ) {
          // we only want to change the return value on syscall exit
          entering = 0;
        }
        else {
          ptrace( PTRACE_GETREGS, pid, 0, &regs );
          // replace the return value with our own 
          regs.rax = 0;
        
          // set the return value of the syscall
          ptrace( PTRACE_SETREGS, pid, 0, &regs );
          entering = 1;
        }
      }
    }
  }

  return 0;
}