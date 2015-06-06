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
#include "backtrace.h"

int main(int argc, char *argv[]) {
  int pid = fork();
  int status = 0;
  int sig = 0;
  int fntab_size = 0;

  const char *target = argv[1];
  finfo *fntab = read_symbol_table(target, &fntab_size);

  if(!pid) {
    ptrace(PTRACE_TRACEME, 0, 0, 0);
    execlp(target, target, NULL);

  } else {
    waitpid(pid, &status, 0);
    ptrace(PTRACE_CONT, pid, 0, sig);

    while (1) {
      waitpid(pid, &status, 0);
 
      if(WIFEXITED(status) || WIFSIGNALED(status)) break;

      if(WIFSTOPPED(status)) {
        sig = WSTOPSIG(status);
        if(sig == SIGSEGV) execute_backtrace(fntab, fntab_size, pid);
      }

      ptrace(PTRACE_CONT, pid, 0, sig);
    } 

    destroy_function_table(fntab, fntab_size);
  }

  return 0;
}
