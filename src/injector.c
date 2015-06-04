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
#include "breakfast.h"
#include "argparse.h"
#include "addr_utils.h"

#define BUFLEN 4096



int main(int argc, char *argv[]) {
  args_t *args = argparse_parse(argc, argv);
  if (!args) {
    argparse_usage();
    exit(1);
  }

  const char *fn = argv[1];
  int retval = atoi(argv[2]);
  const char *target = argv[3];

  int status = 0;
  int entering = 1;
  struct user_regs_struct regs;

  void *addr = get_fn_address(fn, target);  // Address where malloc's code lives - failure? 0x414680
  //void *addr = (void *) 0x40108b;  // Address where malloc is called - success?
  //void *addr = (void *) 0x4010fc;  // Address before the last printf
  if (!addr) {
    printf("Couldn't read address of %s from %s! Aborting.\n", fn, target);
    exit(1);
  }
  printf("Read address=%p for fn=%s from target=%s\n", addr, fn, target);


  fflush(stdout);
  pid_t pid = fork();
  if (!pid) {
    // Child: register as tracee and run target process
    printf("Child: execing %s!\n", target);
    fflush(stdout);
    ptrace(PTRACE_TRACEME, 0, 0, 0);
    //kill(getpid(), SIGSTOP);
    execlp(target, target, NULL);
  } else {
    // Parent: trace child and inject breakpoints
    printf("Parent: attaching breakfast\n");
    fflush(stdout);
    //breakfast_attach(pid);

    waitpid(pid, NULL, 0);

    // Set breakpoint at malloc_addr
    struct breakpoint *malloc_break = breakfast_break(pid, (target_addr_t) addr);
    struct breakpoint *last_break = NULL;

    void *last_ip;

    printf("Before breakfast_run\n");
    fflush(stdout);
    while (breakfast_run(pid, last_break)) {
      printf("In breakfast_run loop\n");
      fflush(stdout);
      last_ip = breakfast_getip(pid);
      if (last_ip == addr) {
        printf("Break at malloc()\n");
        fflush(stdout);
        last_break = malloc_break;
      } else {
        printf("Unknown trap at %p\n", last_ip);
        fflush(stdout);
        last_break = NULL;
      }
    }

    printf("injector: All done!\n");
  }

  return 0;
}
