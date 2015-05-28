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

void print_usage() {
  printf("Usage: injector fn retval target\n");
  printf("Where:\n");
  printf("        fn = function to inject, e.g. 'malloc'\n");
  printf("    retval = return value to inject, e.g. '0'\n");
  printf("    target = statically-compiled target executable, e.g. 'bin/malloc_target'\n");
}

/**
 * Tries to read the address of the function identified by "fn" from the
 * symbol table in "target".
 *
 * @param fn The name of the function to search for; e.g. 'malloc'
 * @param target The target binary, which must be statically compiled
 *
 * @return The address in "target" of function "fn", or NULL if reading fails
 */
void *get_target_address(const char *fn, const char *target) {
  char buf[BUFLEN];
  memset(buf, 0, BUFLEN);
  snprintf(buf, BUFLEN - 4, "nm %s", target);

  FILE *fp = popen(buf, "r");
  if (fp == NULL) {
    fprintf(stderr, "Execution of \"%s\" failed; couldn't read symtab of target!\n", buf);
    return NULL;
  } else if (strlen(fn) > BUFLEN - 3) {
    fprintf(stderr, "Target function name '%s' is too long!\n", fn);
    pclose(fp);
    return NULL;
  }

  // Read each line looking for the address of fn
  char *line = NULL;
  size_t len = 0;
  ssize_t read;

  memset(buf, 0, BUFLEN);
  size_t fn_len = strlen(fn);
  buf[0] = ' ';
  strncpy(&buf[1], fn, fn_len);
  buf[fn_len + 1] = '\n';

  void *addr = NULL;
  while ((read = getline(&line, &len, fp)) != -1) {
    if (strstr(line, buf)) {
      // This is the line for our fn: now try to read the address
      if (strstr(line, " U ")) {
        fprintf(stderr, "No address in the symbol table for '%s'! Make sure the target was compiled with '-static'!\n", fn);
      } else {
        unsigned long long val;
        if (sscanf(line, "%16llx", &val) <= 0) {
          fprintf(stderr, "Couldn't parse address from line '%s'\n", line);
        } else {
          // Got the address!
          addr = (void *) val;
        }
      }
      break;
    }
  }

  if (ferror(fp)) {
    fprintf(stderr, "Error reading line from popen()!\n");
  }
  free(line);
  pclose(fp);
  return addr;
}

int main(int argc, char *argv[]) {
  if (argc != 4) {
    print_usage();
    exit(1);
  }

  const char *fn = argv[1];
  int retval = atoi(argv[2]);
  const char *target = argv[3];

  int status = 0;
  int entering = 1;
  struct user_regs_struct regs;

  void *addr = get_target_address(fn, target);  // Address where malloc's code lives - failure? 0x414680
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
