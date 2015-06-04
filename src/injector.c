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

#define BUFLEN 4096
#define MAIN "main"

// TODO: fix Makefile
// gcc -Iinclude src/injector.c src/breakfast.c -o bin/injector

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

unsigned long long *get_target_addrs(const char *fn, const char *target) {
  char buf[BUFLEN];
  memset(buf, 0, BUFLEN);
  snprintf(buf, BUFLEN - 4, "objdump -D %s | grep -E 'callq  [0-9a-f]* <%s>'", target, fn);

  FILE *fp = popen(buf, "r");
  if (fp == NULL) {
    fprintf(stderr, "Execution of \"%s\" failed; couldn't read symtab of target!\n", buf);
    //return NULL;
    return NULL;
  } else if (strlen(fn) > BUFLEN - 3) {
    fprintf(stderr, "Target function name '%s' is too long!\n", fn);
    pclose(fp);
    //return NULL;
    return NULL;
  }


  unsigned long long *addrs = malloc (sizeof (unsigned long long) * 1000);
  size_t addr_idx = 0; 

  // Read each line looking for the address of fn
  char *line = NULL;
  size_t len = 0;
  ssize_t read;

  memset(buf, 0, BUFLEN);

  void *addr = NULL;
  while ((read = getline(&line, &len, fp)) != -1) {
    if (strstr(line, ":")) {
      unsigned long long val;
 
      // This is the line for our fn: now try to read the address
      if (strstr(line, " U ")) {
        fprintf(stderr, "No address in the symbol table for '%s'! Make sure the target was compiled with '-static'!\n", fn);
        continue;
      } else {

        if (sscanf(line, "%16llx", &val) <= 0) {
          fprintf(stderr, "Couldn't parse address from line '%s'\n", line);
          continue;
        } 
      }

      char *start = strstr(line, ":");
      start++;
      char *end = strstr(line, "call");
      *end = 0;

      int byte_count = 0;
      char *tok = strtok(start, " ");

      while(tok) {
        byte_count++;
        tok = strtok(NULL, " ");
      }

      addrs[addr_idx] = val + byte_count - 1;
      addr_idx ++;
    }
  }

  pclose(fp);

  // Sentinel value for end of addresses
  addrs[addr_idx] = (unsigned long long) 0;
  return addrs;
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

  void *main_addr = get_target_address(MAIN, target);
  unsigned long long *target_addrs = get_target_addrs(fn, target);

  if (!target_addrs) {
    printf("Couldn't read address of %s from %s! Aborting.\n", fn, target);
    exit(1);
  }

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

    struct breakpoint *last_break = NULL;
    void *last_ip;

    waitpid(pid, NULL, 0);

    struct breakpoint *main_break = breakfast_break(pid, (target_addr_t) main_addr);

    printf("Skip preprocess. Main function should be called.\n");
    fflush(stdout);

    // Run until main is caught
    while(breakfast_run(pid, last_break)) {
      last_ip = breakfast_getip(pid);
      if(last_ip == main_addr) {
        last_break = main_break;
        break;
      }
    } 

    printf("Main is called. Now our breakpoint is to be set.\n");
    fflush(stdout);

    struct breakpoint **breakpoints = (struct breakpoint **)(malloc(1000 * sizeof(struct breakpoint *)));

    int i, count = 0;
    for(i = 0; target_addrs[i] != 0; i++) {
      breakpoints[i] = breakfast_break(pid, (target_addr_t)target_addrs[i]);
      count ++;
    }

    // Set breakpoint at malloc_addr
    //struct breakpoint *malloc_break = breakfast_break(pid, (target_addr_t) addr);

    printf("Before breakfast_run\n");
    fflush(stdout);
    while (breakfast_run(pid, last_break)) {
      printf("In breakfast_run loop\n");
      fflush(stdout);
      last_ip = breakfast_getip(pid);

      int j;
      for(j = 0; j < count; j++) {
        if(last_ip == (void *)target_addrs[j]) break;
      }

      if(j == count) {
        printf("Unknown trap at %p\n", last_ip);
        fflush(stdout);
        last_break = NULL;
      } else {
        printf("Break at return after malloc()\n");
        fflush(stdout);
        ptrace(PTRACE_GETREGS, pid, 0, &regs);
        regs.rax = retval;
        ptrace(PTRACE_SETREGS, pid, 0, &regs);
        last_break = breakpoints[j];
      }
    }

    free(main_break);
    free(breakpoints);
    free(target_addrs);
    printf("injector: All done!\n");
  }

  return 0;
}
