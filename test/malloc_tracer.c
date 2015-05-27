#define _XOPEN_SOURCE 500
#define _GNU_SOURCE

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
#include <stdbool.h>

#define TARGET "./malloc_target"

#define BUFLEN 4096
#define MAX_TARGET_LEN 255

#define NUM_ARGS 5

void print_usage_and_exit() {
  printf("Usage: injector fn retval target callnum\n");
  printf("Where:\n");
  printf("        fn  = function to inject, e.g. 'malloc'\n");
  printf("    retval  = return value to inject, e.g. '0'\n");
  printf("    target  = statically-compiled target executable, e.g. 'bin/malloc_target'\n");
  printf("    callnum = callnum_th call will be intercepted\n");
  exit(1);
}

unsigned long long*get_target_addrs(const char *fn, const char *target) {
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
  // Sentinel value for end of addresses
  addrs[addr_idx] = (unsigned long long) 0;
  return addrs;
}
/**
 * TODO: Okay, so now this function can retrieve the address of first instuction
 *       of target function. What we need to retrieve is the address of last
 *       instruction. Any idea??
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

void reset_trap (
    int pid, unsigned long long addr, unsigned long long data_with_trap) 
{
  ptrace(PTRACE_SINGLESTEP, pid, 0, 0);

  wait(NULL);

  ptrace(PTRACE_POKETEXT, pid, (void *)addr, (void *)data_with_trap);
  ptrace(PTRACE_CONT, pid, 0, 0);  
}

int main(int argc, char *argv[]) {
  

  if(argc != NUM_ARGS) {
    printf("Wrong number of arguments: %d for %d.\n", argc, NUM_ARGS);
    print_usage_and_exit();
  }

  if(strlen(argv[3]) > MAX_TARGET_LEN) {
    printf("Target name cannot be longer than 255.\n");
    return 1;
  }

  const char *fn = argv[1];
  long long int retval = atoll(argv[2]);
  char target[MAX_TARGET_LEN + 1];
  strncpy(target, argv[3], MAX_TARGET_LEN);
  int callnum = atoi (argv[4]);

  get_target_addrs(fn, target);

  int status = 0;
  int signum = 0;

  unsigned long long *addrs = get_target_addrs (fn, target);
  
  // Something went wrong in retrieving addrs...
  if (!addrs) {
    exit(-1);
  }

  for (int i = 0 ; addrs[i] != 0; i ++ ) {
    unsigned long long addr = addrs[i];
    printf ("%16llx\n", addr);
  }

  // TODO: Do something with the parsed addresses


  //unsigned long long addr = get_target_address(fn, target);
  /*unsigned long long addr = 0x414504;

  struct user_regs_struct regs;
  int pid = fork();

  if ( !pid ) {
    ptrace(PTRACE_TRACEME, 0, 0, 0);
    execlp(TARGET, TARGET, NULL);

  } else {
    wait( &status );

    // Set initial break point.
    unsigned long long data = ptrace(PTRACE_PEEKTEXT, pid, (void *)addr, 0);
    unsigned long long data_with_trap = (data & 0xFFFFFFFFFFFFFF00) | 0xcc;

    ptrace(PTRACE_POKETEXT, pid, (void *)addr, (void *)data_with_trap);
    ptrace(PTRACE_CONT, pid, 0, 0); 

    while ( 1 ) {
      wait( &status );
      if (WIFEXITED(status) || WIFSIGNALED(status)) break;

      ptrace(PTRACE_GETREGS, pid, 0, &regs );
      
      if(regs.rip == addr + 1) {
        regs.rip -= 1;
        regs.rax = 0;
    
        // Set to original data and move one step
        ptrace(PTRACE_POKETEXT, pid, (void *)addr, (void *)data);
        ptrace(PTRACE_SETREGS, pid, 0, &regs);

        // Reset trap at address
        reset_trap(pid, addr, data_with_trap);
      
      } else {
        // For other signals, skip and move on.
        signum = WSTOPSIG(status);
        ptrace(PTRACE_CONT, pid, 0, signum);
      } 
    }
  }*/

  return 0;
}
