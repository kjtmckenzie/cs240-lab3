/* breakfast.c
 *
 * ptrace breakpoint implementation, borrowed from 
 * http://mainisusuallyafunction.blogspot.ca/2011/01/implementing-breakpoints-on-x86-linux.html
 *
 * Useable under BSD license. TODO: cite properly
 */

#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <stdbool.h>
#include <signal.h>
#include "breakfast.h"

#if defined(__i386)
#define REGISTER_IP EIP
#define TRAP_LEN    1
#define TRAP_INST   0xCC
#define TRAP_MASK   0xFFFFFF00

#elif defined(__x86_64)
#define REGISTER_IP RIP
#define TRAP_LEN    1
#define TRAP_INST   0xCC
#define TRAP_MASK   0xFFFFFFFFFFFFFF00

#else
#error Unsupported architecture
#endif

struct breakpoint {
  target_addr_t addr;  /* The breakpoint address in the tracee */
  long orig_code;      /* The original word at that address */
};

/* Forward declarations */
static bool enable(pid_t pid, struct breakpoint *bp);
static bool disable(pid_t pid, struct breakpoint *bp);
static int run(pid_t pid, int cmd);

/**
 * Prepare a process for breakpointing by PTRACE_ATTACH-ing to it
 *
 * @param pid Tracee process id
 */
void breakfast_attach(pid_t pid) {
  int status;
  if (ptrace(PTRACE_ATTACH, pid) < 0) {
    fprintf(stderr, "breakfast_attach: PTRACE_ATTACH failed: %s\n", strerror(errno));
  }
  waitpid(pid, &status, 0);  /* wait for tracee to receive SIGSTOP */
  // if (ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACEEXIT) < 0) {
  //   fprintf(stderr, "breakfast_attach: PTRACE_SETOPTIONS failed: %s\n", strerror(errno));
  // }
}

/** 
 * Read the current instruction pointer from tracee
 *
 * @param pid Tracee process id.
 *
 * @return Current value of tracee's instruction pointer as a target_addr_t
*/
target_addr_t breakfast_getip(pid_t pid) {
  errno = 0;
  long v = ptrace(PTRACE_PEEKUSER, pid, sizeof(long)*REGISTER_IP);
  if (errno) {
    fprintf(stderr, "breakfast_getip: PTRACE_PEEKUSER failed: %s\n", strerror(errno));
  }
  return (target_addr_t) (v - TRAP_LEN);
}

/**
 * Insert a breakpoint in tracee at addr.
 *
 * @param pid Tracee process id
 * @param addr Tracee address for breakpoint insertion 
 *
 * @return a dynamically allocated breakpoint; caller must free with breakfast_destroy
 */
struct breakpoint *breakfast_break(pid_t pid, target_addr_t addr) {
  fprintf(stderr, "breakfast_break: inserting breakpoint @ %p for pid=%d\n", addr, pid);
  struct breakpoint *bp = malloc(sizeof(struct breakpoint));
  bp->addr = addr;
  if (!enable(pid, bp)) {
    fprintf(stderr, "breakfast_break: enable() failed: %s\n", strerror(errno));
  }
  return bp;
}

/**
 * Disable a breakpoint and free its memory
 *
 * @param pid Tracee process id
 * @param bp The breakpoint to destroy, created by breakfast_break
 */
void breakfast_destroy(pid_t pid, struct breakpoint *bp) {
  if (bp) {
    if (!disable(pid, bp)) {
      fprintf(stderr, "breakfast_destroy: disable() failed: %s\n", strerror(errno));
    }
    free(bp);
  }
}

/**
 * Run the tracee until it stops or hits a breakpoint.
 *
 * @param pid Tracee process id
 * @param bp NULL for first invocation
 *
 * @return 0 If tracee exited, 1 if it stopped at a breakpoint 
 */
int breakfast_run(pid_t pid, struct breakpoint *bp) {
  if (bp) {
    /* POKEUSER: write word at an addr in the USER area, where registers are */
    ptrace(PTRACE_POKEUSER, pid, sizeof(long)*REGISTER_IP, bp->addr);

    // We're currently stopped at "bp". Disable breakpoint, single-step, then re-enable
    disable(pid, bp);
    if (!run(pid, PTRACE_SINGLESTEP))
      return 0;
    enable(pid, bp);
  }
  return run(pid, PTRACE_CONT);
}

/* --- Below here private to breakfast.c --- */

// Actually insert the breakpoint by writing the break instruction and saving the old value
static bool enable(pid_t pid, struct breakpoint *bp) {
  bool success = true;
  errno = 0;
  long orig = ptrace(PTRACE_PEEKTEXT, pid, bp->addr, 0);
  if (errno) {
    fprintf(stderr, "enable: PTRACE_PEEKTEXT failed: %s\n", strerror(errno));
    success = false;
  }
  if (ptrace(PTRACE_POKETEXT, pid, bp->addr, (orig & TRAP_MASK) | TRAP_INST) < 0) {
    fprintf(stderr, "enable: PTRACE_POKETEXT failed: %s\n", strerror(errno));
    success = false;
  }
  bp->orig_code = orig;
  return success;
}

// Undo a breakpoint by writing back the old value
static bool disable(pid_t pid, struct breakpoint *bp) {
  bool success = true;
  if (ptrace(PTRACE_POKETEXT, pid, bp->addr, bp->orig_code) < 0) {
    fprintf(stderr, "disable: PTRACE_POKETEXT failed: %s\n", strerror(errno));
    success = false;
  }
  return success;
}

// cmd: Either PTRACE_CONT or PTRACE_SINGLESTEP
// return: 0 if tracee exited; 1 if tracee hit breakpoint
static int run(pid_t pid, int cmd) {
  int status, last_sig = 0, event;
  while (1) {
    ptrace(cmd, pid, 0, last_sig);
    waitpid(pid, &status, 0);

    if (WIFEXITED(status)) {
      fprintf(stderr, "breakfast: run: child exited with status=%d\n", WEXITSTATUS(status));
      return 0;
    }

    if (WIFSTOPPED(status)) {
      last_sig = WSTOPSIG(status);
      target_addr_t ip = breakfast_getip(pid);
      fprintf(stderr, "breakfast: run: current_ip=%p\n", ip);
      psignal(last_sig, "breakfast: run: last_sig");
      if (last_sig == SIGTRAP) {
        event = (status >> 16) & 0xffff;
        if (event == PTRACE_EVENT_EXIT) {
          fprintf(stderr, "breakfast: run: tracee exited\n");
          return 0;
        } else {
          return 1;
        }
      }
    }
  }
}
