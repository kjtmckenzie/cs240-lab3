/* 
 * breakfast.c
 *
 * ptrace breakpoint implementation, borrowed & extended from :
 * http://mainisusuallyafunction.blogspot.ca/2011/01/implementing-breakpoints-on-x86-linux.html
 *
 * Useable under BSD license.
 */

#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <signal.h>
#include "breakfast.h"
#include "debug_utils.h"

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

// Forward-declaration
static int run(pid_t pid, int cmd);

/** 
 * Read the current instruction pointer from tracee
 *
 * @param pid Tracee process id.
 *
 * @return Current value of tracee's instruction pointer as a target_addr_t
*/
target_addr_t breakfast_get_ip(pid_t pid) {
  errno = 0;
  long v = ptrace(PTRACE_PEEKUSER, pid, sizeof(long)*REGISTER_IP);
  if (errno) {
    debug("breakfast_get_ip: PTRACE_PEEKUSER failed: %s\n", strerror(errno));
  }
  return (target_addr_t) (v - TRAP_LEN);
}

/**
 * Create a new, enabled breakpoint in tracee at addr.
 *
 * @param pid Tracee process id
 * @param addr Tracee address for breakpoint insertion 
 *
 * @return malloc'd breakpoint or NULL on fail; caller breakfast_destroy's it
 */
breakpoint_t *breakfast_create(pid_t pid, target_addr_t addr) {
  breakpoint_t *bp = malloc(sizeof(breakpoint_t));
  if (!bp) {
    debug( "breakfast_create: malloc failed!\n");
    return NULL;
  }
  memset(bp, 0, sizeof(breakpoint_t));

  bp->addr = addr;
  breakfast_enable(pid, bp);
  return bp;
}

/**
 * Disable a breakpoint and free its memory
 *
 * @param pid Tracee process id
 * @param bp The breakpoint to destroy, created by breakfast_create
 */
void breakfast_destroy(pid_t pid, breakpoint_t *bp) {
  if (bp) {
    if (bp->enabled) {
      breakfast_disable(pid, bp);
    }
    free(bp);
  }
}

/**
 * Enable breakpoint bp by writing the trap instruction and saving old data
 *
 * @param pid tracee process id
 * @param bp breakpoint 
 *
 * @return success status
 */
bool breakfast_enable(pid_t pid, struct breakpoint *bp) {
  bool success = true;
  if (!bp->enabled) {
    errno = 0;
    long orig = ptrace(PTRACE_PEEKTEXT, pid, bp->addr, 0);
    if (errno) {
      debug("enable: PTRACE_PEEKTEXT failed: %s\n", strerror(errno));
      success = false;
    }
    if (ptrace(PTRACE_POKETEXT, pid, bp->addr, (orig & TRAP_MASK) | TRAP_INST) < 0) {
      debug("enable: PTRACE_POKETEXT failed: %s\n", strerror(errno));
      success = false;
    }
    bp->orig = orig;
    bp->enabled = true;
  }
  return success;
}

/**
 * Disable breakpoint bp by writing by the old value
 *
 * @param pid tracee process id
 * @param bp breakpoint
 *
 * @return success status
 */
bool breakfast_disable(pid_t pid, struct breakpoint *bp) {
  bool success = true;
  if (bp->enabled) {
    if (ptrace(PTRACE_POKETEXT, pid, bp->addr, bp->orig) < 0) {
      debug("disable: PTRACE_POKETEXT failed: %s\n", strerror(errno));
      success = false;
    }
    bp->enabled = false;
  }
  return success;
}

/**
 * Run the tracee until it stops or hits a breakpoint.
 *
 * @param pid Tracee process id
 * @param bp NULL for first invocation
 *
 * @return 0 If tracee exited, 1 if it stopped at a breakpoint 
 */
int breakfast_run(pid_t pid, breakpoint_t *bp) {
  if (bp) {
    /* POKEUSER: write word at an addr in the USER area, where registers are */
    ptrace(PTRACE_POKEUSER, pid, sizeof(long)*REGISTER_IP, bp->addr);

    // We're currently stopped at "bp". Disable breakpoint, single-step, then re-enable
    breakfast_disable(pid, bp);
    if (!run(pid, PTRACE_SINGLESTEP))
      return 0;
    breakfast_enable(pid, bp);
  }
  return run(pid, PTRACE_CONT);
}

// cmd: Either PTRACE_CONT or PTRACE_SINGLESTEP
// return: 0 if tracee exited; 1 if tracee hit breakpoint
static int run(pid_t pid, int cmd) {
  int status, last_sig = 0, event;
  while (1) {
    ptrace(cmd, pid, 0, last_sig);
    waitpid(pid, &status, 0);

    if (WIFEXITED(status)) {
      debug("breakfast: run: child exited with status=%d\n", WEXITSTATUS(status));
      return 0;
    }

    if (WIFSTOPPED(status)) {
      last_sig = WSTOPSIG(status);
      target_addr_t ip = breakfast_get_ip(pid);
      debug("breakfast: run: current_ip=%p\n", ip);
      psignal(last_sig, "breakfast: run: last_sig");
      if (last_sig == SIGTRAP) {
        event = (status >> 16) & 0xffff;
        if (event == PTRACE_EVENT_EXIT) {
          debug("breakfast: run: tracee exited\n");
          return 0;
        } else {
          return 1;
        }
      }
    }
  }
}
