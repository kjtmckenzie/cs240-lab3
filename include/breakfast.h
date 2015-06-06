#ifndef _BREAKFAST_H
#define _BREAKFAST_H

#include <sys/types.h>  /* for pid_t */

/* This typedef reminds us not to deference the tracee addr in the tracer process */
typedef void *target_addr_t;

struct breakpoint {
  target_addr_t addr;  /* The breakpoint address in the tracee */
  long orig_code;      /* The original word at that address */
};

void breakfast_attach(pid_t pid);
target_addr_t breakfast_getip(pid_t pid);
struct breakpoint *breakfast_break(pid_t pid, target_addr_t addr);
void breakfast_destroy (pid_t pid, struct breakpoint *bp);
int breakfast_run(pid_t pid, struct breakpoint *bp);

#endif
