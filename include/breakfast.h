#ifndef _BREAKFAST_H
#define _BREAKFAST_H

#include <stdbool.h>
#include <sys/types.h>  /* for pid_t */

/* This typedef reminds us not to deference the tracee addr in the tracer process */
typedef void *target_addr_t;

struct breakpoint {
  target_addr_t addr;       /* The breakpoint address in the tracee */
  long orig;                /* The original word at that address */
  bool enabled;             /* Enabled or disabled */

  struct breakpoint *next;  /* Linked-list of breakpoints */
};
typedef struct breakpoint breakpoint_t;

target_addr_t breakfast_get_ip(pid_t pid);

breakpoint_t *breakfast_create(pid_t pid, target_addr_t addr);
void breakfast_destroy (pid_t pid, breakpoint_t *bp);

bool breakfast_enable(pid_t pid, breakpoint_t *bp);
bool breakfast_disable(pid_t pid, breakpoint_t *bp);

int breakfast_run(pid_t pid, breakpoint_t *bp);

#endif
