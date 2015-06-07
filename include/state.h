#ifndef _STATE_H
#define _STATE_H

#include <stdbool.h>
#include <sys/user.h>
#include <sys/reg.h>
#include "breakfast.h"
#include "utils.h"
#include "argparse.h"
#include "backtrace.h"

struct list_entry;

struct injector_state {
  struct list_entry *dir_fds;   /* Linked list of tracee's directory fds */

  bool clone_entering;          /* Are we entering or exiting a clone call? */
  bool entering;                /* Entering or exiting a syscall? */
  bool open_entering;           /* Entering or exiting open()? */
  bool entry_intercepted;       /* Did we intercept a syscall this iter? */
  bool found_directory;         /* Have we seen open() for a dir? */

  int syscall_n;                /* Most recent intercepted syscall no. */
  int intercepted_retval;       /* Most recent intercepted retval */
  long long int syscall_count;  /* Count of syscalls intercepted */

  size_t n_functions;           /* Number of functions to intercept */

  /* fn_call_addrs: length (args->n_functions) array of function callsites */
  /* fn_call_addrs[i]: the array of call sites for args->fn_names[i] */
  target_addr_t **fn_call_addrs;

  /* n_calls[i]: length of fn_call_addrs[i] array */
  size_t *n_calls;

  int pid;                       /* Pid of the tracee process */
  int status;                    /* Most recent tracee status */
  struct user_regs_struct regs;  /* Most recent tracee register values */

  struct backtracer *bt;
};
typedef struct injector_state state_t;

bool state_add_dir(state_t *state, int fd);
bool state_is_dir(state_t * state, int fd);

void state_prep_backtrace(state_t *state, const char *target, pid_t pid);
void state_dump(state_t *state, FILE *f);

state_t *state_init(args_t *args);
void state_reset(state_t *state);
void state_destroy(state_t *state);

#endif
