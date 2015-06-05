#ifndef _STATE_H
#define _STATE_H

#include <stdbool.h>
#include <sys/user.h>
#include <sys/reg.h>
#include "argparse.h"

struct list_entry;

struct injector_state {
  struct list_entry *dir_fds;   /* Linked list of tracee's directory fds */

  bool clone_entering;
  bool entering;
  bool open_entering;
  bool entry_intercepted;
  bool found_directory;

  int status;                    /* Most recent tracee status */
  int syscall_n;                 /* Most recent intercepted syscall no. */
  int intercepted_retval;        /* Most recent intercepted retval */
  long long int syscall_count;   /* Count of syscalls intercepted */

  struct user_regs_struct regs;  /* Most recent tracee register values */
};
typedef struct injector_state state_t;

bool state_add_dir(state_t *state, int fd);
bool state_is_dir(state_t * state, int fd);

state_t *state_init(args_t *args);
void state_reset(state_t *state);
void state_destroy(state_t *state);

#endif
