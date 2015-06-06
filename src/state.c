/* state.c
 *
 * Utilities for managing and passing around injector state.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "argparse.h"
#include "state.h"

struct list_entry {
    int id;         
    struct list_entry * next;
};

static struct list_entry* find_last_node(state_t *state) {
  struct list_entry* cur_node = state->dir_fds;
  while (cur_node != NULL && cur_node->next != NULL){
    cur_node = cur_node->next;
  }
  return cur_node;
}

static void free_dir_fds(state_t *state) {
  struct list_entry* next_node;
  struct list_entry* cur_node = state->dir_fds;
  while (cur_node != NULL) {
    next_node = cur_node->next;
    free(cur_node);
    cur_node = next_node;
  }
  state->dir_fds = NULL;
}

/**
 * Track a tracee's file descriptor known to be associated with a directory.
 *
 * @param state struct injector_state object
 * @param fd file descriptor of a directory in the tracee process
 *
 * @return true on success, or false if memory allocation fails
 */
bool state_add_dir(state_t *state, int fd) {
  struct list_entry* last_node;
  struct list_entry* new_node;
  if ((new_node = (struct list_entry *) malloc(sizeof(struct list_entry)))) {
    new_node->id = fd;
    new_node->next = NULL;
    last_node = find_last_node(state);
    if (last_node == NULL) {
      state->dir_fds = new_node;
    } else {
      last_node->next = new_node;
    }
    return true;
  } else {
    fprintf(stderr, "add_dirfd: malloc failed!\n");
    return false;
  }
}

/**
 * Lookup whether a tracee file descriptor is known to be a directory.
 *
 * @param state struct injector_state object
 * @param fd the tracee file descriptor to search for
 *
 * @return true iff this fd is known to be a directory in the tracee process
 */
bool state_is_dir(state_t *state, int fd) {
  struct list_entry* cur_node = state->dir_fds;
  while (cur_node != NULL) {
    if (cur_node->id == fd)
      return true;
    cur_node = cur_node->next;
  }
  return false;
}

/**
 * Do one-time initialization and setup for a state_t struct.
 *
 * @return a malloc()d and intialized state_t; freed with state_destroy
 */
state_t *state_init(args_t *args) {
  state_t *state = NULL;
  if ((state = malloc(sizeof(state_t)))) {
    memset(state, 0, sizeof(state_t));
  } else {
    fprintf(stderr, "state_init: malloc() failed for state!\n");
    goto fail;
  }

  state_reset(state);

  return state;

fail:
  state_destroy(state);
  return NULL;
}

/**
 * Reset the per-run state to be ready for another run.
 *
 * @param state A struct injector_state that has just been used in a run
 */
void state_reset(state_t *state) {
  free_dir_fds(state);

  state->clone_entering = true;
  state->entering = true;
  state->open_entering = true;
  state->entry_intercepted = false;
  state->found_directory = false;

  state->status = 0;
  state->syscall_n = 0;
  state->intercepted_retval = 0;
  state->syscall_count = 0;

  state->pid = 0;
}

/**
 * Deallocate resources and cleanup a state_t struct.
 *
 * @param state The struct injector_state to be deallocated
 */
void state_destroy(state_t *state) {
  if (state) {
    state_reset(state);

    free(state);
  }
}

