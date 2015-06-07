/* 
 * utils.c
 *
 * Miscellaneous helper utilities that don't revolve around a central struct,
 * like a "state_t", "args_t", or "struct backtracer".
 *
 * Currently has helpers for finding function definitions and function call
 * sites in a target process.
 */

#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "utils.h"

#define BUFLEN 4096

 /**
 * Tries to read the address of the function identified by "fn" from the
 * symbol table in "target", by spawning a subprocess to use 'nm'.
 *
 * @param fn The name of the function to search for; e.g. 'malloc'
 * @param target The target binary, which must be statically compiled
 *
 * @return The address in "target" of function "fn", or NULL if reading fails
 */
target_addr_t get_fn_address(const char *fn, const char *target) {
  char buf[BUFLEN];
  memset(buf, 0, BUFLEN);
  snprintf(buf, BUFLEN - 4, "nm %s", target);

  FILE *fp = popen(buf, "r");
  if (fp == NULL) {
    fprintf(stderr, "get_fn_address: Execution of \"%s\" failed; couldn't read symtab of target!\n", buf);
    return NULL;
  } else if (strlen(fn) > BUFLEN - 3) {
    fprintf(stderr, "get_fn_address: Target function name '%s' is too long!\n", fn);
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
        fprintf(stderr, "get_fn_address: No address in the symbol table for '%s'! Make sure the target was compiled with '-static'!\n", fn);
      } else {
        unsigned long long val;
        if (sscanf(line, "%16llx", &val) <= 0) {
          fprintf(stderr, "get_fn_address: Couldn't parse address from line '%s'\n", line);
        } else {
          // Got the address!
          addr = (void *) val;
        }
      }
      break;
    }
  }

  if (ferror(fp)) {
    fprintf(stderr, "get_fn_address: Error reading line from popen()!\n");
  }
  free(line);
  pclose(fp);
  return addr;
}

// Return # of lines in output of 'cmd', or -1 on failure
static int get_line_count(const char *cmd) {
  FILE *fp = popen(cmd, "r");
  if (!fp) {
    fprintf(stderr, "get_line_count: Execution of \"%s\" failed!\n", cmd);
    return -1;
  }

  int count = 0;
  char *line = NULL;
  size_t len = 0;
  ssize_t read;
  while ((read = getline(&line, &len, fp)) != -1) {
    count++;
  }

  pclose(fp);
  return count;
}

/**
 * Calls objdump and parses its output to gather the call addrs into
 * the addrs array.
 *
 * An example command would be:
 *   $ objdump -D bin/malloc_target | grep 'call.*414690 '
 *
 * And the output this parses would be:
 *     400760:  e8 2b 3f 01 00        callq  414690 <__libc_malloc>
 *     40096a:  e8 21 3d 01 00        callq  414690 <__libc_malloc>
 *     ...
 *
 * @param cmd objump & grep command to find the call sites
 * @param addrs array of (void *) to be populated
 *
 * @return how many addrs were inserted, or -1 on failure
 */
static int read_objdump_addrs(const char *cmd, void **addrs) {
  FILE *fp = popen(cmd, "r");
  if (!fp) {
    fprintf(stderr, "read_addrs: Execution of \"%s\" failed!\n", cmd);
    return -1;
  }

  int count = 0;
  char *line = NULL;
  size_t len = 0;
  ssize_t read;
  while ((read = getline(&line, &len, fp)) != -1) {
    // This is the line for our fn: now try to read the address
    unsigned long long val;
    if (sscanf(line, "%16llx", &val) <= 0) {
      fprintf(stderr, "Couldn't parse address from line '%s'\n", line);
    } else {
      // Got the address!
      addrs[count++] = (void *) val;
    }
  }

  pclose(fp);
  return count;
}

/**
 * Objdumps and greps the "target" executable to find all the call sites of "fn".
 *
 * @param fn The name of the function to search for; e.g. 'malloc'
 * @param target The target binary, which must be statically compiled
 * @param n_calls Pointer to a size_t, gets set to the # of calls on success
 *
 * @return A malloc()d array, which the caller must free, of n_calls call sites
 */
target_addr_t *get_fn_call_addrs(const char *fn, const char *target, size_t *n_calls) {
  void **addrs = NULL;
  target_addr_t fn_addr = get_fn_address(fn, target);
  if (!fn_addr) {
    fprintf(stderr, "get_fn_call_addrs: couldn't find the address of %s in %s!\n",
      fn, target);
    goto fail;
  }

  // Grepping for *address* of fn is more robust than grepping for *name*!
  char cmd[BUFLEN];
  memset(cmd, 0, BUFLEN);
  snprintf(cmd, BUFLEN - 4, "objdump -D %s | grep 'call.*%llx '",
   target, (unsigned long long) fn_addr);

  // First pass over objump output: count how many addrs to malloc() for
  int count = get_line_count(cmd);
  if (count < 0) {
    fprintf(stderr, "get_fn_call_addrs: get_line_count failed!\n");
    goto fail;
  }

  if (!(addrs = malloc(sizeof(void *) * count))) {
    fprintf(stderr, "get_fn_call_addrs: malloc() failed for addrs array!\n");
    goto fail;
  }

  // Second pass: now actually read in the addrs
  int num_addrs = read_objdump_addrs(cmd, addrs);
  if (num_addrs < 0) {
    fprintf(stderr, "get_fn_call_addrs: read_objdump_addrs failed!\n");
    goto fail;
  }

  *n_calls = num_addrs;
  return addrs;

fail:
  if (addrs) {
    free(addrs);
  }
  return NULL;
}
