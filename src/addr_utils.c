/* addr_utils.c
 *
 * Helpers to read either the address of a function in a target executable,
 * or find all of the sites where that function is called.
 */

#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "addr_utils.h"

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
  target_addr_t fn_addr = get_fn_address(fn, target);
  if (!fn_addr) {
    fprintf(stderr, "get_fn_call_addrs: couldn't find the address of %s in %s!\n",
      fn, target);
    return NULL;
  }

  char buf[BUFLEN];
  memset(buf, 0, BUFLEN);
  // Grepping for the *address* of the target function seems more robust than
  // grepping for the *name*!
  snprintf(buf, BUFLEN - 4, "objdump -D %s | grep 'call.*%llu '",
   target, (unsigned long long) fn_addr);

  FILE *fp = popen(buf, "r");
  if (fp == NULL) {
    fprintf(stderr, "get_fn_call_addrs: Execution of \"%s\" failed; couldn't read objdump of target!\n", buf);
    return NULL;
  } else if (strlen(fn) > BUFLEN - 3) {
    fprintf(stderr, "get_fn_call_addrs: Target function name '%s' is too long!\n", fn);
    pclose(fp);
    return NULL;
  }

  size_t count = 0;

  // Pass #1: count how many addrs to malloc for
  char *line = NULL;
  size_t len = 0;
  ssize_t read;
  while ((read = getline(&line, &len, fp)) != -1) {
    count++;
  }

  void **addrs = malloc(sizeof(void *) * count);
  if (!addrs) {
    fprintf(stderr, "get_fn_call_addrs: malloc() failed for addrs array!\n");
    return NULL;
  }

  // Pass #2: Now actually read in the addrs
  line = NULL;
  len = 0;
  size_t addr_idx = 0;
  while ((read = getline(&line, &len, fp)) != -1) {
    // This is the line for our fn: now try to read the address
    unsigned long long val;
    if (sscanf(line, "%16llx", &val) <= 0) {
      fprintf(stderr, "Couldn't parse address from line '%s'\n", line);
    } else {
      // Got the address
      addrs[addr_idx++] = (void *) val;
    }
  }

  // addr_idx is how many we successfully inserted (<= count)
  *n_calls = addr_idx;
  return addrs;
}
