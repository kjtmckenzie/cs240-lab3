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
#include "backtrace.h"

#define BUFLEN 4096
// TODO: look into a more robust way to do this
#define FLIST_SIZE 10000

// Function table entry
struct fn_info {
  unsigned long long addr;
  unsigned size;
  char *name;
};

// backtracer state
struct backtracer {
  pid_t pid;
  int fn_table_len;
  struct fn_info *fn_table;
};

// Entry in the backtrace crawl
struct bt_entry {
  unsigned offset;
  char *name;
};

// Simple comparison function for struct bt_entry
static int finfo_cmp(const void *one, const void *two) {
   return (((struct fn_info *)one)->addr > ((struct fn_info *)two)->addr);
}

static int addr_in_range(const void *one, const void *two) {
  struct fn_info *first = (struct fn_info *)one;
  struct fn_info *second = (struct fn_info *)two;

  if(first->addr >= second->addr && first->addr < (second->addr + second->size)) {
    return 0;
  } else if (first->addr < second->addr) {
    return -1;
  } else {
    return 1;
  }
}

/**
 * Parameter:
 *   target: the file name (binary file)
 *   size:   the pointer of integer. After execution, 
 *           this will store number of elements in function table.
 */
struct fn_info *read_symbol_table(const char *target, int *size) {
  char buf[BUFLEN];
  memset(buf, 0, BUFLEN);
  snprintf(buf, BUFLEN - 4, "readelf -s %s", target);

  FILE *fp = popen(buf, "r"); 
  if (fp == NULL) {
    fprintf(stderr, "Execution of \"%s\" failed; couldn't read symtab of target!\n", buf);
    return NULL;
  }

  struct fn_info flist[FLIST_SIZE];
  int count = 0;

  char *line = NULL;
  size_t len = 0;
  ssize_t read;

  // Skip boilerplate
  read = getline(&line, &len, fp);
  read = getline(&line, &len, fp);
  read = getline(&line, &len, fp);

  while ((read = getline(&line, &len, fp)) != -1) {
    char *tok = strtok(line, " ");
    int temp_idx = 0;
    while(tok) {
      if(temp_idx == 1) 
        flist[count].addr = strtoull(tok, NULL, 16);
      else if(temp_idx == 2)
        flist[count].size = atoi(tok);
      else if(temp_idx == 3 && strcmp(tok, "FUNC") != 0) break;
      else if(temp_idx == 7) {
        tok[strlen(tok) - 1] = 0; // Erase new line at the end
        flist[count].name = strdup(tok);
        count++;
      }

      temp_idx++;
      tok = strtok(NULL, " ");
    }

    if(count == FLIST_SIZE) break; // Too many functions. Maybe need fix?
  }

  qsort(flist, count, sizeof(struct fn_info), finfo_cmp);

  struct fn_info *return_list = (struct fn_info *)malloc(sizeof(struct fn_info) * count);
  memcpy(return_list, flist, sizeof(struct fn_info) * count);

  *size = count;

  return return_list;
}

struct bt_entry *get_bt_info_from_addr(struct fn_info *fntab, int size, void *addr_) {
  unsigned long long addr = (unsigned long long)addr_;

  struct fn_info temp;
  temp.addr = addr;

  struct fn_info *curr_fn = bsearch(&temp, fntab, size, sizeof(struct fn_info), addr_in_range);
  if(!curr_fn) return NULL;

  struct bt_entry *new_btinfo = (struct bt_entry *)malloc(sizeof(struct bt_entry)); 
  new_btinfo->offset = addr - curr_fn->addr;
  new_btinfo->name = curr_fn->name;

  return new_btinfo;
}

/**
 * Parameter:
 *   fntab: corresponding function table for child process
 *   size:  number of elements in function table.
 *   pid:   process id to execute backtrace.
 */
void execute_backtrace(struct fn_info *fntab, int size, pid_t pid) {

  struct user_regs_struct regs;
  void *rbp, *rip;

  rip = (void *)ptrace(PTRACE_PEEKUSER, pid, sizeof(long) * RIP, 0);
  rbp = (void *)ptrace(PTRACE_PEEKUSER, pid, sizeof(long) * RBP, 0);

  fprintf(stderr, "Backtrace starts at instruction (%p)\n", rip);

  while(rbp) {
    struct bt_entry *curr_stack = get_bt_info_from_addr(fntab, size, rip);
    if(!curr_stack) break;
    fprintf(stderr, " ->in \"%s\" at offset (0x%x) on address (%p)\n", 
                   curr_stack->name, curr_stack->offset, rip);

    rip = (void *)ptrace(PTRACE_PEEKTEXT, pid, (void *)((char *)rbp + sizeof(void *)), 0);
    rbp = (void *)ptrace(PTRACE_PEEKTEXT, pid, rbp, 0);

    free(curr_stack);
  }
}

/**
 * Parameter:
 *   fntab: function table to destroy.
 *   size:  number of elements in function table.
 */
void destroy_function_table(struct fn_info *fntab, int size) {
  if(fntab) {
    for(int i = 0; i < size; i++) {
      free(fntab[i].name);
    }

    free(fntab);
  }
}

struct backtracer *backtrace_init(const char *target, pid_t pid) {
  struct backtracer *bt = malloc(sizeof(struct backtracer));
  if (!bt) {
    fprintf(stderr, "backtrace_init: malloc failed!\n");
    return NULL;
  }

  bt->pid = pid;
  bt->fn_table = read_symbol_table(target, &(bt->fn_table_len));

  return bt;
}

void backtrace_execute(struct backtracer *bt) {
  execute_backtrace(bt->fn_table, bt->fn_table_len, bt->pid);
}

void backtrace_destroy(struct backtracer *bt) {
  if (bt) {
    destroy_function_table(bt->fn_table, bt->fn_table_len);
    free(bt);
  }
}
