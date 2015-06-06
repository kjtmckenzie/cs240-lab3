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

/////////////////////////////////////////////////////

int finfo_cmp(const void *one, const void *two) {
   return (((finfo *)one)->addr > ((finfo *)two)->addr);
}

////////////////////////////////////////////////////

struct bt_info {
  unsigned offset;
  char *name;
};

typedef struct bt_info btinfo;

int addr_in_range(const void *one, const void *two) {
  finfo *first = (finfo *)one;
  finfo *second = (finfo *)two;

  if(first->addr >= second->addr && first->addr < (second->addr + second->size))
    return 0;
  else if (first->addr < second->addr) return -1;
  else return 1;
}

////////////////////////////////////////////////////

finfo *read_symbol_table(const char *target, int *size) {
  char buf[BUFLEN];
  memset(buf, 0, BUFLEN);
  snprintf(buf, BUFLEN - 4, "readelf -s %s", target);

  FILE *fp = popen(buf, "r"); 
  if (fp == NULL) {
    fprintf(stderr, "Execution of \"%s\" failed; couldn't read symtab of target!\n", buf);
    return NULL;
  }

  finfo flist[1000];
  int count = 0;

  char *line = NULL;
  size_t len = 0;
  ssize_t read;

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

    if(count == 1000) break; // Too many functions. Maybe need fix?
  }

  qsort(flist, count, sizeof(finfo), finfo_cmp);

  finfo *return_list = (finfo *)malloc(sizeof(finfo) * count);
  memcpy(return_list, flist, sizeof(finfo) * count);

  *size = count;

  return return_list;
}

/////////////////////////////////////////////////////////

btinfo *get_bt_info_from_addr(finfo *fntab, int size, void *addr_) {
  unsigned long long addr = (unsigned long long)addr_;

  finfo temp;
  temp.addr = addr;

  finfo *curr_fn = bsearch(&temp, fntab, size, sizeof(finfo), addr_in_range);

  btinfo *new_btinfo = (btinfo *)malloc(sizeof(btinfo)); 
  new_btinfo->offset = addr - curr_fn->addr;
  new_btinfo->name = curr_fn->name;

  return new_btinfo;
}

////////////////////////////////////////////////////////

void execute_backtrace(finfo *fntab, int size, pid_t pid) {

  struct user_regs_struct regs;
  void *rbp, *rip;

  rip = (void *)ptrace(PTRACE_PEEKUSER, pid, sizeof(long) * RIP, 0);
  rbp = (void *)ptrace(PTRACE_PEEKUSER, pid, sizeof(long) * RBP, 0);

  fprintf(stderr, "Backtrace starts at instruction (%p)\n", rip);

  while(rbp) {
    btinfo *curr_stack = get_bt_info_from_addr(fntab, size, rip);
    fprintf(stderr, "	->in \"%s\" at offset (0x%x)\n", curr_stack->name, curr_stack->offset);

    rip = (void *)ptrace(PTRACE_PEEKTEXT, pid, (void *)((char *)rbp + sizeof(void *)), 0);
    rbp = (void *)ptrace(PTRACE_PEEKTEXT, pid, rbp, 0);

    free(curr_stack);
  }

  return;
}

////////////////////////////////////////////////////////

void destroy_function_table(finfo *fntab, int size) {
  if(!fntab) return;

  for(int i = 0; i < size; i++) {
    free(fntab[i].name);
  }

  free(fntab);
}
