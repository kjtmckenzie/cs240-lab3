#ifndef _BACKTRACE_H
#define _BACKTRACE_H

/**
 * How to use:
 * First, before executing the child process, create function table
 * using function "read_symbol_table".
 * 
 * Then use function "execute_backtrace" where you want to execute backtrace.
 *
 * After all, call "destroy_function_table" to free memory.
 */



#include <sys/types.h>

struct fn_info {
  unsigned long long addr;
  unsigned size;
  char *name;
};

typedef struct fn_info finfo;

/**
 * Parameter:
 *   target: the file name (binary file)
 *   size:   the pointer of integer. After execution, 
 *           this will store number of elements in function table.
 */
finfo *read_symbol_table(const char *target, int *size);

/**
 * Parameter:
 *   fntab: function table to destroy.
 *   size:  number of elements in function table.
 */
void destroy_function_table(finfo *fntab, int size);

/**
 * Parameter:
 *   fntab: corresponding function table for child process
 *   size:  number of elements in function table.
 *   pid:   process id to execute backtrace.
 */
void execute_backtrace(finfo *fntab, int size, pid_t pid);

#endif //_BACKTRACE_H
