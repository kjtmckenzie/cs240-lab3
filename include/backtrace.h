#ifndef _BACKTRACE_H
#define _BACKTRACE_H

#include <sys/types.h>  // pid_t

struct backtracer;

struct backtracer *backtrace_init(const char *target, pid_t pid);
void backtrace_execute(struct backtracer *bt);
void backtrace_destroy(struct backtracer *bt);

// TODO: remove these once test_parent no longer relies on them

/**
 * Parameter:
 *   target: the file name (binary file)
 *   size:   the pointer of integer. After execution, 
 *           this will store number of elements in function table.
 */
struct fn_info *read_symbol_table(const char *target, int *size);

/**
 * Parameter:
 *   fntab: corresponding function table for child process
 *   size:  number of elements in function table.
 *   pid:   process id to execute backtrace.
 */
void execute_backtrace(struct fn_info *fntab, int size, pid_t pid);

/**
 * Parameter:
 *   fntab: function table to destroy.
 *   size:  number of elements in function table.
 */
void destroy_function_table(struct fn_info *fntab, int size);


#endif //_BACKTRACE_H
