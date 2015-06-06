#ifndef _BACKTRACE_H
#define _BACKTRACE_H

#include <sys/types.h>  // pid_t

struct backtracer;

struct backtracer *backtrace_init(const char *target, pid_t pid);
void backtrace_execute(struct backtracer *bt);
void backtrace_destroy(struct backtracer *bt);

#endif //_BACKTRACE_H
