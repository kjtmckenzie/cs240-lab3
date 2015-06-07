#ifndef _UTILS_H
#define _UTILS_H

// It doesn't make sense to dereference target addresses in the tracer;
// this typedef tries to remind us of that, syntactically
typedef void *target_addr_t;

target_addr_t get_fn_address(const char *fn, const char *target);
target_addr_t *get_fn_call_addrs(const char *fn, const char *target, size_t *n_calls);

#endif
