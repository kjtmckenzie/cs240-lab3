#ifndef _ARGPARSE_H
#define _ARGPARSE_H

#include <stdbool.h>

typedef enum {skip_n,
              run_n,
              run_all}
injector_mode_t;

struct injector_args {
    size_t n_syscalls;      /* Length of syscall_nos array */
    int *syscall_nos;       /* Array of syscall #s to inject */
    long long int *syscall_retvals;   /* Array of corresponding return values */

    size_t n_functions;     /* Length of fn_names array */
    char **fn_names;        /* Array of library function calls to intercept */
    int *fn_retvals;        /* Array of return values for intercepted functions */

    bool fail_on_entry;     /* True to fail on entry; false to fails on exit */
    bool follow_clones;     /* True to follow clones/forks creates by the traced process. */
    bool fail_only_dirs;    /* Specific to FS calls: true to only fail syscalls to directories. */

    injector_mode_t mode;   /* "Skip N", "Run N", or "Run Full" injector mode */
    long long int num_ops;  /* Number of skipped ops, or runs */

    int target_argc;        /* Length of target_argv array */
    char **target_argv;     /* Array of target path & cmdline args */
};
typedef struct injector_args args_t;

void argparse_usage();
args_t *argparse_parse(int argc, char *argv[]);
void argparse_destroy(args_t *args);

#endif
