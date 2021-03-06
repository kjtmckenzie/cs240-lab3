/* 
 * argparse.c
 *
 * Utilities for parsing cmdline args for the fault injector.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <search.h>
#include "argparse.h"

#define MAX_SYSCALLS 430

#define INPUT_LIST_DELIM ","

#define MAX_TARGET_LEN 1024
#define MAX_TARGET_ARGS 64

// Argument argv indices
#define SYSCALLS      1
#define SYS_RETVALS   2
#define FUNCTIONS     3
#define FN_RETVALS    4
#define FAIL_ENTRY    5
#define FOLLOW_CLONES 6
#define ONLY_DIRS     7
#define AFTER_MAIN    8
#define BACKTRACE     9
#define RUN_MODE      10
#define NUM_OPS       11
#define TARGET        12

/**
 * Prints the expected argument structure and order.
 */
void argparse_usage() {
  printf("\n");
  printf("Ptrace Fault Injector\n");
  printf("=====================\n");
  printf("Usage:\n");
  printf("    injector syscalls sys_retvals functions fn_retvals fail_on_entry follow_clones only_dirs after_main run_mode num target\n");
  printf("\n");
  printf("Where:\n");
  printf("    syscalls: Syscall numbers to intercept.\n");
  printf("              Single number, comma-separated values, or -1 to intercept none.\n");
  printf("    sys_retvals: System call integer return values to inject.\n");
  printf("                 Singleton or comma-separated values.\n");
  printf("    functions: libc function names to intercept.\n");
  printf("               Single name, comma-separated names, or -1 to intercept none.\n");
  printf("    fn_retvals: Function return values to inject.\n");
  printf("                Singleton or comma-separated values.\n");
  printf("    fail_on_entry: 1 to fail syscall on entry, or\n");
  printf("                   0 to fail syscall after it has returned\n");
  printf("    follow_clones: 1 to follow processes cloned/forked by the traced process.\n");
  printf("                   0 to follow no subprocesses besides the initial traced process.\n");
  printf("    only_dirs: 1 to have filesystem-based syscalls fail only for directories.\n");
  printf("               0 to have filesystem-based syscalls fail on any ops when scheduled.\n");
  printf("    after_main: 1 to only begin faulting after entering main() of the target\n");
  printf("                0 to begin faulting immediately\n");
  printf("    perform_backtrace: 1 to construct a backtrace on child process termination by singal\n");
  printf("                       0 to not construct any backtrace\n");
  printf("    run_mode: Controls how faults are injected from run to run. Valid modes are:\n");
  printf("              \"skip\": Injector will skip \'num\' syscalls before injecting.\n");
  printf("              \"run\": Injector runs \'num\' times. Run i skips the first i syscalls before injection.\n");
  printf("              \"full\": Injector \n");
  printf("    num: The number of syscall skips or runs; ignored if run_mode is \"full\".\n");
  printf("    target: Path to target executable. Include cmdline args within a single string.\n");
  printf("\n");
  printf("Examples:\n");
  printf("    Fault getuid() to return -1:\n");
  printf("      $ ./bin/injector 102 -1 -1 0 1 0 0 0 1 skip 0 'bin/getuid_target'\n");
  printf("    Fault malloc() to return NULL:\n");
  printf("      $ ./bin/injector -1 -1 malloc 0 1 0 0 1 1 skip 0 'bin/malloc_target'\n");
  printf("\n");
}

/* A simple int comparison functions for checking against syscall numbers. Used for lfind. */
static int cmp_sys_num(const void* num_a, const void* num_b) {
  return (*(int*)num_a) - (*(int*)num_b);
}

/* Parses the comma-separated lists of target syscalls and return values. Returns 0 unless
*  something bad happened in the parsing. Note that this functiona allocates dynamic memory
*  to store the syscall numbers array and the return value arrays. */
static bool parse_syscalls(args_t *args, char *argv[]) {
  if (!strcmp(argv[SYSCALLS], "-1")) {
    // No syscalls will be faulted
    args->n_syscalls = 0;
    args->r_type = r_function;
    return true;
  }

  args->r_type = r_syscall;

  int sys_buf[MAX_SYSCALLS];
  long long int ret_buf[MAX_SYSCALLS];
  size_t n_syscalls = 0;
  size_t n_retvals = 0;

  char* sys_args = argv[SYSCALLS];
  char* ret_args = argv[SYS_RETVALS];

  // Read in the syscall numbers.
  char* cur_sys = strtok(sys_args, INPUT_LIST_DELIM);
  while ((cur_sys != NULL) && (n_syscalls < MAX_SYSCALLS)) {
    int ival = atoi(cur_sys);
    if (lfind(&ival, sys_buf, &n_syscalls, sizeof(int), cmp_sys_num)) {
      fprintf(stderr, "parse_syscalls: Invalid target syscall list -- duplicate syscall numbers are not allowed.\n");
      return false;
    }
    sys_buf[n_syscalls] = ival;
    n_syscalls++;
    cur_sys = strtok(NULL, INPUT_LIST_DELIM);
  }

  // Read in the return values.
  char* cur_ret = strtok(ret_args, INPUT_LIST_DELIM);
  while ((cur_ret != NULL) && (n_retvals < n_syscalls)) {
    int rval = atoi(cur_ret);
    ret_buf[n_retvals] = rval;
    n_retvals++; 
    cur_ret = strtok(NULL, INPUT_LIST_DELIM);
  }
  if ((n_retvals < n_syscalls) || (cur_ret && (*cur_ret))) {
    fprintf(stderr, "parse_syscalls: Invalid syscall retval list -- number of values should match number of target syscalls.\n");
    return false;
  }

  // Allocate right-sized arrays and fill in "args".
  if (!(args->syscall_nos = malloc(sizeof(int) * n_syscalls))) {
    fprintf(stderr, "parse_syscalls: Failed to allocate memory for syscall numbers\n");
    return false;
  }
  if (!(args->syscall_retvals = malloc(sizeof(long long int) * n_retvals))) {
    fprintf(stderr, "parse_syscalls: Failed to allocate memory for syscall return values\n");
    return false;
  }
  memcpy(args->syscall_nos, sys_buf, sizeof(int) * n_syscalls);
  memcpy(args->syscall_retvals, ret_buf, sizeof(long long int) * n_retvals);

  args->n_syscalls = n_syscalls;

  return true;
}

static bool parse_functions(args_t *args, char *argv[]) {
  if (!strcmp(argv[FUNCTIONS], "-1")) {
    // No functions will be faulted
    args->n_functions = 0;
    return true;
  } else if (args->r_type == r_syscall) {
    // TODO: injector currently only supports faulting syscalls OR functions; not both simultaneously!
    fprintf(stderr, "Error: injector does not yet support simultaneous function and syscall interception.\n");
    fprintf(stderr, "\tOne of \"syscalls\" and \"functions\" must be -1.\n");
    exit(1);
  }

  args->r_type = r_function;

  char *fn_buf[MAX_SYSCALLS];
  long long int ret_buf[MAX_SYSCALLS];
  size_t n_functions = 0;
  size_t n_retvals = 0;

  char* fn_args = argv[FUNCTIONS];
  char* ret_args = argv[FN_RETVALS];

  // Read in the function names
  char* cur_fn = strtok(fn_args, INPUT_LIST_DELIM);
  while ((cur_fn != NULL) && (n_functions < MAX_SYSCALLS)) {
    fn_buf[n_functions] = strdup(cur_fn);
    n_functions++;
    cur_fn = strtok(NULL, INPUT_LIST_DELIM);
  }

  // Read in the return values.
  char* cur_ret = strtok(ret_args, INPUT_LIST_DELIM);
  while ((cur_ret != NULL) && (n_retvals < n_functions)) {
    int rval = atoi(cur_ret);
    ret_buf[n_retvals] = rval;
    n_retvals++;
    cur_ret = strtok(NULL, INPUT_LIST_DELIM);
  }
  if ((n_retvals < n_functions) || (cur_ret && (*cur_ret))) {
    fprintf(stderr, "parse_functions: Invalid retval list -- number of values should match number of target functions.\n");
    return false;
  }

  // Allocate right-sized arrays and fill in "args".
  if (!(args->fn_names = malloc(sizeof(char *) * n_functions))) {
    fprintf(stderr, "parse_functions: Failed to allocate memory for function names\n");
    return false;
  }
  if (!(args->fn_retvals = malloc(sizeof(long long int) * n_retvals))) {
    fprintf(stderr, "parse_functions: Failed to allocate memory for function return values\n");
    return false;
  }
  memcpy(args->fn_names, fn_buf, sizeof(char*) * n_functions);
  memcpy(args->fn_retvals, ret_buf, sizeof(long long int) * n_retvals);

  args->n_functions = n_functions;

  return true;
}

static bool parse_flags(args_t *args, char *argv[]) {
  if (strcmp(argv[FAIL_ENTRY], "0") && strcmp(argv[FAIL_ENTRY], "1")) {
    fprintf(stderr, "parse_flags: Expected 0 or 1 for fail_entry, got %s\n", argv[FAIL_ENTRY]);
    return false;
  }
  args->fail_on_entry = atoi(argv[FAIL_ENTRY]);

  if (strcmp(argv[FOLLOW_CLONES], "0") && strcmp(argv[FOLLOW_CLONES], "1")) {
    fprintf(stderr, "parse_flags: Expected 0 or 1 for follow_clones, got %s\n", argv[FOLLOW_CLONES]);
    return false;
  }
  args->follow_clones = atoi(argv[FOLLOW_CLONES]);

  if (strcmp(argv[ONLY_DIRS], "0") && strcmp(argv[ONLY_DIRS], "1")) {
    fprintf(stderr, "parse_flags: Expected 0 or 1 for only_dirs, got %s\n", argv[ONLY_DIRS]);
    return false;
  }
  args->fail_only_dirs = atoi(argv[ONLY_DIRS]);

  if (strcmp(argv[AFTER_MAIN], "0") && strcmp(argv[AFTER_MAIN], "1")) {
    fprintf(stderr, "parse_flags: Expected 0 or 1 for after_main, got %s\n", argv[AFTER_MAIN]);
    return false;
  }
  args->after_main = atoi(argv[AFTER_MAIN]);

  if (strcmp(argv[BACKTRACE], "0") && (strcmp(argv[BACKTRACE], "1"))) {
    fprintf(stderr, "parse_flags: Expected 0 or 1 for perform_backtrace, got %s\n", argv[BACKTRACE]);
    return false;
  }
  args->run_backtrace = atoi(argv[BACKTRACE]);

  return true;
}

static bool parse_run_mode(args_t *args, char *argv[]) {
  if (!strcmp(argv[RUN_MODE], "skip")) {
    args->mode = skip_n;
  } else if (!strcmp(argv[RUN_MODE], "run")) {
    args->mode = run_n;
  } else if (!strcmp(argv[RUN_MODE], "full")) {
    args->mode = run_all;
  } else {
    fprintf(stderr, "parse_run_mode: Unknown value for run_mode: \"%s\".\n", argv[RUN_MODE]);
    return false;
  }

  args->num_ops = atoll(argv[NUM_OPS]);

  return true;
}

/* Parses the target command, extracting arguments as individual strings and allocating
 * each string as well as the array to hold them. Returns the number of arguments. */
int parse_target_command(char* cmd, char** target_name, char*** target_args) {
  char target_buf[MAX_TARGET_LEN];
  char* targ_buf[MAX_TARGET_ARGS];
  strcpy(target_buf, cmd);
  
  //Extract and save a copy of the target executable path.
  char* cur_arg = strtok(target_buf, " ");
  *target_name = strdup(cur_arg);
  targ_buf[0] = strdup(*target_name);

  int i = 1;
  
  while ((cur_arg = strtok(NULL, " "))) {
    targ_buf[i] = strdup(cur_arg);
    i++;
  }

  *target_args = malloc(sizeof(char*) * (i+1));
  memcpy(*target_args, targ_buf, sizeof(char*) * i);

  return i;
}

static bool parse_target(args_t *args, int argc, char *argv[]) {
  if(strlen(argv[TARGET]) > MAX_TARGET_LEN) {
    fprintf(stderr, "parse_target: Target command cannot exceed %d characters.\n", MAX_TARGET_LEN);
    return false;
  }

  // "target" holds the full cmdline: path arg1 arg2 arg3...
  char target[MAX_TARGET_LEN + 1]; 
  strcpy(target, argv[TARGET]);

  // "target_argv" will hold the strdup()d strings as we tokenize them
  char* target_argv[MAX_TARGET_ARGS];
  
  char* cur = strtok(target, " ");
  //printf("parse_target: parsed %s for target_argv[0]\n", cur);
  //fflush(0);
  target_argv[0] = strdup(cur);
  args->target_argc = 1;

  while ((cur = strtok(NULL, " "))) {
    if (args->target_argc > MAX_TARGET_ARGS) {
      fprintf(stderr, "parse_target: target cannot have more than %d arguments.\n", MAX_TARGET_ARGS - 1);
      return false;
    }
    target_argv[args->target_argc] = strdup(cur);
    args->target_argc++;
  }

  if (!(args->target_argv = malloc(sizeof(char*) * (args->target_argc + 1)))) {
    fprintf(stderr, "parse_target: malloc failed for args->target_argv!\n");
    return false;
  }
  memcpy(args->target_argv, target_argv, sizeof(char*) * args->target_argc);
  args->target_argv[args->target_argc] = 0;
  return true;
}

/**
 * Attempts to parse and validate the cmdline arguments into a struct injector_args.
 * Complains into stderr if an argument is missing or invalid.
 * The returned args_t should be deallocated with argparse_destroy() when not needed.
 *
 * @param argc The argc to main() of injector
 * @param argv The argv to main() of injector
 *
 * @return A malloc()d struct injector_args, or NULL on error
 */
args_t *argparse_parse(int argc, char*argv[]) {
  args_t *args = NULL;
  if (argc < TARGET + 1) {
    fprintf(stderr, "Wrong number of arguments (got %d; need %d)\n", argc, TARGET + 1);
    argparse_usage();
    goto fail;
  }

  if ((args = malloc(sizeof(args_t)))) {
    memset(args, 0, sizeof(args_t));
  } else {
    fprintf(stderr, "argparse_parse: malloc() failed for args!\n");
    goto fail;
  }

  // Parse the syscall_nos and syscalls_retval CSV arguments
  if (!parse_syscalls(args, argv)) {
    fprintf(stderr, "argparse_parse: parse_syscalls failed!\n");
    goto fail;
  }

  // Parse "functions" and "fn_retvals", each CSVs
  if (!parse_functions(args, argv)) {
    fprintf(stderr, "argparse_parse: parse_functions failed!\n");
    goto fail;
  }

  // Parse the "fail_on_entry", "follow_clones", and "only_dirs" flags
  if (!parse_flags(args, argv)) {
    fprintf(stderr, "argparse_parse: parse_flags failed!\n");
    goto fail;
  }

  // Parse the "run mode" and "num"
  if (!parse_run_mode(args, argv)) {
    fprintf(stderr, "argparse_parse: parse_run_mode failed!\n");
    goto fail;
  }

  // Parse the target path, cmdline args, and target_argc
  if (!parse_target(args, argc, argv)) {
    fprintf(stderr, "argparse_parse: parse_target failed!\n");
    goto fail;
  }

  return args;

fail:
  argparse_destroy(args);
  return NULL;
}

/**
 * Release memory associated with a struct injector_args. We probably won't need to use
 * this, but it's here for completeness. 
 *
 * @param args A struct injector_args malloc()d by parse_args
 */
void argparse_destroy(args_t *args) {
  if (args) {
    if (args->syscall_nos) {
      free(args->syscall_nos);
    }

    if (args->syscall_retvals) {
      free(args->syscall_retvals);
    }

    if (args->fn_names) {
      for (int i = 0; i < args->n_functions; i++) {
        free(args->fn_names[i]);
      }

      free(args->fn_names);
    }

    if (args->fn_retvals) {
      free(args->fn_retvals);
    }

    if (args->target_argv) {
      for (int i = 0; i < args->target_argc; i++) {
        free(args->target_argv[i]);
      }

      free(args->target_argv);
    }

    free(args);
  }
}
