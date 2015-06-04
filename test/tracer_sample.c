#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <sys/reg.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <search.h>

#define MAX_TARGET_LEN 1024
#define MAX_TARGET_ARGS 64

#define MAX_ARGS 9
#define MIN_ARGS 7

#define FULL_RUN_MODE 0
#define RUN_MODE 1
#define SKIP_MODE 2

#define MAX_SYSCALLS 430

#define READ 0
#define WRITE 1
#define OPEN 2
#define CLOSE 3
#define FSYNC 74
#define MKDIR 83
#define OPENAT 257

#define INPUT_LIST_DELIM ","
//A return value indicating we reached past the end of executable. Chosen larger than 256 so that it 
//won't clash with most POSIX exit codes.
#define END_OF_EXECUTABLE 400

void print_usage_and_exit() {
  printf("Usage: tracer_sample signum[,signum2,signum3,...] retval[,retval2,retval3,...] fail_on_entry follow_clones [ -s num_to_skip || -r num_of_runs ] target\n");
  printf("    signum: Syscall #s to intercept\n");
  printf("    retval: Return value to insert. Should be one retval per signum\n");
  printf("    fail_on_entry: 1 to fail syscall on entry or 0 to fail syscall after it has returned\n");
  printf("    follow_clones: 1 to trace cloned or forked processes or 0 to only trace the original process\n");
  printf("    fail_only_dirs: 1 to fail syscalls only on directory file descriptors\n");
  printf("    num_to_skip: Number of syscalls to skip before injection\n");
  printf("    num_of_runs: Runs in multi-run mode, skipping first 0 syscalls before fault injection, then 1, 2, etc.. up to num_of_runs\n");
  printf("    target: Path to target executable. Include any command-line args to run with\n");
  printf("Default behavior for skip/runs is to run until no faults are injected.\n");
  exit(1);
}

/* A simple int comparison functions for checking against syscall numbers. Used for lfind. */
int cmp_sys_num(const void* num_a, const void* num_b) {
  return (*(int*)num_a) - (*(int*)num_b);
}

struct list_entry {
    int id;         
    struct list_entry * next;
};

struct list_entry * list_of_dirfds;

struct list_entry* find_last_node() {
  struct list_entry* cur_node;
  if (list_of_dirfds == NULL)
    return NULL;
  cur_node = list_of_dirfds;
  while (cur_node->next != NULL){
    cur_node = cur_node->next;
  }
  return cur_node;
}

void add_dirfd(int dirfd) {
  struct list_entry* last_node;
  struct list_entry* new_node = (struct list_entry *) malloc(sizeof(struct list_entry));
  new_node->id = dirfd;
  new_node->next = NULL;
  last_node = find_last_node();
  if (last_node == NULL)
    list_of_dirfds = new_node;
  else
    last_node->next = new_node;
}

int is_dirfd(int fd) {
  struct list_entry* cur_node = list_of_dirfds;
  while (cur_node != NULL) {
    if (cur_node->id == fd)
      return 1;
    cur_node = cur_node->next;
  }
  return 0;
}

void free_dirfd_list() {
  struct list_entry* next_node;
  struct list_entry* cur_node = list_of_dirfds;
  if (cur_node != NULL) {
    next_node = cur_node->next;
    free(cur_node);
    cur_node = next_node;
  }
  return;
}

int clone_entering = 1;
/* Get PID of cloned process.  If not process was cloned or an error occured, return -1 */
/* pid is the process id of the current traced process */
int trace_clone(long pid) {
  long newpid, trace;
  int syscall_n;
  struct user_regs_struct regs;
  ptrace( PTRACE_GETREGS, pid, 0, &regs );
  syscall_n = regs.orig_rax;
  if (syscall_n == 56) {
    if (clone_entering) {
      clone_entering = 0;
    } else {
      clone_entering = 1;
      newpid = regs.rax;
      //ptrace(PTRACE_DETACH,pid,NULL,NULL);
      trace = ptrace(PTRACE_ATTACH,newpid,NULL,NULL);
      ptrace( PTRACE_SYSCALL, newpid, 0, 0 );
      if(trace == 0) {
        //printf("\e[1;32mAttached to offspring %ld\n\e[0m", newpid);  
        //fflush(stdout);
        return newpid;
      } else {
        printf("Could not attach to the child, trace = %ld\n", trace);
        fflush(stdout);
        return -1;
      }
    }
  }
  return -1;
}

/* Perform a single run of tracing, skipping the first num_to_skip syscalls and injecting a fault in all those 
   that follow. */
int single_injection_run(int* target_syscalls, int num_syscalls, long long int* retvals,
			 int fail_on_entry, int follow_clones, int fail_only_dirs, long long int num_to_skip, char* target, char** args) {
  int status = 0;
  int syscall_n = 0;
  int entering = 1;
  int open_entering = 1;
  int entry_intercepted = 0;
  int intercepted_retval = 0;
  long long int syscall_count = 0;
  struct user_regs_struct regs;
  int found_directory = 0;
  int cloned_pid;
  int flags;
  int pid = fork();
  if ( !pid ) {
    printf("The child is running\n");
    ptrace( PTRACE_TRACEME, 0, 0, 0 );
    execvp( target, args );
  }
  else {
    // Print status message concerning the run.
    printf("\nRunning ptrace injector on %s for syscalls: ", target);
    ptrace( PTRACE_SYSCALL, pid, 0, 0 );
    for (int i = 0; i < num_syscalls; i++) {
      printf("%d, ", target_syscalls[i]);
    }
    printf("with num_to_skip %lld\n", num_to_skip);
    wait( &status );

    size_t loop_counter = 0; 
    while ( 1 ) {
      ptrace( PTRACE_SYSCALL, pid, 0, 0 );
      wait( &status );
      fflush(stdout);

      
      if ( WIFEXITED( status ) ) {
        break;
      }
      else { 
        /* I'm not sure this code works as intended */
        //sleep(1);
        fflush(stdout);
        loop_counter ++; 
        if (loop_counter > 1000000) {
          printf("TIMEOUT: Ptrace is taking too long on %s for syscall %d\n", target, syscall_n);
          exit(-1);
        }
        
      }
      //printf("Im here! 5\n");
      fflush(stdout);
      // check to see if the process has cloned itself
      if (follow_clones) {
        cloned_pid = trace_clone(pid);
        if (cloned_pid > 0)
          pid = cloned_pid;
      }

      ptrace( PTRACE_GETREGS, pid, 0, &regs );

      // get syscall number
      syscall_n = regs.orig_rax;

      int* syscall_idx = NULL;
      
      size_t n_syscalls_idx = num_syscalls;
      // only intercept the syscall we want to intercept
      
      if (open_entering) {
        if ( syscall_n == OPEN) {
          open_entering = 0;
          flags = regs.rsi;
          if (flags & O_DIRECTORY)
            found_directory = 1;
        } else if ( syscall_n == OPENAT) {
          open_entering = 0;
          flags = regs.rdx;
          if (flags & O_DIRECTORY)
            found_directory = 1;
        } 
      } else {
        open_entering = 1;
        if ( syscall_n == OPEN && found_directory)
          add_dirfd((int) regs.rax);
        if ( syscall_n == OPENAT && found_directory)
          add_dirfd((int) regs.rax);
        found_directory = 0;
      }
      
      if ( (syscall_idx = lfind(&syscall_n, target_syscalls, &n_syscalls_idx, sizeof(int), cmp_sys_num)) || entry_intercepted ) {
        if ( entering ) {
          // we only want to change the return value on syscall exit
          entering = 0;
          syscall_count++;
          
          if ( syscall_count > num_to_skip  && fail_on_entry && !(syscall_n == WRITE && regs.rdi < 3)) {
            if (!fail_only_dirs || is_dirfd(regs.rdi)) {
              ptrace( PTRACE_GETREGS, pid, 0, &regs );
              // set it to a dummy syscall getpid
  	          regs.orig_rax = 39;
              ptrace( PTRACE_SETREGS, pid, 0, &regs );
              entry_intercepted = 1;      
              intercepted_retval = retvals[syscall_idx - target_syscalls];
            }
          }
          
        }
        else {
          entering = 1;
          entry_intercepted = 0;
          if (syscall_count > num_to_skip && !(syscall_n == WRITE && regs.rdi < 3)) {
            if (!fail_only_dirs || is_dirfd(regs.rdi)) {
              ptrace( PTRACE_GETREGS, pid, 0, &regs );
              if ( fail_on_entry ) {
                regs.rax = intercepted_retval;
              } else {
                regs.rax = retvals[syscall_idx - target_syscalls];
              }
              // set the return value of the syscall
              ptrace( PTRACE_SETREGS, pid, 0, &regs );
            }
          }
        }
      }
    }
  }
  if (syscall_count <= num_to_skip) { // If num_to_skip was so high no faults were injected.
    return END_OF_EXECUTABLE; 
  }

  return 0;
}

/* Run injections progressing from faulting the first syscall, to the second, third, etc... until 
   the runs have faulted every syscall in the execution once. */
int full_injection_run(int* target_syscalls, int num_syscalls, long long int* retvals, 
		       int fail_on_entry, int follow_clones, int fail_only_dirs, char* target, char** args) {
  long long int current_skip = 0;
  
  int res = 0;
  while (res == 0) {
    res = single_injection_run(target_syscalls, num_syscalls, retvals, fail_on_entry, follow_clones, fail_only_dirs, current_skip, target, args);
    current_skip++;
  }
  return res;
}

/* Run injections progressing from faulting the first syscall to the second, third, etc... until
   either all syscall in the execution have been faulted or all syscalls up to the input num_ops have been 
   faulted, whichever comes first. */
int multi_injection_run(int* target_syscalls, int num_syscalls, long long int* retvals, 
			int fail_on_entry, int follow_clones, int fail_only_dirs, long long int num_ops, char* target, char** args) {
  for (long long int i = 0; i <= num_ops; i++) {
    int res = single_injection_run(target_syscalls, num_syscalls, retvals, fail_on_entry, follow_clones, fail_only_dirs, i, target, args);
    if (res) { //End if an error w.r.t the injector's end occurs or we reach past the end of the executable.
      return res;
    }
  }
  return 0;
}

/* Parses the comma-separated lists of target syscalls and return values. Returns 0 unless
*  something bad happened in the parsing. Note that this functiona allocates dynamic memory
*  to store the syscall numbers array and the return value arrays. */
int parse_target_syscall_args(int** target_syscalls, int* num_syscalls, long long int** retvals, char** argv) {
  int sys_buf[MAX_SYSCALLS];
  long long int ret_buf[MAX_SYSCALLS];
  *num_syscalls = 0;
  int num_retvals = 0;

  char* sys_args = argv[1];
  char* ret_args = argv[2];

  //Read in the syscall numbers.
  char* cur_sys = strtok(sys_args, INPUT_LIST_DELIM);
  while ((cur_sys != NULL) && (*num_syscalls < MAX_SYSCALLS)) {
    int ival = atoi(cur_sys);
    size_t n_syscall_idx = *num_syscalls;
    if (lfind(&ival, sys_buf, &n_syscall_idx, sizeof(int), cmp_sys_num)) {
      printf("Invalid target syscall list -- duplicate syscall numbers are not allowed\n");
      return 1;
    }
    sys_buf[*num_syscalls] = ival;
    (*num_syscalls)++;
    cur_sys = strtok(NULL, INPUT_LIST_DELIM);
  }

  //Read in the return values.
  char* cur_ret = strtok(ret_args, INPUT_LIST_DELIM);
  while ((cur_ret != NULL) && (num_retvals < *num_syscalls)) {
    int rval = atoi(cur_ret);
    ret_buf[num_retvals] = rval;
    num_retvals++; 
    cur_ret = strtok(NULL, INPUT_LIST_DELIM);
  }
  if ((num_retvals < *num_syscalls) || (cur_ret && (*cur_ret))) {
    printf("Invalid injected return value list -- number of values should match number of target syscalls\n");
    return 1;
  }

  //Allocate right-sized arrays and return.
  if (!(*target_syscalls = malloc(sizeof(int) * *num_syscalls))) {
    printf("Failed to allocate memory for syscall numbers\n");
    return 1;
  }
  if (!(*retvals = malloc(sizeof(long long int) * num_retvals))) {
    printf("Failed to allocate memory for injected return values\n");
    return 1;
  }
  memcpy(*target_syscalls, sys_buf, sizeof(int) * *num_syscalls);
  memcpy(*retvals, ret_buf, sizeof(long long int) * num_retvals);

  return 0;
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

  *target_args = malloc(sizeof(char*) * i);
  memcpy(*target_args, targ_buf, sizeof(char*) * i);

  return i;
}

/* Launch the program. */
int main(int argc, char *argv[]) {
  // Validate argc
  if((argc != MIN_ARGS) && (argc != MAX_ARGS)) {
    print_usage_and_exit();
  }

  // Validate target name
  char* target_inp;
  if (argc == MIN_ARGS) {
    target_inp = argv[6];
  } else {
    target_inp = argv[8];
  }
  if(strlen(target_inp) > MAX_TARGET_LEN) {
    printf("Target command cannot be longer than 1024.\n");
    return 1;
  }

  //Parse the targeted syscall numbers and values to inject.
  int* target_syscalls;
  int num_syscalls;
  long long int* retvals;
  if (parse_target_syscall_args(&target_syscalls, &num_syscalls, &retvals, argv)) {
    return 1;
  }

  int fail_on_entry = atoi(argv[3]);
  int follow_clones = atoi(argv[4]);
  int fail_only_dirs = atoi(argv[5]);

  int mode = FULL_RUN_MODE;
  long long int num_ops;

  // Determine the mode of operation and the number of skips/runs if applicable.
  if (argc == MAX_ARGS) {
    num_ops = atoll(argv[7]);
    if (!strcmp(argv[6], "-s")) {
      mode = SKIP_MODE;
    } else if (!strcmp(argv[6], "-r")) {
      mode = RUN_MODE;
    } else {
      print_usage_and_exit();
    }
  }

  // Create a buffer to store the target name.
  char* target;
  char** args;
  int nargs = parse_target_command(target_inp, &target, &args);
  
  int rval = 0;

  // Dispatch the runs.
  if (mode == FULL_RUN_MODE) {
    rval = full_injection_run(target_syscalls, num_syscalls, retvals, fail_on_entry, follow_clones, fail_only_dirs, target, args);
  } else if (mode == RUN_MODE) {
    rval = multi_injection_run(target_syscalls, num_syscalls, retvals, fail_on_entry, follow_clones, fail_only_dirs, num_ops, target, args);
  } else {
    rval = single_injection_run(target_syscalls, num_syscalls, retvals, fail_on_entry, follow_clones, fail_only_dirs, num_ops, target, args);
  }

  //Free dynamic memory used for syscall numbers and injected values.
  free(target_syscalls);
  free(retvals);
  free(target);
  for (int to_free = 0; to_free < nargs; to_free++) {
    free(args[to_free]);
  }
  free(args);

  // END_OF_EXECUTABLE is an internal signal, not an external one.
  if (rval == END_OF_EXECUTABLE) {
    return 0;
  }
  return rval;
}