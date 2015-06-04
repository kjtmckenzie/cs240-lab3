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
#include "../include/argparse.h"

#define READ 0
#define WRITE 1
#define OPEN 2
#define CLOSE 3
#define FSYNC 74
#define MKDIR 83
#define OPENAT 257

//A return value indicating we reached past the end of executable. Chosen larger than 256 so that it 
//won't clash with most POSIX exit codes.
#define END_OF_EXECUTABLE 400

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

/* Launch the program. */
int main(int argc, char *argv[]) {
  args_t* args = argparse_parse(argc, argv);
  if (args == NULL) {
    return -1;
  }

  int rval = 0;

  // Dispatch the runs.
  if (args->mode == run_all) {
    rval = full_injection_run(args->syscall_nos, args->n_syscalls, args->syscall_retvals, 
			      args->fail_on_entry, args->follow_clones, 
			      args->fail_only_dirs, args->target_argv[0], 
			      args->target_argv);
  } else if (args->mode == run_n) {
    rval = multi_injection_run(args->syscall_nos, args->n_syscalls, args->syscall_retvals, 
			       args->fail_on_entry, args->follow_clones, 
			       args->fail_only_dirs, args->num_ops, args->target_argv[0], 
			       args->target_argv);
  } else {
    rval = single_injection_run(args->syscall_nos, args->n_syscalls, args->syscall_retvals, 
				args->fail_on_entry, args->follow_clones, 
				args->fail_only_dirs, args->num_ops, args->target_argv[0],
				args->target_argv);
  }

  //Free dynamic memory used for syscall numbers and injected values.
  argparse_destroy(args);

  // END_OF_EXECUTABLE is an internal signal, not an external one.
  if (rval == END_OF_EXECUTABLE) {
    return 0;
  }
  return rval;
}
