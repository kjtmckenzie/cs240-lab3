# PTRACE Fault Injector

#### Team Members:
Patrick Harvey, Do Kwon, Sunkyu Lim, Kevin McKenzie, Ian Walsh

___

This is a tool that uses the Linux `ptrace` system call to automatically
inject faults into a target program. It takes as input an arbitrary list of
system call numbers or library function names and the path of a target binary
to run. It runs the target, failing the appropriate calls and changing their
return values to ones of our choosing. We have used this tool to systematically
look for bugs caused by incorrect error handling in common programs, including
vim, Firefox, and the Python interpreter.

#### Prerequisites
A Linux machine that supports `ptrace`. That's it! One way to get such a 
machine is to create a Vagrant VM using the Vagrantfile located in this repo 
(n.b. that Vagrant additionally requires VirtualBox to work!)
After cloning:

    $ cd lab3/
    $ vagrant init
    $ vagrant up
    $ vagrant ssh
    $ cd lab3/

Stock Ubuntu (14.04) should also work.

#### Setup

Once you have a `ptrace`-capable machine, setup is straightforward:

    $ git clone https://github.com/kjtmckenzie/cs240-lab3.git lab3
    $ cd lab3
    $ make clean && make

#### Examples

Run the injector on `test/getuid_target.c`, faulting the `getuid()` syscall to return -1:

    $ ./bin/injector 102 -1 -1 0 1 0 0 0 skip 0 'bin/getuid_target'

Run the injector on `test/malloc_target.c`, faulting `malloc()` to return `NULL`:

    $ ./bin/injector -1 -1 malloc 0 1 0 0 1 skip 0 'bin/malloc_target'

Demonstrate backtrace functionality:

    $ bin/backtrace_sample bin/segfault_target

#### Usage

The syntax for running the injector is:

`$ bin/injector syscalls sys_retvals functions fn_retvals fail_on_entry follow_clones only_dirs after_main run_mode num target`

Here is the meaning of each argument:

1. **syscalls, sys_retvals:** comma-separated lists of syscall #s and integer
return values to inject. If **syscalls** is `-1`, no syscalls will be faulted.
For example, to fault `mmap` and `brk` (commonly used to implement dynamic
 memory allocation), the command would begin

    `$ bin/injector 9,12 0,0 ...`

2. **functions, fn_retvals:** comma-separated lists of function names and
integer return values to inject. If **functions** is `-1`, no functions will
be faulted.

3. **fail_on_entry:** 1 to fail the call on entry, before any side effects occur,
or 0 to allow the function to complete and only modify the return value

4. **follow_clones:** 1 if the injector should follow `clone()`d and `fork()`d
child processes, or 0 if it should keep tracing the parent.

5. **only_dirs:** When faulting file system syscalls (`read()`, `write()`), 1
if only calls to directories should be faulted, or 0 to fault all such calls.

6. **after_main:** 1 if fault injection should only begin after control reaches
 `main()` in the target, or 0 to begin faulting immediately

7. **run_mode, num:** **run_mode** is one of `skip`, `run`, and `full`, and **num** 
is an integer.
  - In `skip` mode, the first **num** calls are skipped before injection begins
  - In `run` mode, the injector runs **num* times. Run _i_ skips the first _i_
calls before injection.
  - In `full` mode, the injector runs repeatedly in `skip` mode, incrementing **num**
each iteration until it is so high that no calls are faulted.

8. **target:** The path to the target binary, and any command line arguments, 
as a single strip. Ex: `'/usr/bin/myProgram arg1 arg2'`

#### Known Issues & Limitations

1. The injector can only fault syscalls or functions in a single run, not both 
simultaneously. This is simply a limitation of our implementation, not a 
fundamental property of `ptrace`, and could be addressed with modifications to 
the main tracing loop in `injector.c`.

2. Invocation is clunky (as you may have noticed). A nicer interface would use 
sensible defaults and optional flags to specify arguments in arbitrary order. 
This would require modifications to `argparse.c`.

3. When injecting functions, the target binary must have been compiled with the 
`-static` option, so that function addresses are resolved at compile-time. This 
is needed because of how we fault functions: we insert breakpoints at every 
call site in the target, then jump over the call and fake the return value. To 
locate the call sites, we use `nm` and `objdump` on the binary file, and this 
only works if the addresses have already been resolved.

4. Similarly, the target must have been compiled with a symbol table and frame 
pointer (`%rbp`) present. These are required by the backtrace utility.

5. Breakpoints are not fully integrated with the injector state struct. There
are `TODO` comments about including a linked-list of `breakpoint_t`s in the 
`state_t` struct. Also, the breakpoint interface in `breakfast.h` could be 
improved (`breakfast_run` is particularly mystifying).

6. Handling of tracee hangs and infinite loops could be improved. `waitpid()`
doesn't have any notion of a timeout, so if the tracee gets into a nonresponsive 
state, the whole injector will hang. Techniques exist for getting timeout-like 
functionality from `waitpid()`; we could use some of them in the main tracer 
loop in `injector.c`.

7. The 'skip N' behavior hasn't been plumbed through to function injection, 
only to syscalls. This should be trivial to extend.
