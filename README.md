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
machine is to create a Vagrant VM using the Vagrantfile located in this repo.
(N.B. that Vagrant requires additionally requires VirtualBox to work!)
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

#### Usage

TODO

#### Known Issues & Limitations

TODO