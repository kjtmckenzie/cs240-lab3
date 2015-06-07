CC = gcc

CFLAGS = -std=gnu99

INCLUDES = -Iinclude 

# Other C source files for injector
SRCS = src/injector.c src/state.c src/argparse.c src/utils.c src/breakfast.c src/backtrace.c

MAIN = injector

all: $(MAIN)
	$(CC) $(CFLAGS) test/getuid_target.c -o bin/getuid_target
	$(CC) $(CFLAGS) test/fork_target.c -o bin/fork_target
	# Require -static compilation so function addressses are known
	$(CC) $(CFLAGS) -static test/malloc_target.c -o bin/malloc_target 
	$(CC) $(CFLAGS) $(INCLUDES) src/utils.c src/breakfast.c test/malloc_tracer.c -o bin/malloc_tracer
	$(CC) $(CFLAGS) $(INCLUDES) src/backtrace.c test/backtrace_sample.c -o bin/backtrace_sample
	$(CC) $(CFLAGS) test/segfault_target.c -o bin/segfault_target

$(MAIN):
	$(CC) $(CFLAGS) $(INCLUDES) $(SRCS) -o bin/$(MAIN) 

clean:
	rm -rf bin/*
