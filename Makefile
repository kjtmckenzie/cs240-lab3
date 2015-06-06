CC = gcc

CFLAGS = -std=gnu99

INCLUDES = -Iinclude

# Other C source files for injector
SRCS = src/backtrace.c src/injector.c src/state.c src/argparse.c src/addr_utils.c

MAIN = injector

all: $(MAIN)
	$(CC) $(CFLAGS) -static test/getuid_target.c -o bin/getuid_target
	$(CC) $(CFLAGS) -static test/fork_target.c -o bin/fork_target
	$(CC) $(CFLAGS) -static test/malloc_target.c -o bin/malloc_target 
	$(CC) $(CFLAGS) $(INCLUDES) src/backtrace.c src/test_parent.c -o bin/test_parent
	$(CC) $(CFLAGS) -static src/test_child.c -o bin/test_child
	$(CC) $(CFLAGS) $(INCLUDES) src/addr_utils.c src/breakfast.c test/malloc_tracer.c -o bin/malloc_tracer

$(MAIN):
	$(CC) $(CFLAGS) $(INCLUDES) $(SRCS) -o bin/$(MAIN) 

clean:
	rm -rf bin/*
