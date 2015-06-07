CC = gcc

CFLAGS = -std=gnu99 -static

INCLUDES = -Iinclude 

# Other C source files for injector
SRCS = src/injector.c src/state.c src/argparse.c src/addr_utils.c src/breakfast.c

MAIN = injector

all: $(MAIN)
	$(CC) $(CFLAGS) test/getuid_target.c -o bin/getuid_target
	$(CC) $(CFLAGS) test/fork_target.c -o bin/fork_target
	$(CC) $(CFLAGS) test/malloc_target.c -o bin/malloc_target

	$(CC) $(CFLAGS) $(INCLUDES) src/addr_utils.c src/breakfast.c test/malloc_tracer.c -o bin/malloc_tracer

$(MAIN):
	$(CC) $(CFLAGS) $(INCLUDES) $(SRCS) -o bin/$(MAIN) 

clean:
	rm -rf bin/*
