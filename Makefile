CC = gcc

CFLAGS = -std=gnu99

INCLUDES = -Iinclude

# Other C source files for injector
SRCS = src/injector.c src/breakfast.c src/argparse.c src/addr_utils.c

MAIN = injector

all: $(MAIN)
	$(CC) $(CFLAGS) test/getuid_target.c -o bin/getuid_target
	$(CC) $(CFLAGS) test/tracer_sample.c -o bin/tracer_sample
	$(CC) $(CFLAGS) -static test/malloc_target.c -o bin/malloc_target
	$(CC) $(CFLAGS) test/malloc_tracer.c -o bin/malloc_tracer

$(MAIN):
	$(CC) $(CFLAGS) $(INCLUDES) $(SRCS) -o bin/$(MAIN) 

clean:
	rm -rf bin/*
