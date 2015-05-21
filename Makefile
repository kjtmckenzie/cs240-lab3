CFLAGS = -std=c99

all: 
	# for the test files
	gcc $(CFLAGS) test/target_sample.c -o bin/target_sample
	gcc $(CFLAGS) test/tracer_sample.c -o bin/tracer_sample
	gcc $(CFLAGS) -static test/malloc_target.c -o bin/malloc_target
	gcc $(CFLAGS) test/malloc_injector.c -o bin/malloc_injector

	# for breakfast file
	gcc -Iinclude src/injector.c src/breakfast.c -o bin/injector

clean:
	rm -rf bin/target_sample bin/tracer_sample bin/malloc_target bin/malloc_injector
