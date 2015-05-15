CFLAGS = -std=c99

all:
	gcc $(CFLAGS) target_sample.c -o target_sample
	gcc $(CFLAGS) tracer_sample.c -o tracer_sample
	gcc $(CFLAGS) -static malloc_target.c -o malloc_target
	gcc $(CFLAGS) malloc_injector.c -o malloc_injector

clean:
	rm target_sample tracer_sample malloc_target malloc_injector
