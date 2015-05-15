all:
	gcc target_sample.c -o target_sample
	gcc tracer_sample.c -o tracer_sample
	gcc -static malloc_target.c -o malloc_target
	gcc malloc_injector.c -o malloc_injector

clean:
	rm target_sample tracer_sample malloc_target malloc_injector
