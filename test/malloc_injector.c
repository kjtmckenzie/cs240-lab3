#include <stdio.h>
#include <string.h>
#include <dlfcn.h>

#define STDOUT_LEN 4096

int main(int argc, char *argv[]) {
    printf("malloc_injector\n");

    // char nm_stdout[STDOUT_LEN];
    // memset (nm_stdout, 0, STDOUT_LEN);
    // FILE *f = popen("nm malloc_target", "r");
    // fscanf(f, "%4095c", nm_stdout);
    // printf("Read: \"%s\"\n", nm_stdout);
    // pclose(f);

    // ^^ Run "nm" from shell and read stdout, but dynamically symbols still undefined

    // void *handle = dlopen("malloc_target", RTLD_NOW);
    // if (!handle) {
    //     printf("handle was null\n");
    //     exit(1);
    // }

    // void *addr = dlsym(handle, "malloc");

    // printf("malloc @ %p", addr);
    // dlclose(handle);

    // ^^ messing around with dlopen, dlsym, but no success yet

    return 0;
}
