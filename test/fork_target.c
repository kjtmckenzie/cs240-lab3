// target.c
#include <stdio.h>
#include <unistd.h>

int main() {
  printf( "Process id: %d\n", getpid() );
  printf( "(Initial) User id: %d\n", getuid() );
  
  //sleep(2);
  
  int parent = fork();
  
  if (parent) {
    // parent process
    printf( "(Child) Process id: %d\n", getpid() );
    printf( "(Child) User id: %d\n", getuid() );
    printf( "(Child) Group id: %d\n", getgid() );
    
  } else {
    // child process
    parent = fork();
    if (parent) {
      printf( "(GrandChild) Process id: %d\n", getpid() );
      printf( "(GrandChild) Group id: %d\n", getgid() );
    } else {
      printf( "(GreatGrandChild) Process id: %d\n", getpid() );
      printf( "(GreatGrandChild) Group id: %d\n", getgid() );
    }
  }
  return 0;
}