// target.c
#include <stdio.h>
#include <unistd.h>
#include <ftw.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <inttypes.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>

int main() {
  char *directory = "test_dir";
  
  

  struct stat dir = {0};
  if(stat(directory, &dir) == -1)
  {
      mkdir(directory, 0755);
      printf("*** created directory test_dir successfully! \n");
      fflush(stdout);
  }
  
  DIR *dir_ptr = opendir(directory);
  printf("*** Successfully opened directory test_dir\n");
  fflush(stdout);
  
  int dir_fd = dirfd(dir_ptr);
  printf("*** Received dir_fd = %d\n", dir_fd);
  fflush(stdout);
  
  char *directory2 = "test_dir2";

  struct stat dir2 = {0};
  if(stat(directory2, &dir2) == -1)
  {
      mkdir(directory2, 0755);
      printf("*** created directory test_dir2 successfully! \n");
      fflush(stdout);
  }
  
  DIR *dir_ptr2 = opendir(directory2);
  printf("*** Successfully opened directory test_dir2\n");
  fflush(stdout);

  int dir_fd2 = dirfd(dir_ptr2);
  printf("*** Received dir_fd = %d\n", dir_fd2);
  fflush(stdout);
  
  
  
  int dir_synched = fsync(dir_fd);
  if (dir_synched < 0) {
    printf("\e[1;31m*** Error while saving directory initially: %d\n\e[0m", errno);
    fflush(stdout);
  } else {
    printf("*** Successfully saved directory initially\n");
    fflush(stdout);
  }
  
  int dir_synched2 = fsync(dir_fd2);
  if (dir_synched2 < 0) {
    printf("\e[1;31m*** Error while saving directory test_dir2 initially: %d\n\e[0m", errno);
    fflush(stdout);
  } else {
    printf("*** Successfully saved directory test_dir2 initially\n");
    fflush(stdout);
  }
  
  
  char path[256];
  sprintf(path, "%s/test_file.txt", directory);
  printf("Path is %s\n", path);
  int fd = open(path, O_RDWR | O_APPEND | O_CREAT);
  
  if (fd < 0) {
    printf("\e[1;31m*** Error creating test_file file, %d\n\e[0m", errno);
    fflush(stdout);
    exit(-1);
  } else {
    printf("*** Created test_file file successfuly\n");
    fflush(stdout);
  }
  
  char *test_string = "Hello, world!\n";
  
  ssize_t bytes = write(fd, test_string, strlen(test_string) + 1);
  if (bytes < 0) {
    printf("\e[1;31m*** Error writing to test_file file\n\e[0m");
    fflush(stdout);
  } else {
    printf("*** Successfully wrote %d bytes to the file\n", (int) bytes);
    fflush(stdout);
  }
  
  int synched = fsync(fd);
  if (synched < 0) {
    printf("\e[1;31m*** Error while saving file to disk after write: %d\n\e[0m", errno);
    fflush(stdout);
  } else {
    printf("*** Successfully saved file to disk after write\n");
    fflush(stdout);
  }
  
  dir_synched = fsync(dir_fd);
  if (dir_synched < 0) {
    printf("\e[1;31m*** Error while saving directory to disk after write: %d\n\e[0m", errno);
    fflush(stdout);
  } else {
    printf("*** Successfully saved directory to disk after write\n");
    fflush(stdout);
  }
  
  char read_string[255];
  lseek(fd, 0, SEEK_SET);
  bytes = read(fd, &read_string, strlen(test_string) + 1);
  if (bytes < 1) {
    printf("\e[1;31m*** Error reading from test_file file.  Bytes retval: %d\n\e[0m", (int) bytes);
    fflush(stdout);
  } else {
    printf("*** Successfully read %d bytes: %s", (int) bytes, read_string);
    fflush(stdout);
  }
  
  synched = fsync(fd);
  if (synched < 0) {
    printf("\e[1;31m*** Error while saving file to disk after read: %d\n\e[0m", errno);
    fflush(stdout);
  } else {
    printf("*** Successfully saved file to disk after read\n");
    fflush(stdout);
  }
  
  dir_synched = fsync(dir_fd);
  if (dir_synched < 0) {
    printf("\e[1;31m*** Error while saving directory to disk after read: %d\n\e[0m", errno);
    fflush(stdout);
  } else {
    printf("*** Successfully saved directory to disk after read\n");
    fflush(stdout);
  }
  
  int removed = remove(path);
  if (removed < 0) {
    printf("\e[1;31m*** Error while removing file test_file\n\e[0m");
    fflush(stdout);
  } else {
    printf("*** Successfully removed file test_file\n");
    fflush(stdout);
  }
  
  removed = remove(directory);
  if (removed < 0) {
    printf("\e[1;31m*** Error while removing directory test_dir\n\e[0m");
    fflush(stdout);
  } else {
    printf("*** Successfully removed directory test_dir\n");
    fflush(stdout);
  }
  
  synched = fsync(fd);
  if (synched < 0) {
    printf("\e[1;31m*** Error while saving file deletion to disk: %d\n\e[0m", errno);
    fflush(stdout);
  } else {
    printf("*** Successfully saved file deletion to disk\n");
    fflush(stdout);
  }
  
  dir_synched = fsync(dir_fd);
  if (dir_synched < 0) {
    printf("\e[1;31m*** Error while saving directory deletion to disk: %d\n\e[0m", errno);
    fflush(stdout);
  } else {
    printf("*** Successfully saved directory deletion to disk\n");
    fflush(stdout);
  }
  
}