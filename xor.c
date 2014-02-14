#include <string.h>
#include "xor.h"

void x(char *p) {
	int i, key=0xFE;
	for(i = 0; i < strlen(p); i++)
		p[i] ^= key;
}
