#include <windows.h>

int main()
{
	unsigned char code[] = {
		0x48, 0x83, 0xec, 0x28, 0x48, 0x83, 0xe4, 0xf0, 0x48, 0x31, 0xc9, 0x65,
		0x48, 0x8b, 0x41, 0x60, 0x48, 0x8b, 0x40, 0x18, 0x48, 0x8b, 0x70, 0x20,
		0x48, 0xad, 0x48, 0x96, 0x48, 0xad, 0x4c, 0x8b, 0x78, 0x20, 0x4d, 0x31,
		0xc0, 0x45, 0x8b, 0x47, 0x3c, 0x4c, 0x89, 0xc2, 0x4c, 0x01, 0xfa, 0x44,
		0x8b, 0x82, 0x88, 0x00, 0x00, 0x00, 0x4d, 0x01, 0xf8, 0x48, 0x31, 0xf6,
		0x41, 0x8b, 0x70, 0x20, 0x4c, 0x01, 0xfe, 0x48, 0x31, 0xc9, 0x49, 0xb9,
		0x47, 0x65, 0x74, 0x50, 0x72, 0x6f, 0x63, 0x41, 0x48, 0xff, 0xc1, 0x48,
		0x31, 0xc0, 0x8b, 0x04, 0x8e, 0x4c, 0x01, 0xf8, 0x4c, 0x39, 0x08, 0x75,
		0xef, 0x48, 0x31, 0xf6, 0x41, 0x8b, 0x70, 0x24, 0x4c, 0x01, 0xfe, 0x66,
		0x8b, 0x0c, 0x4e, 0x48, 0x31, 0xf6, 0x41, 0x8b, 0x70, 0x1c, 0x4c, 0x01,
		0xfe, 0x48, 0x31, 0xd2, 0x8b, 0x14, 0x8e, 0x4c, 0x01, 0xfa, 0x49, 0x89,
		0xd6, 0x48, 0x31, 0xc9, 0xb9, 0x61, 0x72, 0x79, 0x41, 0x51, 0x48, 0xb9,
		0x4c, 0x6f, 0x61, 0x64, 0x4c, 0x69, 0x62, 0x72, 0x51, 0x48, 0x89, 0xe2,
		0x4c, 0x89, 0xf9, 0x48, 0x83, 0xec, 0x30, 0x41, 0xff, 0xd6, 0x48, 0x83,
		0xc4, 0x30, 0x48, 0x83, 0xc4, 0x10, 0x49, 0x89, 0xc5, 0x48, 0x31, 0xc9,
		0xb9, 0x6c, 0x6c, 0x00, 0x00, 0x51, 0x48, 0xb9, 0x75, 0x73, 0x65, 0x72,
		0x33, 0x32, 0x2e, 0x64, 0x51, 0x48, 0x89, 0xe1, 0x48, 0x83, 0xec, 0x30,
		0x41, 0xff, 0xd5, 0x48, 0x83, 0xc4, 0x30, 0x48, 0x83, 0xc4, 0x10, 0x49,
		0x89, 0xc4, 0x48, 0x31, 0xc9, 0xb9, 0x6f, 0x78, 0x41, 0x00, 0x51, 0x48,
		0xb9, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x42, 0x51, 0x48, 0x89,
		0xe2, 0x4c, 0x89, 0xe1, 0x48, 0x83, 0xec, 0x30, 0x41, 0xff, 0xd6, 0x48,
		0x83, 0xc4, 0x30, 0x48, 0x83, 0xc4, 0x10, 0x48, 0x89, 0xc6, 0x4d, 0x31,
		0xc9, 0x49, 0x83, 0xc1, 0x01, 0x48, 0x31, 0xc9, 0x48, 0xb9, 0x54, 0x69,
		0x74, 0x6c, 0x65, 0x00, 0x00, 0x00, 0x51, 0x49, 0x89, 0xe0, 0x48, 0x31,
		0xc9, 0x51, 0xb9, 0x72, 0x6c, 0x64, 0x21, 0x51, 0x48, 0xb9, 0x48, 0x65,
		0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x51, 0x48, 0x89, 0xe2, 0x48, 0x31,
		0xc9, 0x48, 0x83, 0xec, 0x30, 0xff, 0xd6, 0x48, 0x83, 0xc4, 0x30, 0x48,
		0x83, 0xc4, 0x20, 0x48, 0x31, 0xc9, 0xb9, 0x65, 0x73, 0x73, 0x00, 0x51,
		0x48, 0xb9, 0x45, 0x78, 0x69, 0x74, 0x50, 0x72, 0x6f, 0x63, 0x51, 0x48,
		0x89, 0xe2, 0x4c, 0x89, 0xf9, 0x48, 0x83, 0xec, 0x30, 0x41, 0xff, 0xd6,
		0x48, 0x83, 0xc4, 0x30, 0x48, 0x83, 0xc4, 0x10, 0x48, 0x89, 0xc6, 0x48,
		0x31, 0xc9, 0xff, 0xd6
	};
	unsigned int code_len = 376;
	void *shellcode = VirtualAlloc(0, code_len, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	memcpy(shellcode, code, code_len);

	((void(*)())shellcode)();

	VirtualFree(shellcode, 0, MEM_RELEASE);

	return 0;
}
