# Shellcoding

This repository contains basic assembly shellcode examples for both linux and windows on x64 arch.

## Linux

The linux example shows how to make a simple `execve()` syscall on `/bin/sh` executable.

```
nasm -f elf64 linux_x64/spawnshell.asm -o spawnshell.o
python3 parsers/shellcode_from_asm_object.py -i linux_x64/spawnshell.o -o cstyle
# copy the output to the linux_x64/lin_loader.c
gcc linux_x64/lin_loader.c -o linux_x64/spawnshell
```

If you want to directly compile the object and not use the shellcode inside a loader use the following command:

`ld linux_x64/spawnshell.o -o linux_x64/spawnshell`

## Windows

The windows example shows how to make a simple message box by finding the address of kernel32.dll and GetProcAddress function inside the dll export table, then using GetProcAddress to get the address of LoadLibraryA function to load the user32.dll and using again GetProcAddress to get the address of MessageBoxA.

```
nasm -f win64 windows_x64/messagebox.asm -o messagebox.obj
python3 parsers/shellcode_from_asm_object.py -i windows_x64/messagebox.obj -o cstyle
# copy the output to the windows_x64/win_loader.c
x86_64-w64-mingw32-gcc windows_x64/win_loader.c -o windows_x64/messagebox.exe
```

If you want to directly compile the object and not use the shellcode inside a loader use the following command inside a VS Native Console:

`link /ENTRY:main /MACHINE:X64 /NODEFAULTLIB /SUBSYSTEM:WINDOWS messagebox.obj`
