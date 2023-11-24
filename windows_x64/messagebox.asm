BITS 64

SECTION .text
global main

main:

sub rsp, 0x28                   ; 40 bytes of shadow space
and rsp, 0xfffffffffffffff0     ; Align the stack to a multiple of 16 bytes

; Parse PEB and find kernel32

xor rcx, rcx                    ; RCX = 0
mov rax, [gs:rcx + 0x60]        ; RAX = PEB
mov rax, [rax + 0x18]           ; RAX = PEB->Ldr
mov rsi, [rax + 0x20]           ; RSI = PEB->Ldr.InMemOrder
lodsq                           ; RAX = Second module
xchg rax, rsi                   ; RAX = RSI, RSI = RAX
lodsq                           ; RAX = Third(kernel32)
mov r15, [rax + 0x20]           ; R15 = Base address of kernel32

; Parse kernel32 PE

xor r8, r8                      ; Clear r8
mov r8d, [r15 + 0x3c]           ; R8D = DOS->e_lfanew offset
mov rdx, r8                     ; RDX = DOS->e_lfanew
add rdx, r15                    ; RDX = PE Header
mov r8d, [rdx + 0x88]           ; R8D = Offset export table
add r8, r15                     ; R8 = Export table
xor rsi, rsi                    ; Clear RSI
mov esi, [r8 + 0x20]            ; RSI = Offset namestable
add rsi, r15                    ; RSI = Names table
xor rcx, rcx                    ; RCX = 0
mov r9, 0x41636f7250746547      ; GetProcA

; Loop through exported functions and find GetProcAddress

Get_Function:
inc rcx                         ; Increment the ordinal
xor rax, rax                    ; RAX = 0
mov eax, [rsi + rcx * 4]        ; Get name offset
add rax, r15                    ; Get function name
cmp QWORD [rax], r9             ; GetProcA ?
jnz Get_Function
xor rsi, rsi                    ; RSI = 0
mov esi, [r8 + 0x24]            ; ESI = Offset ordinals
add rsi, r15                    ; RSI = Ordinals table
mov cx, [rsi + rcx * 2]         ; Number of function
xor rsi, rsi                    ; RSI = 0
mov esi, [r8 + 0x1c]            ; Offset address table
add rsi, r15                    ; ESI = Address table
xor rdx, rdx                    ; RDX = 0
mov edx, [rsi + rcx * 4]        ; EDX = Pointer(offset)
add rdx, r15                    ; RDX = GetProcAddress
mov r14, rdx                    ; Save GetProcAddress in R14

; Call GetProcAddress(kernel32.dll, "LoadLibraryA")

xor rcx, rcx
mov rcx, 0x41797261             ; aryA
push rcx                        ; Push on the stack
mov rcx, 0x7262694c64616f4c     ; LoadLibr
push rcx                        ; Push on stack
mov rdx, rsp                    ; Second argument rdx = "LoadLibraryA"
mov rcx, r15                    ; First argument rcx = kernel32.dll base address
sub rsp, 0x30                   ; Allocate stack space for function call
call r14                        ; Call GetProcAddress
add rsp, 0x30                   ; Cleanup allocated stack space
add rsp, 0x10                   ; Clean space for LoadLibrary string
mov r13, rax                    ; LoadLibraryA saved in R13

; Call LoadLibrary("user32.dll")

xor rcx, rcx
mov rcx, 0x6c6c                 ; ll
push rcx                        ; Push on the stack
mov rcx, 0x642e323372657375     ; user32.d
push rcx                        ; Push on stack
mov rcx, rsp                    ; First argument rcx = user32.dll
sub rsp, 0x30                   ; Allocate stack space for function call
call r13                        ; Call LoadLibraryA
add rsp, 0x30                   ; Cleanup allocated stack space
add rsp, 0x10                   ; Clean space for user32.dll string
mov r12, rax                    ; Base address of user32.dll in R12

; Call GetProcAddress(user32.dll, "MessageBoxA")

xor rcx, rcx
mov rcx, 0x41786f               ; oxA
push rcx                        ; Push on the stack
mov rcx, 0x426567617373654d     ; MessageB
push rcx                        ; Push on stack
mov rdx, rsp                    ; Second argument rdx = "MessageBoxA"
mov rcx, r12                    ; First argument rcx = User32.dll base address
sub rsp, 0x30                   ; Allocate stack space for function call
call r14                        ; Call GetProcAddress
add rsp, 0x30                   ; Cleanup allocated stack space
add rsp, 0x10                   ; Clean space for MessageBoxA string
mov rsi, rax                    ; Save MessageBoxA in rsi

; Call MessageBoxA(0,"Hello World!","Title",1)

xor r9, r9
add r9, 0x01                    ; Fourth argument r9 = 1
xor rcx, rcx
mov rcx, 0x656c746954           ; Title
push rcx
mov r8, rsp                     ; Third argument r8 = "Title
xor rcx, rcx
push rcx                        ; Add NULL delimiter on stack
mov rcx, 0x21646c72             ; rld!
push rcx
mov rcx, 0x6f57206f6c6c6548     ; Hello Wo
push rcx
mov rdx, rsp                    ; Second argument rdx = "Hello World!"
xor rcx, rcx                    ; First argument rcx = 0
sub rsp, 0x30
call rsi
add rsp, 0x30
add rsp, 0x20

; Call GetProcAddress(kernel32.dll, "ExitProcess")

xor rcx, rcx
mov rcx, 0x737365               ; ess
push rcx                        ; Push on the stack
mov rcx, 0x636f725074697845     ; ExitProc
push rcx                        ; Push on stack
mov rdx, rsp                    ; Second argument rdx = "ExitProcess"
mov rcx, r15                    ; First argument rcx = Kernel32.dll base address
sub rsp, 0x30                   ; Allocate stack space for function call
call r14                        ; Call GetProcAddress
add rsp, 0x30                   ; Cleanup allocated stack space
add rsp, 0x10                   ; Clean space for ExitProcess string
mov rsi, rax                    ; Save ExitProcess in rsi

; Call ExitProcess(0)

xor rcx, rcx                    ; Exit code 0
call rsi                        ; Call ExitProcess
