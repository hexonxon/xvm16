;
;   Test kernel entry point
;   We start in real mode at 0h:8000h with no firmware
;

section .boot

extern rust_main
global _entry16

%define BASE 0x8000
%define STACK_TOP (BASE - 1)

use16
_entry16:
    ; Enter protected mode
    cli
    lgdt    [gdtr]
    lidt    [idtr]
    mov     eax, cr0
    or      eax, 1
    mov     cr0, eax
    jmp     0x08:_entry32

use32
_entry32:
    mov     ax, 0x10    
    mov     ds, ax
    mov     es, ax
    mov     ss, ax
    mov     esp, STACK_TOP
    call    rust_main   

.halt:
    jmp     $

gdtr:
    dw      (gdt_end - gdt_start) + 1
    dd      gdt_start

idtr:
    dw      0
    dd      0

gdt_start:
    dq      0                   ; Null
    dq      0x004f9a000000ffff  ; Code
    dq      0x004f92000000ffff  ; Data
gdt_end:

