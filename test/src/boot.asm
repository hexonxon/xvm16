;
;   Test kernel entry point
;   Segment descriptors set to flat 32-bit space loaded at 0x10000
;

%define BASE 0x10000
%define STACK_TOP (BASE - 1)

extern rust_main
global _entry32

;org 0x10000
section .entry32
use32

_entry32:
    ; Set our own GDT and IDT first so we can touch segment registers
    cli
    lgdt    [gdtr]
    lidt    [idtr]
    mov     ax, 0x10    
    mov     ds, ax
    mov     es, ax
    mov     ss, ax
    mov     esp, STACK_TOP
    push    0x0
    push    .L1
    retf

.L1:
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

