ENTRY(_entry32)

SECTIONS 
{
    . = 0x10000;

    .text :
    {
        *(.entry32)
        *(.text)
    }
    . = ALIGN(4096);

    .data :
    {
        *(.data)
        *(.rodata*)
        *(.bss)
    }
    . = ALIGN(4096);

    /DISCARD/ :
    {
        *(.eh_frame)
        *(.comment)
    }
}
