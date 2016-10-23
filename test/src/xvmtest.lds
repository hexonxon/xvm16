ENTRY(_entry16)

SECTIONS 
{
    . = 0x8000;

    .text :
    {
        *(.boot)
        *(.text*)
    }
    . = ALIGN(4096);

    .data :
    {
        *(.data*)
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
