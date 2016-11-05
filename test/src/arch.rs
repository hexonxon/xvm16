/*
 * Architecture specific stuff.
 * For now arch is assumed to be x86_32
 */

use dbgprint;

const X86_EFLAGS_IF_BIT: usize = 9;
const X86_EFLAGS_IF: u32 = (1u32 << X86_EFLAGS_IF_BIT);

pub fn read_eflags() -> u32 {
    let mut eflags: u32 = 0;
    unsafe {
        asm!("pushf");
        asm!("pop %eax" : "={eax}"(eflags));
    }

    return eflags;
}

/* Interrupts */

pub fn interrupts_enabled() -> bool {
    (read_eflags() & X86_EFLAGS_IF) != 0
}

pub fn interrupts_enable() {
    unsafe { asm!("sti"); }
}

pub fn interrupts_disable() -> bool {
    let iflag = interrupts_enabled();
    unsafe { asm!("cli"); }
    return iflag;
}

pub fn interrupts_enable_if(iflag: bool) {
    if iflag {
        interrupts_enable();
    }
}

pub struct InterruptGuard {
    iflag: bool,
}

impl Default for InterruptGuard {
    fn default() -> InterruptGuard {
        InterruptGuard {
            iflag: interrupts_disable(),
        }
    }
}

impl Drop for InterruptGuard {
    fn drop(&mut self) {
        interrupts_enable_if(self.iflag);
    }
}

/* IDT */

#[derive(Default, Copy, Clone)]
#[repr(C, packed)]
struct IDTR {
    limit: u16,
    base: u32,
}

#[derive(Default, Copy, Clone)]
#[repr(C, packed)]
struct IDTDescriptor {
    offset_low: u16,
    selector: u16,
    _unused: u8,
    attr: u8,
    offset_high: u16,
}

#[derive(Default, Copy, Clone)]
#[repr(C)]
pub struct ExceptionFrame {
    pub eip: u32,
    pub cs: u16, // Relying on natural alignment here to pad this field to 32 bits
    pub eflags: u32,
}

/* That's our global IDT */
static mut IDT: [IDTDescriptor; 256] = [IDTDescriptor {
    offset_low: 0,
    selector: 0,
    _unused: 0,
    attr: 0,
    offset_high: 0
}; 256];


fn get_code_selector() -> u16 {
    let mut cs_val: u16 = 0;
    unsafe {
        asm!("mov ax, cs" :"={ax}"(cs_val):::"intel", "volatile");
    }

    cs_val & !0x7 // Clear CPL and TI bits if any
}

pub fn set_idt_entry(vec: u8, handler: extern "C" fn() -> !) {
    let iflag = InterruptGuard::default();
    let addr: u32 = handler as u32;

    unsafe {
        let desc: &mut IDTDescriptor = &mut IDT[vec as usize];
        desc.offset_low = addr as u16;
        desc.offset_high = (addr >> 16) as u16;
        desc.selector = get_code_selector();
        desc.attr = 0x8E; // 32-bit interrupt gate present
    }
}

pub fn clear_idt_entry(vec: i8) {
    let iflag = InterruptGuard::default();

    unsafe {
        let desc: &mut IDTDescriptor = &mut IDT[vec as usize];
        desc.offset_low = 0;
        desc.offset_high = 0;
        desc.selector = 0;
        desc.attr = 0;
    }
}

pub type InterruptHandlerFn = extern "C" fn(u8);
pub type ExceptionHandlerFn = extern "C" fn(*mut ExceptionFrame);
pub type ExceptionHandlerWithErrorFn = extern "C" fn(*mut ExceptionFrame, u32);

/**
 * Register function as an exception handler that does not accept an error code:
 * handler should be typed as ExceptionHandlerFn
 * exception_handler!(0x3, my_handler)
 */
macro_rules! exception_handler {
    ($vec:expr, $handler:ident) => {{
        #[naked] extern "C" fn _exception_wrapper() -> ! {
            unsafe {
                asm!("push  eax
                      push  ecx
                      push  edx

                      // On IA32 interrupt frame is not guaranteed to be aligned
                      // Save current stack pointer and align ESP to 16 bytes
                      push  ebp
                      mov   ebp, esp
                      lea   eax, [ebp + 16]
                      push  eax // Exception frame pointer argument
                      and   esp, 0xFFFFFFF0

                      call  $0
                      mov   esp, ebp
                      pop   ebp
                      pop   edx
                      pop   ecx
                      pop   eax
                      iret"
                      ::"X"($handler as arch::ExceptionHandlerFn)::"intel","volatile");
                ::core::intrinsics::unreachable();
            }
        }
        set_idt_entry($vec, _exception_wrapper);
    }}
}

/**
 * Register function as an exception handler that accepts an error code:
 * handler should be typed as ExceptionHandlerWithErrorFn
 * exception_handler_with_error!(0x3, my_handler)
 */
macro_rules! exception_handler_with_error {
    ($vec:expr, $handler:ident) => {{
        #[naked] extern "C" fn _exception_wrapper_with_error() -> ! {
            unsafe {
                asm!("push  eax
                      push  ecx
                      push  edx

                      // On IA32 interrupt frame is not guaranteed to be aligned
                      // Save current stack pointer and align ESP to 16 bytes
                      push  ebp
                      mov   ebp, esp
                      push  [ebp + 16] // Error code argument
                      lea   eax, [ebp + 20]
                      push  eax // Exception frame pointer argument
                      and   esp, 0xFFFFFFF0

                      call  $0
                      mov   esp, ebp
                      pop   ebp
                      pop   edx
                      pop   ecx
                      pop   eax

                      // IA32 exception handling requires error code to be removed from stack
                      // before iret
                      add   esp, 4
                      iret"
                      ::"X"($handler as arch::ExceptionHandlerWithErrorFn)::"intel","volatile");
                ::core::intrinsics::unreachable();
            }
        }
        set_idt_entry($vec, _exception_wrapper_with_error);
    }}
}

/**
 * Register function as an interrupt vector handler:
 * interrupt_handler!(0x20, my_handler)
 */
macro_rules! interrupt_handler {
    ($vec:expr, $handler:ident) => {{
        #[naked] extern "C" fn _interrupt_wrapper() -> ! {
            unsafe {
                asm!("push  eax
                      push  ecx
                      push  edx

                      // On IA32 interrupt frame is not guaranteed to be aligned
                      // Save current stack pointer and align ESP to 16 bytes
                      push  ebp
                      mov   ebp, esp
                      and   esp, 0xFFFFFFF0

                      call  $0
                      mov   esp, ebp
                      pop   ebp
                      pop   edx
                      pop   ecx
                      pop   eax
                      iret"
                      ::"X"($handler as arch::InterruptHandlerFn)::"intel", "volatile");
                ::core::intrinsics::unreachable();
            }
        }
        set_idt_entry($vec, _interrupt_wrapper)
    }}
}

/*
 * Arch initialization.
 * GDT is already set to flat 32-bit, which is perfectly fine,
 * so we need to initialize IDT only.
 */
#[no_mangle]
pub fn arch_init() {
    unsafe {
        let idtr: IDTR = IDTR {
            limit: 256,
            base: IDT.as_ptr() as u32,
        };

        asm!("lidt [$0]" ::"X"(&idtr as *const IDTR)::"intel", "volatile");
    }
}
