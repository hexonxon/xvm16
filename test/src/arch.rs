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

struct InterruptGuard {
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
#[repr(C, packed)]
struct ExceptionFrame {
    eip: u32,
    _pad1: u16,
    cs: u16,
    eflags: u32,
    esp: u32,
    _pad2: u16,
    ss: u16,
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

pub fn set_interrupt_handler(vec: i8, handler: extern "C" fn() -> !) {
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

pub fn clear_interrupt_handler(vec: i8) {
    let iflag = InterruptGuard::default();

    unsafe {
        let desc: &mut IDTDescriptor = &mut IDT[vec as usize];
        desc.offset_low = 0;
        desc.offset_high = 0;
        desc.selector = 0;
        desc.attr = 0;
    }
}

/**
 * Register function as an exception handler:
 * exception_handler!(0x3, my_handler)
 */
macro_rules! exception_handler {
    ($vec:expr, $name:ident) => {{
        #[naked]
        extern "C" fn exception_handler() -> ! {
            unsafe {
                asm!("
                  push eax
                  push ecx
                  push edx

                  cmp  $1, 8
                  jb   .no_code
                  je   .has_code
                  cmp  $1, 10
                  jb   .no_code
                  cmp  $1, 15
                  jb   .has_code
                  cmp  $1, 17
                  je   .has_code
                  cmp  $1, 30
                  je   .has_code
                .no_code:
                  push  0
                .has_code:
                  push  [esp + 12]

                  push  esp + 16
                  push  $1
                  call  $0
                  add   esp, 122
                  pop  edx
                  pop  ecx
                  pop  eax
                  iret"
                  ::"i"($name as extern "C" fn(u8, *const ExceptionFrame, u32)), "i"($vec as u8) :: "intel");
                ::core::intrinsics::unreachable();
            }
        }
        set_interrupt_handler($vec, exception_handler)
    }}
}

/**
 * Register function as an interrupt vector handler:
 * interrupt_handler!(0x20, my_handler)
 */
macro_rules! interrupt_handler {
    ($vec:expr, $name:ident) => {{
        #[naked]
        extern "C" fn interrupt_handler() -> ! {
            unsafe {
                asm!("
                  push eax
                  push ecx
                  push edx
                  push $1
                  call $0
                  add  esp, 4
                  pop  edx
                  pop  ecx
                  pop  eax
                  iret"
                  :: "i"($name as extern "C" fn(u8)), "i"($vec as u8) :: "intel");
                ::core::intrinsics::unreachable();
            }
        }
        set_interrupt_handler($vec, interrupt_handler)
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
