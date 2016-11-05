#![allow(non_snake_case)] 
#![allow(non_camel_case_types)]

#[macro_use] extern crate lazy_static;
#[macro_use] extern crate log;
extern crate rlibc;
extern crate num;
extern crate core;
extern crate time;
extern crate capstone;
extern crate hypervisor_framework;

mod util;
mod qemudbg;
mod miscdev;
mod cmos;
mod pit;
mod vm;
mod pci;
mod pic;

use hypervisor_framework::*;
use rlibc::*;
use std::sync::Arc;
use std::fs::*;
use std::io::Read;
use std::env;
use log::*;
use num::traits::*;

struct SimpleLogger;

impl log::Log for SimpleLogger {
    fn enabled(&self, metadata: &LogMetadata) -> bool {
        metadata.level() <= LogLevel::Debug
    }

    fn log(&self, record: &LogRecord) {
        if self.enabled(record.metadata()) {
            println!("[{}] {}", record.level(), record.args());
        }
    }
}

impl SimpleLogger {
    pub fn init() -> Result<(), SetLoggerError> {
        log::set_logger(|max_log_level| {
            max_log_level.set(LogLevelFilter::Debug);
            Box::new(SimpleLogger)
        })
    }
}

#[derive(Default, Debug)]
struct ia32_reg_t {
    val: u32,
}

#[allow(dead_code)]
impl ia32_reg_t {
    fn as_u8_lo(&self) -> u8    { self.val as u8 }
    fn as_u8_hi(&self) -> u8    { (self.val >> 8) as u8 }
    fn as_u8(&self) -> u8       { self.as_u8_lo() }
    fn as_u16(&self) -> u16     { self.val as u16 }
    fn as_u32(&self) -> u32     { self.val }

    fn set_u8_lo(&mut self, v8: u8)     { self.val = (self.val & 0xFFFFFF00) | v8 as u32 }
    fn set_u8_hi(&mut self, v8: u8)     { self.val = (self.val & 0xFFFF00FF) | ((v8 as u32) << 8) }
    fn set_u8(&mut self, v8: u8)        { self.set_u8_lo(v8) }
    fn set_u16(&mut self, v16: u16)     { self.val = (self.val & 0xFFFF0000) | v16 as u32 }
    fn set_u32(&mut self, v32: u32)     { self.val = v32 }
}

fn rvmcs(vcpu: hv_vcpuid_t, field: hv_vmx_vmcs_regs) -> u64
{
    unsafe {
        let mut v: u64 = 0;
        let res = hv_vmx_vcpu_read_vmcs(vcpu, field as u32, &mut v);
        assert!(res == HV_SUCCESS);
        return v;
    }
}

fn rvmcs32(vcpu: hv_vcpuid_t, field: hv_vmx_vmcs_regs) -> u32
{
    unsafe {
        let mut v: u64 = 0;
        let res = hv_vmx_vcpu_read_vmcs(vcpu, field as u32, &mut v);
        assert!(res == HV_SUCCESS);
        return v as u32;
    }
}

fn wvmcs(vcpu: hv_vcpuid_t, field: hv_vmx_vmcs_regs, v: u64) 
{
    unsafe {
        let res = hv_vmx_vcpu_write_vmcs(vcpu, field as u32, v);
        assert!(res == HV_SUCCESS);
    }
}

fn wvmcs32(vcpu: hv_vcpuid_t, field: hv_vmx_vmcs_regs, v: u32) 
{
    unsafe {
        let res = hv_vmx_vcpu_write_vmcs(vcpu, field as u32, v as u64);
        assert!(res == HV_SUCCESS);
    }
}

fn read_guest_reg(vcpu: hv_vcpuid_t, reg: hv_x86_reg_t) -> u64
{
    unsafe {
        let mut v: u64 = 0;
        let res = hv_vcpu_read_register(vcpu, reg, &mut v);
        assert!(res == HV_SUCCESS);
        return v;
    }
} 

fn write_guest_reg(vcpu: hv_vcpuid_t, reg: hv_x86_reg_t, v: u64)
{
    unsafe {
        let res = hv_vcpu_write_register(vcpu, reg, v);
        assert!(res == HV_SUCCESS);
    }
} 

fn read_capability(capid: hv_vmx_capability_t) -> u64
{
    unsafe {
        let mut v: u64 = 0;
        let res = hv_vmx_read_capability(capid, &mut v);
        assert!(res == HV_SUCCESS);
        return v;
    }
}

fn check_capability(capid: hv_vmx_capability_t, val: u32) -> u32 
{
    let cap: u64 = read_capability(capid);
    let cap_low: u32 = (cap & 0xFFFFFFFF) as u32;
    let cap_high: u32 = ((cap >> 32) & 0xFFFFFFFF) as u32;

    (val | cap_low) & cap_high
}

fn dump_guest_state(vcpu: hv_vcpuid_t)
{
    let rip = rvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_RIP);
    let cs_base = rvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_CS_BASE);
    let gpa = cs_base + rip;
    println!(" EIP {:x} (CS {:x}, PA {:x})", rip, cs_base, gpa);

    println!(" EAX = {:x}, EBX = {:x}, ECX = {:x}, EDX = {:x} ",
        read_guest_reg(vcpu, hv_x86_reg_t::HV_X86_RAX),
        read_guest_reg(vcpu, hv_x86_reg_t::HV_X86_RBX),
        read_guest_reg(vcpu, hv_x86_reg_t::HV_X86_RCX),
        read_guest_reg(vcpu, hv_x86_reg_t::HV_X86_RDX));

    println!(" ESI = {:x}, EDI = {:x}, EBP = {:x}, ESP = {:x} ",
        read_guest_reg(vcpu, hv_x86_reg_t::HV_X86_RSI),
        read_guest_reg(vcpu, hv_x86_reg_t::HV_X86_RDI),
        read_guest_reg(vcpu, hv_x86_reg_t::HV_X86_RBP),
        read_guest_reg(vcpu, hv_x86_reg_t::HV_X86_RSP));
    
    println!(" EFLAGS = {:x} ",
        read_guest_reg(vcpu, hv_x86_reg_t::HV_X86_RFLAGS));

    println!(" CR0 = {:x}, CR2 = {:x}, CR3 = {:x}, CR4 = {:x} ",
        read_guest_reg(vcpu, hv_x86_reg_t::HV_X86_CR0),
        read_guest_reg(vcpu, hv_x86_reg_t::HV_X86_CR2),
        read_guest_reg(vcpu, hv_x86_reg_t::HV_X86_CR3),
        read_guest_reg(vcpu, hv_x86_reg_t::HV_X86_CR4));

    println!(" CS = {:x}, DS = {:x}, SS = {:x}, ES = {:x}, FS = {:x}, GS = {:x} ",
        read_guest_reg(vcpu, hv_x86_reg_t::HV_X86_CS),
        read_guest_reg(vcpu, hv_x86_reg_t::HV_X86_DS),
        read_guest_reg(vcpu, hv_x86_reg_t::HV_X86_SS),
        read_guest_reg(vcpu, hv_x86_reg_t::HV_X86_ES),
        read_guest_reg(vcpu, hv_x86_reg_t::HV_X86_FS),
        read_guest_reg(vcpu, hv_x86_reg_t::HV_X86_GS));

    println!(" GDTR = ({:x}, {:x}), IDTR = ({:x}, {:x}) ",
        read_guest_reg(vcpu, hv_x86_reg_t::HV_X86_GDT_BASE),
        read_guest_reg(vcpu, hv_x86_reg_t::HV_X86_GDT_LIMIT),
        read_guest_reg(vcpu, hv_x86_reg_t::HV_X86_IDT_BASE),
        read_guest_reg(vcpu, hv_x86_reg_t::HV_X86_IDT_LIMIT));

    println!(" GLA = {:x}", rvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_RO_GUEST_LIN_ADDR));
    println!(" EXITQ = {:x}", rvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_RO_EXIT_QUALIFIC));
}

fn is_in_real_mode(vcpu: hv_vcpuid_t) -> bool
{
    (rvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_CR0) & 0x1) == 0
}

fn get_capstone_mode(vcpu: hv_vcpuid_t) -> capstone::constants::CsMode {
    if is_in_real_mode(vcpu) {
        return capstone::CsMode::MODE_16;
    } else {
        return capstone::CsMode::MODE_32;
    }
}

fn dump_guest_code(pa: hv_gpaddr_t)
{
    const CODE_SIZE: usize = 32;
    let addr = pa;
    let mut buf: [u8; CODE_SIZE] = [0; CODE_SIZE];
    let bytes = vm::read_guest_memory(addr, &mut buf);
    let mode = get_capstone_mode(vm::vcpu());

    let cs = match capstone::Capstone::new(capstone::CsArch::ARCH_X86, mode) {
        Ok(cs) => cs,
        Err(err) => { 
            error!("Error: {}", err);
            return;
        }
    };

    match cs.disasm(&buf[0..bytes], addr, 0) {
        Ok(insns) => {
            for i in insns.iter() {
                println!("{}", i);
            }
        },
        Err(err) => {
            error!("Error: {}", err);
        }
    }
}

fn load_image(path: &str) -> Vec<u8>
{
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(err) => panic!(err.to_string()),
    };

    let mut buffer = Vec::new();
    let nbytes = match file.read_to_end(&mut buffer) {
        Ok(usize) => usize,
        Err(err) => panic!(err.to_string()),
    };

    return buffer;
}

fn make_ram_region(base: u64, size: usize) -> Arc<vm::memory_region>
{
    let ram_region = vm::alloc_memory_region(size);
    vm::map_memory_region(base, HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC, ram_region.clone());

    // Put software breakpoints everywhere
    unsafe {
        memset(ram_region.data as *mut u8, 0xCC, ram_region.size);
    }

    ram_region
}

fn next_instruction(vcpu: hv_vcpuid_t)
{
    wvmcs(vcpu,
          hv_vmx_vmcs_regs::VMCS_GUEST_RIP,
          rvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_RIP) + rvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_RO_VMEXIT_INSTR_LEN));
}

// TODO: macro
fn is_bit_changed<T: PrimInt>(old_val: T, new_val: T, bit: usize) -> bool {
    ((old_val ^ new_val) & (T::one() << bit)) != T::zero()
}

#[test]
fn test_is_bit_changed() {
    assert!(is_bit_changed(0xdeadf00du32, 0xdeadf00du32, 15) == false);
    assert!(is_bit_changed(0xdeadf00du32, !0xdeadf00du32, 15) == true);
}

fn wait_any_key() 
{
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).ok().expect("stdin failed");

}

fn is_interruptible(vcpu: hv_vcpuid_t) -> bool
{
    let flags = read_guest_reg(vcpu, hv_x86_reg_t::HV_X86_RFLAGS);
    let intstate = rvmcs32(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_IGNORE_IRQ);

    return (intstate == 0) && (flags & (1 << 9)) != 0;
}

fn request_interrupt_window(vcpu: hv_vcpuid_t)
{
    let ctrls = check_capability(hv_vmx_capability_t::HV_VMX_CAP_PROCBASED,
                                 rvmcs32(vcpu, hv_vmx_vmcs_regs::VMCS_CTRL_CPU_BASED) | CPU_BASED_IRQ_WND);
    wvmcs32(vcpu, hv_vmx_vmcs_regs::VMCS_CTRL_CPU_BASED, ctrls);
}

fn complete_interrupt_window(vcpu: hv_vcpuid_t)
{
    let ctrls = check_capability(hv_vmx_capability_t::HV_VMX_CAP_PROCBASED,
                                 rvmcs32(vcpu, hv_vmx_vmcs_regs::VMCS_CTRL_CPU_BASED) & !CPU_BASED_IRQ_WND);
    wvmcs32(vcpu, hv_vmx_vmcs_regs::VMCS_CTRL_CPU_BASED, ctrls);
}

fn init(vcpu: hv_vcpuid_t, bootimg: &String, has_bios: bool)
{
    let kernel_base = 0x8000_u64;
    let img = load_image(bootimg);

    if has_bios {
        let ram = make_ram_region(0x0, 0xA0000);

        assert!((img.len() & 0xFFFF) == 0); // BIOS image should be aligned to real mode segment size
        let rom = vm::alloc_memory_region(img.len());
        if rom.write_bytes(0, &img[..]) != img.len() {
            panic!();
        }

        // First rom mapping goes to upper memory
        vm::map_memory_region(0x100000000u64 - rom.size as u64, HV_MEMORY_READ | HV_MEMORY_EXEC, rom.clone());

        // Second rom mapping goes right below first megabyte
        vm::map_memory_region(0x100000u64 - rom.size as u64, HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC, rom.clone());
    } else {
        let ram = make_ram_region(0x0, 0x100000);
        if ram.write_bytes(kernel_base as usize, &img[..]) != img.len() {
            panic!();
        }
    }

    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_CS, 0);
    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_CS_LIMIT, 0xffff);
    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_CS_AR, 0x9b);

    if has_bios {
        // Firmware entry at real mode CS:0 with CS.base = 0xFFFFFFF0
        wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_CS_BASE, 0xfffffff0);
        write_guest_reg(vcpu, hv_x86_reg_t::HV_X86_RIP, 0x0);

    } else {
        // Kernel entry point at real mode 0h:8000h
        wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_CS_BASE, 0);
        write_guest_reg(vcpu, hv_x86_reg_t::HV_X86_RIP, kernel_base);
    }

    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_DS, 0);
    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_DS_LIMIT, 0xffff);
    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_DS_AR, 0x93);
    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_DS_BASE, 0);

    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_ES, 0);
    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_ES_LIMIT, 0xffff);
    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_ES_AR, 0x93);
    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_ES_BASE, 0);

    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_FS, 0);
    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_FS_LIMIT, 0xffff);
    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_FS_AR, 0x93);
    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_FS_BASE, 0);

    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_GS, 0);
    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_GS_LIMIT, 0xffff);
    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_GS_AR, 0x93);
    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_GS_BASE, 0);

    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_SS, 0);
    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_SS_LIMIT, 0xffff);
    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_SS_AR, 0x93);
    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_SS_BASE, 0);

    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_LDTR, 0);
    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_LDTR_LIMIT, 0);
    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_LDTR_AR, 0x10000);
    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_LDTR_BASE, 0);

    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_TR, 0);
    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_TR_LIMIT, 0);
    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_TR_AR, 0x83);
    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_TR_BASE, 0);

    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_GDTR_LIMIT, 0);
    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_GDTR_BASE, 0);

    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_IDTR_LIMIT, 0);
    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_IDTR_BASE, 0);

    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_CR0, 0x20);
    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_CTRL_CR0_SHADOW, 0x20);
    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_CTRL_CR0_MASK, 0x1);

    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_CR3, 0x0);

    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_CR4, 0x2200);
    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_CTRL_CR4_MASK, 0);
    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_CTRL_CR4_SHADOW, 0);

    write_guest_reg(vcpu, hv_x86_reg_t::HV_X86_RFLAGS, 0x2 /*| (1u64 << 8)*/);
    write_guest_reg(vcpu, hv_x86_reg_t::HV_X86_RSP, 0x0);

    if cfg!(feature = "guest-tracing") {
        write_guest_reg(vcpu, hv_x86_reg_t::HV_X86_RFLAGS,
                        read_guest_reg(vcpu, hv_x86_reg_t::HV_X86_RFLAGS) | (1u64 << 8));
    }
}

fn main()
{
    // Init logger
    SimpleLogger::init().unwrap();

    // Init VM for this process
    vm::create();
    let vcpu = vm::vcpu();

    // Register IO handlers
    qemudbg::init();
    miscdev::init();
    cmos::init();
    pic::init();
    pit::init();
    pci::init();

    // Dump capabilities for debugging
    debug!("HV_VMX_CAP_PINBASED:      {:x}", read_capability(hv_vmx_capability_t::HV_VMX_CAP_PINBASED));
    debug!("HV_VMX_CAP_PROCBASED:     {:x}", read_capability(hv_vmx_capability_t::HV_VMX_CAP_PROCBASED));
    debug!("HV_VMX_CAP_PROCBASED2:    {:x}", read_capability(hv_vmx_capability_t::HV_VMX_CAP_PROCBASED2));
    debug!("HV_VMX_CAP_ENTRY:         {:x}", read_capability(hv_vmx_capability_t::HV_VMX_CAP_ENTRY));
    debug!("HV_VMX_CAP_EXIT:          {:x}", read_capability(hv_vmx_capability_t::HV_VMX_CAP_EXIT));

    // Init vcpu
    wvmcs32(vcpu, hv_vmx_vmcs_regs::VMCS_CTRL_PIN_BASED, check_capability(hv_vmx_capability_t::HV_VMX_CAP_PINBASED, 0
        /*| PIN_BASED_INTR*/
        /*| PIN_BASED_NMI*/
        /*| PIN_BASED_VIRTUAL_NMI*/));

    wvmcs32(vcpu, hv_vmx_vmcs_regs::VMCS_CTRL_CPU_BASED, check_capability(hv_vmx_capability_t::HV_VMX_CAP_PROCBASED, (0
        | CPU_BASED_HLT
        | CPU_BASED_CR8_LOAD
        | CPU_BASED_CR8_STORE
        | CPU_BASED_SECONDARY_CTLS) as u32));

    wvmcs32(vcpu, hv_vmx_vmcs_regs::VMCS_CTRL_CPU_BASED2, check_capability(hv_vmx_capability_t::HV_VMX_CAP_PROCBASED2, 0
        /*| CPU_BASED2_EPT*/
        | CPU_BASED2_UNRESTRICTED as u32));

    wvmcs32(vcpu, hv_vmx_vmcs_regs::VMCS_CTRL_VMENTRY_CONTROLS, check_capability(hv_vmx_capability_t::HV_VMX_CAP_ENTRY, 0));
    wvmcs32(vcpu, hv_vmx_vmcs_regs::VMCS_CTRL_VMEXIT_CONTROLS, check_capability(hv_vmx_capability_t::HV_VMX_CAP_EXIT, 0));

    if cfg!(feature = "guest-tracing") {
        wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_CTRL_EXC_BITMAP, 0
              | (1 << 1)
              | (1 << 3)
        );
    }

    let args: Vec<String> = env::args().collect();
    if args.len() > 1 {
        debug!("Running test image {}", args[1]);
        init(vcpu, &args[1], false);
    } else {
        debug!("Running firmware");
        init(vcpu, &String::from("bios/bios.bin"), true);
    }

    // Run vm loop
    loop {
        let err = vm::run(vcpu);

        if err != HV_SUCCESS {
            error!("vm_run failed with {}", err);
            break;
        }

        let exit_reason = rvmcs32(vcpu, hv_vmx_vmcs_regs::VMCS_RO_EXIT_REASON);
        let exit_qualif = rvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_RO_EXIT_QUALIFIC);
        let ip = rvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_RIP) + rvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_CS_BASE);

        debug!("\n----------");
        debug!("Exit reason {:x} ({})", exit_reason, exit_reason & 0xFFFF);

        let reason: hv_vmx_exit_reason = hv_vmx_exit_reason::from_u32(exit_reason & 0xFFFF).unwrap();

        dump_guest_state(vcpu);
        dump_guest_code(ip);

        match reason {
            hv_vmx_exit_reason::VMX_REASON_EXC_NMI => {
                debug!("VMX_REASON_EXC_NMI");

                let irqInfo: u32 = rvmcs32(vcpu, hv_vmx_vmcs_regs::VMCS_RO_VMEXIT_IRQ_INFO);
                let irqVec: u8 = (irqInfo & 0xff) as u8;

                if irqVec == 1 {
                    debug!("Guest trap @ {:x}", rvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_RO_GUEST_LIN_ADDR));
                }
            },

            hv_vmx_exit_reason::VMX_REASON_IRQ => {
                debug!("VMX_REASON_IRQ");
                debug!("VMCS_RO_IDT_VECTOR_INFO = {:x}", rvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_RO_IDT_VECTOR_INFO));
                debug!("VMCS_RO_IDT_VECTOR_ERROR = {:x}", rvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_RO_IDT_VECTOR_ERROR));
                debug!("VMCS_RO_VMEXIT_IRQ_INFO = {:x}", rvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_RO_VMEXIT_IRQ_INFO));
                debug!("VMCS_RO_VMEXIT_IRQ_ERROR = {:x}", rvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_RO_VMEXIT_IRQ_ERROR));
            }

            hv_vmx_exit_reason::VMX_REASON_IO => {
                let size: u8 = match exit_qualif & 0x7 {
                    0 => 1,
                    1 => 2,
                    3 => 4,
                    _ => panic!("invalid IO size bits"),
                };

                let port: u16 = ((exit_qualif >> 16) & 0xFFFF) as u16; 
                let is_read: bool = (exit_qualif & 0x8) != 0;

                if is_read {
                    let mut eax = ia32_reg_t {
                        val: read_guest_reg(vcpu, hv_x86_reg_t::HV_X86_RAX) as u32
                    };

                    match size {
                        1 => eax.set_u8(vm::handle_io_read(port, size).unwrap_byte()),
                        2 => eax.set_u16(vm::handle_io_read(port, size).unwrap_word()),
                        4 => eax.set_u32(vm::handle_io_read(port, size).unwrap_dword()),
                        _ => panic!(),
                    }

                    write_guest_reg(vcpu, hv_x86_reg_t::HV_X86_RAX, eax.val as u64);
                } else {
                    let eax = ia32_reg_t {
                        val: read_guest_reg(vcpu, hv_x86_reg_t::HV_X86_RAX) as u32
                    };

                    debug!("Writing {:?} to port {:x} size {}", eax, port, size);

                    match size {
                        1 => vm::handle_io_write(port, vm::IoOperandType::byte(eax.as_u8())),
                        2 => vm::handle_io_write(port, vm::IoOperandType::word(eax.as_u16())),
                        4 => vm::handle_io_write(port, vm::IoOperandType::dword(eax.as_u32())),
                        _ => panic!(),
                    }
                }

                next_instruction(vcpu);
            }

            hv_vmx_exit_reason::VMX_REASON_MOV_CR => {
                debug!("VMX_REASON_MOV_CR");
                
                let crreg = exit_qualif & 0xF;
                let optype = (exit_qualif >> 4) & 0x3;
                let gpreg = ((exit_qualif >> 8) & 0xF) as usize;

                if optype != 0 {
                    panic!("VMX_REASON_MOV_CR: Only MOV to CR is supported (got {})", optype);
                }

                if crreg != 0 {
                    panic!("VMX_REASON_MOV_CR: Expected CR0, got CR{}", crreg);
                }

                if gpreg >= 8 {
                    panic!("VMX_REASON_MOV_CR: gpreg index out of bounds {}", gpreg);
                }

                let gpregmap: [hv_x86_reg_t; 8] = [
                    hv_x86_reg_t::HV_X86_RAX,
                    hv_x86_reg_t::HV_X86_RCX,
                    hv_x86_reg_t::HV_X86_RDX,
                    hv_x86_reg_t::HV_X86_RBX,
                    hv_x86_reg_t::HV_X86_RSP,
                    hv_x86_reg_t::HV_X86_RBP,
                    hv_x86_reg_t::HV_X86_RSI,
                    hv_x86_reg_t::HV_X86_RDI,
                ];

                let new_val = read_guest_reg(vcpu, gpregmap[gpreg]);
                let cur_val = read_guest_reg(vcpu, hv_x86_reg_t::HV_X86_CR0);

                debug!("VMX_REASON_MOV_CR: current value {:x}, new value {:x}", cur_val, new_val);

                // CR0.PE?
                if is_bit_changed(cur_val, new_val, 0) {
                    debug!("VMX_REASON_MOV_CR: PE {}", new_val & 0x1);
                }

                // We just keep shadow value in sync
                wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_CTRL_CR0_SHADOW, new_val);
                wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_CR0, new_val);
                next_instruction(vcpu);
            }

            hv_vmx_exit_reason::VMX_REASON_EPT_VIOLATION => {
                debug!("VMX_REASON_EPT_VIOLATION");
            }


            hv_vmx_exit_reason::VMX_REASON_IRQ_WND => {
                debug!("VMX_REASON_IRQ_WND");

                /* Close interrupt window here - we will inject interrupts before returning to guest */
                complete_interrupt_window(vcpu);
            }

            hv_vmx_exit_reason::VMX_REASON_TRIPLE_FAULT => {
                debug!("VMX_REASON_TRIPLE_FAULT");
                panic!();
            }

            _ => {
                panic!("Unhandled exit reason");
            }

        }

        /* Inject pending external interrupts or request interrupt window if guest is not
         * interruptible */
        if vm::has_pending_interrupts() {
            if !is_interruptible(vcpu) {
                request_interrupt_window(vcpu);
            } else {
                match vm::next_external_interrupt() {
                    Some(excp) => {
                        let event = 0x80000000_u32 | excp as u32;
                        wvmcs32(vcpu, hv_vmx_vmcs_regs::VMCS_CTRL_VMENTRY_IRQ_INFO, event);
                    },
                    None => {},
                }
            }
        }

        if cfg!(feature = "guest-tracing") {
            println!("Press any key to resume execution.. ");
            wait_any_key();
        }
    }
}
