#![allow(non_snake_case)] 
#![allow(non_camel_case_types)]

extern crate rlibc;
extern crate num;
#[macro_use]
extern crate log;
extern crate core;
extern crate capstone;
extern crate hypervisor_framework;

mod qemudbg;
mod miscdev;
mod vm;

use hypervisor_framework::*;
use rlibc::*;
use std::sync::Arc;
use std::fs::*;
use std::io::Read;
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

fn dump_guest_code(vm: &vm::vm, pa: hv_gpaddr_t)
{
    const CODE_SIZE: usize = 32;
    let addr = pa;
    let mut buf: [u8; CODE_SIZE] = [0; CODE_SIZE];
    let bytes = vm::read_guest_memory(vm, addr, &mut buf);

    let cs = match capstone::Capstone::new(capstone::CsArch::ARCH_X86, capstone::CsMode::MODE_16) {
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

fn load_rom_image(path: &str) -> Arc<vm::memory_region>
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

    debug!("ROM size {} bytes", nbytes);

    let reg = vm::alloc_memory_region(nbytes);
    if reg.write_bytes(0, &buffer[..]) != nbytes {
        panic!();
    }

    return reg;
}

fn wait_any_key() 
{
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).ok().expect("stdin failed");

}

fn main() 
{
    // Init logger
    SimpleLogger::init().unwrap();
    
    // Init VM for this process
    let mut vm = vm::create();
    let vcpu = vm.vcpu;

    // Dump capabilities for debugging
    debug!("HV_VMX_CAP_PINBASED:      {:x}", read_capability(hv_vmx_capability_t::HV_VMX_CAP_PINBASED));
    debug!("HV_VMX_CAP_PROCBASED:     {:x}", read_capability(hv_vmx_capability_t::HV_VMX_CAP_PROCBASED));
    debug!("HV_VMX_CAP_PROCBASED2:    {:x}", read_capability(hv_vmx_capability_t::HV_VMX_CAP_PROCBASED2));
    debug!("HV_VMX_CAP_ENTRY:         {:x}", read_capability(hv_vmx_capability_t::HV_VMX_CAP_ENTRY));
    debug!("HV_VMX_CAP_EXIT:          {:x}", read_capability(hv_vmx_capability_t::HV_VMX_CAP_EXIT));

    // Create real mode memory region covering 640KB
    let ram_region = vm::alloc_memory_region(0xA0000);
    vm::map_memory_region(&mut vm, 0x0, HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC, ram_region.clone());

    // Put software breakpoints everywhere
    unsafe {
        memset(ram_region.data as *mut u8, 0xCC, ram_region.size);
    }

    // Load bios rom and map it
    let rom_region = load_rom_image("bios/bios.bin");
    assert!((rom_region.size & 0xFFFF) == 0); // BIOS image should be aligned to real mode segment size

    // First rom mapping goes to upper memory
    vm::map_memory_region(&mut vm, 
                         0x100000000u64.checked_sub(rom_region.size as u64).unwrap(), 
                         HV_MEMORY_READ | HV_MEMORY_EXEC, 
                         rom_region.clone());

    // Second rom mapping goes right below first megabyte
    vm::map_memory_region(&mut vm, 
                         0x100000u64.checked_sub(rom_region.size as u64).unwrap(), 
                         HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC, 
                         rom_region.clone());

    // Register IO handlers
    qemudbg::init(&mut vm);
    miscdev::init(&mut vm);

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

    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_CTRL_EXC_BITMAP, 0 
        | (1 << 1)
        | (1 << 3)
        );

    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_CTRL_CR0_MASK, 0x60000000);
    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_CTRL_CR0_SHADOW, 0);
    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_CTRL_CR4_MASK, 0);
    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_CTRL_CR4_SHADOW, 0);

    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_CS, 0);
    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_CS_LIMIT, 0xffff);
    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_CS_AR, 0x9b);
    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_CS_BASE, 0xfffffff0);

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
    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_CR3, 0x0);
    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_CR4, 0x2000);

    write_guest_reg(vcpu, hv_x86_reg_t::HV_X86_RIP, 0x0);
    write_guest_reg(vcpu, hv_x86_reg_t::HV_X86_RFLAGS, 0x2 /*| (1u64 << 8)*/);
    write_guest_reg(vcpu, hv_x86_reg_t::HV_X86_RSP, 0x0);

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

        let reason: hv_vmx_exit_reason = hv_vmx_exit_reason::from_u32(exit_reason).unwrap();

        dump_guest_state(vcpu);
        dump_guest_code(&vm, ip);

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
                        1 => eax.set_u8(vm::handle_io_read(&vm, port, size).unwrap_byte()),
                        2 => eax.set_u16(vm::handle_io_read(&vm, port, size).unwrap_word()),
                        4 => eax.set_u32(vm::handle_io_read(&vm, port, size).unwrap_dword()),
                        _ => panic!(),
                    }

                    write_guest_reg(vcpu, hv_x86_reg_t::HV_X86_RAX, eax.val as u64);
                } else {
                    let eax = ia32_reg_t {
                        val: read_guest_reg(vcpu, hv_x86_reg_t::HV_X86_RAX) as u32
                    };

                    debug!("Writing {:?} to port {:x} size {}", eax, port, size);

                    match size {
                        1 => vm::handle_io_write(&mut vm, port, vm::IoOperandType::byte(eax.as_u8())),
                        2 => vm::handle_io_write(&mut vm, port, vm::IoOperandType::word(eax.as_u16())),
                        4 => vm::handle_io_write(&mut vm, port, vm::IoOperandType::dword(eax.as_u32())),
                        _ => panic!(),
                    }
                }

                //debug!("instruction length {:?}", rvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_RO_VMEXIT_INSTR_LEN));
                wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_RIP, rvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_RIP) + rvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_RO_VMEXIT_INSTR_LEN));
            }

            hv_vmx_exit_reason::VMX_REASON_EPT_VIOLATION => {
                debug!("VMX_REASON_EPT_VIOLATION");
            }


            _ => {
                panic!("Unhandled exit reason");
            }

        }

        // TODO: If single stepping
        println!("Press any key to resume execution.. ");
        wait_any_key();
    }
}
