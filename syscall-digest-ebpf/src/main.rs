#![no_std]
#![no_main]

use core::slice;

use aya_bpf::{
    helpers::*,
    macros::{kprobe, map, raw_tracepoint},
    maps::{HashMap, PerfEventArray},
    programs::{ProbeContext, RawTracePointContext},
    BpfContext, PtRegs,
};

use syscall_digest_common::{Filename, SyscallLog};

#[map(name = "EVENTS")]
static mut EVENTS: PerfEventArray<SyscallLog> =
    PerfEventArray::<SyscallLog>::with_max_entries(1024, 0);

#[map(name = "PIDS")]
static mut PIDS: HashMap<u32, Filename> = HashMap::with_max_entries(10240000, 0);

/// log_syscall is attached to the sys_enter raw tracepoint
/// it sends an event to userspace containing the PID and syscall ID
#[raw_tracepoint]
pub fn log_syscall(ctx: RawTracePointContext) -> u32 {
    match unsafe { try_log_syscall(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_log_syscall(ctx: RawTracePointContext) -> Result<u32, u32> {
    let args = slice::from_raw_parts(ctx.as_ptr() as *const usize, 2);
    let syscall = args[1] as u64;
    let pid = ctx.pid();
    let log_entry = SyscallLog {
        pid,
        syscall: syscall as u32,
    };
    EVENTS.output(&ctx, &log_entry, 0);
    Ok(0)
}

/// log_pid is attached to the execve function in the kernel
/// it logs the pid and filename to the PIDS map
#[kprobe]
pub fn log_pid(ctx: ProbeContext) -> u32 {
    match unsafe { try_log_pid(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_log_pid(ctx: ProbeContext) -> Result<u32, u32> {
    let pid = ctx.pid();

    if PIDS.get(&pid).is_none() {
        let regs = PtRegs::new(ctx.arg(0).unwrap());
        let filename_addr: *const u8 = regs.arg(0).unwrap();

        let mut buf = [0u8; 127];
        let filename_len = bpf_probe_read_user_str(filename_addr as *const u8, &mut buf)
            .map_err(|e| e as u32)? as u8;

        let log_entry = Filename {
            filename: buf,
            filename_len,
        };
        PIDS.insert(&pid, &log_entry, 0).unwrap();
    }

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
