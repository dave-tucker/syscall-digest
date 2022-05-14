#![no_std]

#[repr(C)]
#[derive(Copy, Clone)]
pub struct SyscallLog {
    pub syscall: u32,
    pub pid: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for SyscallLog {}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct Filename {
    pub filename: [u8; 127],
    pub filename_len: u8,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Filename {}
