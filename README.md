# syscall-digest

This is a prototype of a program that:

1. Reads the list of processes from procfs and stores a SHA-256 digest of each executable
2. Attaches an eBPF KProbe program to `sys_execve` to capture the PID and executable of newly instantiated processes
3. Attaches an eBPF Raw Tracepoint program to capture the ID and PID of all syscalls made on the system and sends these events to userspace
4. Processes the events from eBPF and logs the Syscall ID, PID, and the filename and digest of the executable to stdout.

## Prerequisites

1. Install a rust stable toolchain: `rustup install stable`
1. Install a rust nightly toolchain: `rustup install nightly`
1. Install bpf-linker: `cargo install bpf-linker`

## Build eBPF

```bash
cargo xtask build-ebpf
```

To perform a release build you can use the `--release` flag.
You may also change the target architecture with the `--target` flag

## Build Userspace

```bash
cargo build
```

## Run

```bash
cargo xtask run
```

## License

This project is distributed under the terms of either the [MIT license](LICENSE-MIT) or the [Apache License](LICENSE-APACHE) (version
2.0), at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this crate by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.