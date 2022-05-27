use std::{
    collections::HashMap,
    ffi::CString,
    fs,
    io::{self, Write},
    path::Path,
    process::Command,
};

use aya::{
    include_bytes_aligned,
    maps::{perf::AsyncPerfEventArray, HashMap as BpfHashMap, MapRefMut},
    programs::{KProbe, RawTracePoint},
    util::online_cpus,
    Bpf,
};
use bytes::BytesMut;
use clap::Parser;
use log::{error, info};
use regex::Regex;
use simplelog::{ColorChoice, ConfigBuilder, LevelFilter, TermLogger, TerminalMode};
use syscall_digest_common::{Filename, SyscallLog};
use tokio::{signal, sync::mpsc, task};

#[derive(Debug, Parser)]
struct Opt {}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let _opt = Opt::parse();

    TermLogger::init(
        LevelFilter::Debug,
        ConfigBuilder::new()
            .set_target_level(LevelFilter::Error)
            .set_location_level(LevelFilter::Error)
            .build(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )?;

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/syscall-digest"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/syscall-digest"
    ))?;

    // Enable when logging is needed in eBPF
    // BpfLogger::init(&mut bpf)?;

    let tracepoint: &mut RawTracePoint = bpf.program_mut("log_syscall").unwrap().try_into()?;
    tracepoint.load()?;
    tracepoint.attach("sys_enter")?;

    let kprobe: &mut KProbe = bpf.program_mut("log_pid").unwrap().try_into()?;
    kprobe.load()?;
    kprobe.attach("__x64_sys_execve", 0)?;

    let mut perf_array = AsyncPerfEventArray::try_from(bpf.map_mut("EVENTS")?)?;
    let mut pid_map: BpfHashMap<MapRefMut, u32, Filename> =
        BpfHashMap::try_from(bpf.map_mut("PIDS").unwrap()).unwrap();

    info!("Building Syscall Name Database");
    let mut syscalls = HashMap::new();
    let output = Command::new("ausyscall").arg("--dump").output()?;
    println!("status: {}", output.status);
    io::stdout().write_all(&output.stdout).unwrap();
    io::stderr().write_all(&output.stderr).unwrap();
    let pattern = Regex::new(r"([0-9]+)\t(.*)")?;
    String::from_utf8(output.stdout)?
        .lines()
        .filter_map(|line| pattern.captures(line))
        .map(|cap| (cap[1].parse::<u32>().unwrap(), cap[2].trim().to_string()))
        .for_each(|(k, v)| {
            syscalls.insert(k, v);
        });

    info!("Building Process Digest Map From /proc");
    let mut digests: HashMap<u32, String> = HashMap::new();
    for prc in procfs::process::all_processes().unwrap() {
        if let Ok(filename) = prc.exe() {
            let filename = CString::new(filename.to_str().unwrap())?;
            let filename_bytes = filename.as_bytes_with_nul();
            let filename_len = filename_bytes.len() as u8;

            let mut buf = [0u8; 127];
            for (&x, p) in filename_bytes.iter().zip(buf.iter_mut()) {
                *p = x;
            }
            let f = Filename {
                filename: buf,
                filename_len,
            };
            pid_map.insert(prc.pid() as u32, f, 0)?;
        }
    }

    info!("Spawning Event Processing Thread");
    let (tx, mut rx) = mpsc::channel(100);
    task::spawn(async move {
        while let Some((syscall, pid)) = rx.recv().await {
            if let Ok(proc) = pid_map.get(&pid, 0) {
                let filename = unsafe {
                    std::str::from_utf8_unchecked(&proc.filename[0..proc.filename_len as usize - 1])
                };

                if digests.contains_key(&pid) {
                    let digest = digests.get(&pid).unwrap();
                    info!(
                        "got = syscall: {} pid: {} filename: {} digest: {}",
                        syscalls.get(&syscall).unwrap_or(&syscall.to_string()),
                        pid,
                        filename,
                        digest
                    );
                } else {
                    let path = Path::new(filename);
                    if path.exists() {
                        let meta = fs::metadata(path).unwrap();
                        if meta.len() < 10240000 {
                            let digest = sha256::digest_file(path).unwrap();
                            digests.insert(pid, digest.clone());
                            info!(
                                "got = syscall: {} pid: {} filename: {} digest: {}",
                                syscalls.get(&syscall).unwrap_or(&syscall.to_string()),
                                pid,
                                filename,
                                digest
                            );
                        } else {
                            info!(
                                "got = syscall: {} pid: {} filename: {} digest: ETOOBIG",
                                syscalls.get(&syscall).unwrap_or(&syscall.to_string()),
                                pid,
                                filename
                            );
                        }
                    } else {
                        error!("path {} is not valid", filename);
                    }
                };
            }
        }
    });

    info!("Spawning eBPF Event Listener");
    for cpu_id in online_cpus()? {
        let mut buf = perf_array.open(cpu_id, None)?;
        let tx = tx.clone();
        task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();

            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();
                let mut results = vec![];
                for buf in buffers.iter_mut().take(events.read) {
                    let ptr = buf.as_ptr() as *const SyscallLog;
                    let data = unsafe { ptr.read_unaligned() };
                    results.push((data.syscall, data.pid));
                }
                for res in results {
                    tx.send(res).await.unwrap();
                }
            }
        });
    }

    signal::ctrl_c().await.expect("failed to listen for event");

    Ok(())
}
