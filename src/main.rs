// jmd-windows — CLI-tool for detecting JVMTI/JNI injections on Windows
// Copyright (C) 2025 danfordd
// Licensed under the GNU General Public License v3.0 or later.
// See the LICENSE file for details.


use std::mem;
use std::slice;

use anyhow::Result;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Memory::{
    VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT,
    PAGE_READWRITE, PAGE_READONLY, PAGE_WRITECOPY,
};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};

fn main() -> Result<()> {
    let processes = find_process("javaw.exe")?;
    if processes.is_empty() {
        println!("No javaw.exe processes found.");
    } else {
        for pid in processes {
            println!("Scanning process ID: {}", pid);
            match scan_memory(pid) {
                Ok(found) => {
                    if !found {
                        println!("[-] No suspicious manipulations with JVM detected.");
                    }
                }
                Err(e) => {
                    eprintln!("[/] Error while scanning: {}", e);
                }
            }
        }
    }

    println!("Press any key to exit...");
    let term = console::Term::stdout();
    term.read_key().ok();
    Ok(())
}

fn find_process(name: &str) -> Result<Vec<u32>> {
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)? };
    let mut entry: PROCESSENTRY32W = unsafe { mem::zeroed() };
    entry.dwSize = mem::size_of::<PROCESSENTRY32W>() as u32;

    let mut pids = Vec::new();
    if unsafe { Process32FirstW(snapshot, &mut entry) }.is_ok() {
        loop {
            let exe_name = unsafe {
                String::from_utf16_lossy(slice::from_raw_parts(
                    entry.szExeFile.as_ptr(),
                    entry.szExeFile.len(),
                ))
                .trim_end_matches('\0')
                .to_string()
            };

            if exe_name.eq_ignore_ascii_case(name) {
                pids.push(entry.th32ProcessID);
            }

            if unsafe { Process32NextW(snapshot, &mut entry) }.is_err() {
                break;
            }
        }
    }

    unsafe { CloseHandle(snapshot)? };
    Ok(pids)
}

fn scan_memory(pid: u32) -> Result<bool> {
    let handle = unsafe {
        OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)?
    };

    const S1: [u32; 4] = [4242546329, 4601, 0, 0];
    const S2: [u32; 4] = [4242546329, 505, 0, 0];

    let sig1: Vec<u8> = S1.iter().flat_map(|n| n.to_le_bytes()).collect();
    let sig2: Vec<u8> = S2.iter().flat_map(|n| n.to_le_bytes()).collect();

    let mut base_address = 0usize;
    let mut found = false;

    loop {
        let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { mem::zeroed() };
        let result = unsafe {
            VirtualQueryEx(
                handle,
                Some(base_address as *const _),
                &mut mbi,
                mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };

        if result == 0 {
            break;
        }

        let state = mbi.State;
        let protect = mbi.Protect;
        if state != MEM_COMMIT
            || !(protect == PAGE_READONLY
                || protect == PAGE_READWRITE
                || protect == PAGE_WRITECOPY)
        {
            base_address += mbi.RegionSize;
            continue;
        }

        let region_size = mbi.RegionSize;
        if region_size == 0 {
            base_address += 1;
            continue;
        }

        let mut buffer = vec![0u8; region_size.min(1024 * 1024)];
        let bytes_read = unsafe {
            let mut read = 0;
            ReadProcessMemory(
                handle,
                mbi.BaseAddress,
                buffer.as_mut_ptr() as *mut _,
                buffer.len(),
                Some(&mut read),
            )?;
            read
        };

        if bytes_read == 0 {
            base_address += region_size;
            continue;
        }

        buffer.truncate(bytes_read as usize);

        if memmem(&buffer, &sig1).is_some() {
            println!("[+] Injection was detected (#S1).");
            found = true;
            break;
        }

        if memmem(&buffer, &sig2).is_some() {
            println!("[+] Injection was detected (#S2).");
            found = true;
            break;
        }

        base_address += region_size;
    }

    unsafe { CloseHandle(handle)? };
    Ok(found)
}

fn memmem(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    for i in 0..=haystack.len().saturating_sub(needle.len()) {
        if haystack[i..].starts_with(needle) {
            return Some(i);
        }
    }
    None
}
