use goblin::pe::PE;
use log::{debug, error, info};
use std::ptr;
use windows_sys::Win32::Foundation::{CloseHandle, FALSE, HANDLE};
use windows_sys::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JobObjectExtendedLimitInformation, SetInformationJobObject,
};
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE, VirtualAllocEx, VirtualProtectEx,
};
use windows_sys::Win32::System::Threading::{
    CreateRemoteThread, GetExitCodeProcess, WaitForSingleObject,
};

#[cfg(target_os = "windows")]
pub static STUB_EXE: &[u8] = include_bytes!("../stub/stub.exe");

fn rva_to_file_offset(pe: &PE, rva: usize) -> Option<usize> {
    pe.sections
        .iter()
        .find(|s| {
            rva >= s.virtual_address as usize && rva < (s.virtual_address + s.virtual_size) as usize
        })
        .map(|s| s.pointer_to_raw_data as usize + (rva - s.virtual_address as usize))
}

fn read_cstr(buf: &[u8], offset: usize) -> Vec<u8> {
    let end = buf[offset..].iter().position(|&b| b == 0).unwrap_or(0);
    let mut s = buf[offset..offset + end].to_vec();
    s.push(0);
    s
}

pub unsafe fn inject_and_run(
    process_handle: HANDLE,
    thread_handle_host: HANDLE,
    frpc_buffer: &[u8],
) {
    debug!("Parsing frpc.exe PE structure...");
    let pe = PE::parse(frpc_buffer).expect("Failed to parse frpc.exe PE structure");
    let optional_header = pe.header.optional_header.as_ref().unwrap();
    let size_of_image = optional_header.windows_fields.size_of_image as usize;
    let size_of_headers = optional_header.windows_fields.size_of_headers as usize;
    let preferred_base = optional_header.windows_fields.image_base;
    let entry_point_rva = optional_header.standard_fields.address_of_entry_point as u64;

    // 在 stub.exe 中申請記憶體並寫入 frpc
    let remote_image_base = unsafe {
        VirtualAllocEx(
            process_handle,
            ptr::null_mut(),
            size_of_image,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };

    if remote_image_base.is_null() {
        error!(
            "Failed to allocate memory in the target process! Error code: {}",
            std::io::Error::last_os_error()
        );
        unsafe {
            CloseHandle(process_handle);
            CloseHandle(thread_handle_host);
        }
        return;
    }

    let actual_base = remote_image_base as u64;
    debug!(
        "Successfully allocated memory space! Starting address: 0x{:x}, Size: 0x{:x}",
        actual_base, size_of_image
    );

    // 寫入 PE 標頭
    let mut bytes_written: usize = 0;
    let res = unsafe {
        WriteProcessMemory(
            process_handle,
            remote_image_base,
            frpc_buffer.as_ptr() as *const std::ffi::c_void,
            size_of_headers,
            &mut bytes_written,
        )
    };
    if res == FALSE {
        error!(
            "Failed to write PE header! Error code: {}",
            std::io::Error::last_os_error()
        );
        unsafe {
            CloseHandle(process_handle);
            CloseHandle(thread_handle_host);
        }
        return;
    }
    debug!("Successfully wrote PE header ({} bytes)", bytes_written);

    // 寫入各個區段
    debug!("Starting to write frpc sections to the target process memory...");
    for section in &pe.sections {
        if section.size_of_raw_data == 0 {
            continue;
        }

        let remote_section_addr =
            unsafe { remote_image_base.add(section.virtual_address as usize) };
        let local_ptr = unsafe {
            frpc_buffer
                .as_ptr()
                .add(section.pointer_to_raw_data as usize)
        };

        let mut sec_written: usize = 0;
        let res = unsafe {
            WriteProcessMemory(
                process_handle,
                remote_section_addr,
                local_ptr as *const std::ffi::c_void,
                section.size_of_raw_data as usize,
                &mut sec_written,
            )
        };

        if res == FALSE {
            error!(
                "Failed to write section [{}]! Error code: {}",
                String::from_utf8_lossy(&section.name),
                std::io::Error::last_os_error()
            );
            unsafe {
                CloseHandle(process_handle);
                CloseHandle(thread_handle_host);
            }
            return;
        }
        debug!(
            "Section [{}] written successfully: 0x{:x} <- File offset 0x{:x} ({} bytes)",
            String::from_utf8_lossy(&section.name).trim_matches('\0'),
            remote_section_addr as usize,
            section.pointer_to_raw_data,
            sec_written
        );
    }
    debug!("All sections written successfully!");

    // 修復重定位表
    let delta = actual_base.wrapping_sub(preferred_base);
    debug!("Starting to fix relocation table...");
    debug!(
        "Expected base: 0x{:x}，Actual base: 0x{:x}，Delta: 0x{:x}",
        preferred_base, actual_base, delta
    );

    if delta == 0 {
        debug!("Base is the same, no need to fix the relocation table.");
    } else {
        if let Some((_idx, reloc_dir)) = optional_header.data_directories.data_directories[5] {
            let mut reloc_va = reloc_dir.virtual_address as usize;
            let reloc_size = reloc_dir.size as usize;

            if reloc_va != 0 && reloc_size != 0 {
                debug!(
                    "Found relocation table, VA: 0x{:x}, Size: {} bytes",
                    reloc_va, reloc_size
                );
                let mut current_parsed_size = 0;

                while current_parsed_size < reloc_size {
                    if current_parsed_size + 8 > reloc_size {
                        break;
                    }

                    let file_offset = match pe.sections.iter().find(|s| {
                        reloc_va >= s.virtual_address as usize
                            && reloc_va < (s.virtual_address + s.virtual_size) as usize
                    }) {
                        Some(s) => {
                            s.pointer_to_raw_data as usize + (reloc_va - s.virtual_address as usize)
                        }
                        None => break,
                    };

                    let page_rva = u32::from_le_bytes(
                        frpc_buffer[file_offset..file_offset + 4]
                            .try_into()
                            .unwrap(),
                    ) as usize;
                    let size_of_block = u32::from_le_bytes(
                        frpc_buffer[file_offset + 4..file_offset + 8]
                            .try_into()
                            .unwrap(),
                    ) as usize;

                    if size_of_block == 0 {
                        break;
                    }

                    let entries_count = (size_of_block - 8) / 2;
                    for j in 0..entries_count {
                        let entry_off = file_offset + 8 + j * 2;
                        let entry = u16::from_le_bytes(
                            frpc_buffer[entry_off..entry_off + 2].try_into().unwrap(),
                        );
                        let reloc_type = (entry >> 12) & 0xF;
                        let reloc_offset = (entry & 0x0FFF) as usize;

                        // IMAGE_REL_BASED_DIR64 = 10
                        if reloc_type == 10 {
                            let target_rva = page_rva + reloc_offset;
                            let remote_addr =
                                (actual_base + target_rva as u64) as *mut std::ffi::c_void;

                            let mut old_val: u64 = 0;
                            let mut br: usize = 0;
                            unsafe {
                                ReadProcessMemory(
                                    process_handle,
                                    remote_addr,
                                    &mut old_val as *mut u64 as *mut _,
                                    8,
                                    &mut br,
                                );
                            }

                            let new_val = old_val.wrapping_add(delta);
                            let mut bw: usize = 0;
                            unsafe {
                                WriteProcessMemory(
                                    process_handle,
                                    remote_addr,
                                    &new_val as *const u64 as *const _,
                                    8,
                                    &mut bw,
                                );
                            }
                        }
                    }

                    reloc_va += size_of_block;
                    current_parsed_size += size_of_block;
                }
                debug!("Relocation table fix completed!");
            }
        }
    }

    // 修復 IAT
    debug!("Starting to fix IAT (Import Address Table)...");

    if let Some((_idx, import_dir)) = optional_header.data_directories.data_directories[1] {
        let import_va = import_dir.virtual_address as usize;
        let import_size = import_dir.size as usize;

        if import_va != 0 && import_size != 0 {
            let mut desc_offset = rva_to_file_offset(&pe, import_va).unwrap();
            let mut dll_count = 0;
            let mut total_funcs = 0;
            let mut failed_funcs = 0;

            loop {
                let original_first_thunk = u32::from_le_bytes(
                    frpc_buffer[desc_offset..desc_offset + 4]
                        .try_into()
                        .unwrap(),
                ) as usize;
                let first_thunk = u32::from_le_bytes(
                    frpc_buffer[desc_offset + 16..desc_offset + 20]
                        .try_into()
                        .unwrap(),
                ) as usize;
                let name_rva = u32::from_le_bytes(
                    frpc_buffer[desc_offset + 12..desc_offset + 16]
                        .try_into()
                        .unwrap(),
                ) as usize;

                // 整個 descriptor 全零 = 結束標記
                if original_first_thunk == 0 && first_thunk == 0 && name_rva == 0 {
                    break;
                }

                let name_offset = match rva_to_file_offset(&pe, name_rva) {
                    Some(o) => o,
                    None => {
                        desc_offset += 20;
                        continue;
                    }
                };
                let dll_name = read_cstr(frpc_buffer, name_offset);
                let dll_name_str =
                    String::from_utf8_lossy(&dll_name[..dll_name.len().saturating_sub(1)])
                        .to_string();

                let hmod = unsafe { LoadLibraryA(dll_name.as_ptr()) };
                if hmod.is_null() {
                    error!(
                        "[IAT] Failed to load DLL: {} (Error: {})",
                        dll_name_str,
                        std::io::Error::last_os_error()
                    );
                    desc_offset += 20;
                    continue;
                }
                debug!(
                    "[IAT] Loaded DLL: {} (handle: 0x{:x})",
                    dll_name_str, hmod as usize
                );
                dll_count += 1;

                // 優先使用 OriginalFirstThunk (INT) 來查函式名稱，沒有則用 FirstThunk
                let ilt_rva = if original_first_thunk != 0 {
                    original_first_thunk
                } else {
                    first_thunk
                };

                let mut thunk_idx = 0usize;
                while let Some(ilt_file_off) = rva_to_file_offset(&pe, ilt_rva + thunk_idx * 8) {
                    let thunk_val = u64::from_le_bytes(
                        frpc_buffer[ilt_file_off..ilt_file_off + 8]
                            .try_into()
                            .unwrap(),
                    );
                    if thunk_val == 0 {
                        break;
                    }

                    total_funcs += 1;

                    let proc_addr = if thunk_val & 0x8000000000000000 != 0 {
                        // 按序數 (Ordinal) 匯入
                        let ordinal = (thunk_val & 0xFFFF) as usize;
                        let addr = unsafe { GetProcAddress(hmod, ordinal as *const u8) };
                        if addr.is_none() {
                            error!(
                                "[IAT] Failed to resolve {} ordinal #{}",
                                dll_name_str, ordinal
                            );
                            failed_funcs += 1;
                        }
                        addr
                    } else {
                        // 按名稱匯入（IMAGE_IMPORT_BY_NAME，前 2 bytes 是 Hint，跳過）
                        let func_name_rva = (thunk_val & 0x7FFFFFFF_FFFFFFFF) as usize;
                        let func_name_file_off = match rva_to_file_offset(&pe, func_name_rva + 2) {
                            Some(o) => o,
                            None => {
                                thunk_idx += 1;
                                continue;
                            }
                        };
                        let func_name = read_cstr(frpc_buffer, func_name_file_off);
                        let func_name_str = String::from_utf8_lossy(
                            &func_name[..func_name.len().saturating_sub(1)],
                        )
                        .to_string();
                        let addr = unsafe { GetProcAddress(hmod, func_name.as_ptr()) };
                        if addr.is_none() {
                            error!(
                                "[IAT] Failed to resolve {}!{}!",
                                dll_name_str, func_name_str
                            );
                            failed_funcs += 1;
                        }
                        addr
                    };

                    // 將解析到的函式位址寫入子進程 IAT（FirstThunk 陣列）
                    let iat_remote_addr = (actual_base + (first_thunk + thunk_idx * 8) as u64)
                        as *mut std::ffi::c_void;
                    let addr_val = proc_addr.map(|f| f as usize as u64).unwrap_or(0);

                    let mut bw: usize = 0;
                    unsafe {
                        WriteProcessMemory(
                            process_handle,
                            iat_remote_addr,
                            &addr_val as *const _ as *const _,
                            8,
                            &mut bw,
                        );
                    }

                    thunk_idx += 1;
                }

                desc_offset += 20;
            }

            debug!(
                "IAT fix completed: {} DLLs, {} functions, {} failures",
                dll_count, total_funcs, failed_funcs
            );
            if failed_funcs > 0 {
                error!("Warning: {} functions failed to resolve!", failed_funcs);
            }
        }
    }

    // 切換記憶體保護權限
    debug!("Starting to set memory protection permissions for frpc sections...");
    for section in &pe.sections {
        if section.size_of_raw_data == 0 {
            continue;
        }

        let characteristics = section.characteristics;
        let is_exec = (characteristics & 0x20000000) != 0; // IMAGE_SCN_CNT_CODE
        let is_write = (characteristics & 0x80000000) != 0; // IMAGE_SCN_MEM_WRITE
        let is_read = (characteristics & 0x40000000) != 0; // IMAGE_SCN_MEM_READ

        let protect = match (is_exec, is_write, is_read) {
            (true, false, _) => PAGE_EXECUTE_READ,
            (true, true, _) => 0x40u32, // PAGE_EXECUTE_READWRITE
            (false, true, _) => PAGE_READWRITE,
            _ => 0x02u32, // PAGE_READONLY
        };

        let remote_addr = unsafe { remote_image_base.add(section.virtual_address as usize) };
        let mut old_protect: u32 = 0;

        let res = unsafe {
            VirtualProtectEx(
                process_handle,
                remote_addr,
                section.virtual_size as usize,
                protect,
                &mut old_protect,
            )
        };

        if res == FALSE {
            error!(
                "Failed to change section [{}] permissions! Error code: {}",
                String::from_utf8_lossy(&section.name),
                std::io::Error::last_os_error()
            );
        } else {
            debug!(
                "Section [{}] permissions set to 0x{:x}",
                String::from_utf8_lossy(&section.name).trim_matches('\0'),
                protect
            );
        }
    }
    debug!("Memory protection permissions set.");
    // 用 CreateRemoteThread 啟動 frpc entry point
    // 不再劫持主執行緒上下文，改為在已完整初始化的 stub.exe 進程中開新執行緒
    // 這樣 Windows loader、CRT、kernel32 等全部都已就位
    let remote_entry_point = actual_base + entry_point_rva;
    debug!("Using CreateRemoteThread to start frpc");
    debug!("frpc Entry Point RVA: 0x{:x}", entry_point_rva);
    debug!("frpc Entry Point (remote): 0x{:x}", remote_entry_point);

    // 分配 8MB stack 給 Go runtime（Go 的 goroutine scheduler 需要較大的初始 stack）
    let stack_size = 8 * 1024 * 1024usize;
    let new_stack = unsafe {
        VirtualAllocEx(
            process_handle,
            ptr::null_mut(),
            stack_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };
    if new_stack.is_null() {
        error!(
            "Failed to allocate stack: {}",
            std::io::Error::last_os_error()
        );
        unsafe {
            CloseHandle(process_handle);
            CloseHandle(thread_handle_host);
        }
        return;
    }
    debug!(
        "Allocated stack: base=0x{:x}, size=0x{:x}",
        new_stack as usize, stack_size
    );

    // CreateRemoteThread 在目標進程建立新執行緒，直接跳到 frpc entry point
    // lpStartAddress 型別為 LPTHREAD_START_ROUTINE，即 unsafe extern "system" fn(*mut c_void) -> u32
    // 我們把 frpc entry point 強制轉型塞進去（Go runtime 的 entry 不是這個 signature，
    // 但 Windows 只是把這個位址當 RIP，實際 calling convention 由 Go runtime 自己處理）
    let thread_handle = unsafe {
        CreateRemoteThread(
            process_handle,
            ptr::null(), // 預設安全屬性
            stack_size,  // stack 大小
            Some(std::mem::transmute::<
                u64,
                unsafe extern "system" fn(*mut std::ffi::c_void) -> u32,
            >(remote_entry_point)), // 執行緒起始位址
            ptr::null(), // 傳入參數（frpc 不需要）
            0,           // 立即執行
            ptr::null_mut(), // 不需要 thread ID
        )
    };

    if thread_handle.is_null() {
        error!(
            "CreateRemoteThread failed! Error code: {}",
            std::io::Error::last_os_error()
        );
        unsafe {
            CloseHandle(process_handle);
            CloseHandle(thread_handle_host);
        }
        return;
    }

    // 將 remote_image_base 的 PE header 清除
    let zeros = vec![0u8; 0x1000];
    let mut bytes_written: usize = 0;
    unsafe {
        WriteProcessMemory(
            process_handle,
            remote_image_base,
            zeros.as_ptr() as *const std::ffi::c_void,
            zeros.len(),
            &mut bytes_written,
        );
    }
    debug!(
        "Successfully cleared PE header! Bytes written: 0x{:x}",
        bytes_written
    );

    debug!(
        "Successfully created remote thread! Thread Handle: 0x{:x}",
        thread_handle as usize
    );
    debug!("frpc has been started in the stub.exe process, waiting for the process to finish...");
    info!("FRPC has been started!");

    unsafe {
        let job = CreateJobObjectW(ptr::null(), ptr::null());

        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
        // 父進程結束時，Job 內所有進程也一起結束
        info.BasicLimitInformation.LimitFlags = 0x2000; // JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE

        SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            &info as *const _ as *const _,
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        );

        AssignProcessToJobObject(job, process_handle);
    }

    // 等待整個進程結束（frpc 通常是長駐進程，這裡設 INFINITE）
    let wait_result = unsafe { WaitForSingleObject(process_handle, u32::MAX) };

    let mut exit_code: u32 = 0;
    unsafe {
        GetExitCodeProcess(process_handle, &mut exit_code);
    }

    debug!("wait_result: 0x{:x}", wait_result);
    debug!("exit_code: 0x{:08x} ({})", exit_code, exit_code);

    unsafe {
        CloseHandle(thread_handle);
        CloseHandle(thread_handle_host);
        CloseHandle(process_handle);
    }
}
