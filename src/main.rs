use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use log::{debug, info, Level};
use std::io::{Cursor, Read};
use std::mem::size_of;
use windows::core::PCSTR;
use windows::s;
use windows::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, HINSTANCE, MAX_PATH};
use windows::Win32::Globalization::lstrcmpiA;
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Module32First, Module32Next, Process32First, Process32Next,
    MODULEENTRY32, PROCESSENTRY32, TH32CS_SNAPMODULE, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::LibraryLoader::GetModuleFileNameA;
use windows::Win32::System::Memory::{
    VirtualQueryEx, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE, PAGE_EXECUTE_READ,
    PAGE_EXECUTE_READWRITE, PAGE_NOCACHE, PAGE_READONLY, PAGE_READWRITE,
};
use windows::Win32::System::ProcessStatus::{
    K32EnumProcessModulesEx, K32GetModuleBaseNameA, K32GetModuleInformation, LIST_MODULES_ALL,
    MODULEINFO,
};
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_ALL_ACCESS, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
};

pub static SEARCH_STR: &str = "-----BEGIN PUBLIC KEY-----";

fn read_process_memory(
    process_handle: HANDLE,
    addr: usize,
    size: usize,
) -> anyhow::Result<Vec<u8>> {
    let mut buffer = vec![0u8; size];
    unsafe {
        ReadProcessMemory(
            process_handle,
            addr as _,
            buffer.as_mut_ptr() as _,
            size,
            None,
        )
        .ok()?
    };
    Ok(buffer)
}

fn sunday(pattern: &[u8], text: &[u8]) -> Option<usize> {
    let mut i = 0;
    let mut j = 0;
    let mut skip = [pattern.len() + 1; 256];
    for (i, &c) in pattern.iter().enumerate() {
        skip[c as usize] = pattern.len() - i;
    }
    while i < text.len() - pattern.len() {
        j = 0;
        while j < pattern.len() && pattern[j] == text[i + j] {
            j += 1;
        }
        if j == pattern.len() {
            return Some(i);
        }
        i += skip[text[i + pattern.len()] as usize];
    }
    None
}

unsafe fn search_memory(
    pattern: &[u8],
    process_handle: HANDLE,
    start_addr: usize,
) -> anyhow::Result<usize> {
    let mut mem_basic_info = MEMORY_BASIC_INFORMATION::default();
    let mut start_addr = start_addr;
    loop {
        let ret = VirtualQueryEx(
            process_handle,
            Some(start_addr as _),
            &mut mem_basic_info,
            size_of::<MEMORY_BASIC_INFORMATION>(),
        );
        if ret == 0 {
            GetLastError().ok()?;
        } else {
        }

        if (mem_basic_info.Protect == PAGE_READONLY
            || mem_basic_info.Protect == PAGE_READWRITE
            || mem_basic_info.Protect == PAGE_EXECUTE_READ
            || mem_basic_info.Protect == PAGE_EXECUTE_READWRITE)
            && mem_basic_info.RegionSize != 1
        {
            let buf_length =
                mem_basic_info.BaseAddress as usize + mem_basic_info.RegionSize - start_addr;
            if buf_length > 0xF000000 {
                start_addr += mem_basic_info.RegionSize;
                continue;
            }
            let mut buf = vec![0u8; buf_length];
            ReadProcessMemory(
                process_handle,
                start_addr as _,
                buf.as_mut_ptr() as _,
                buf_length,
                None,
            )
            .ok()?;
            if let Some(idx) = sunday(pattern, &buf) {
                return Ok(start_addr + idx);
            }
        }
        start_addr += mem_basic_info.RegionSize;
    }
}

fn main() -> anyhow::Result<()> {
    simple_logger::init_with_level(Level::Info)?;

    unsafe {
        let handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)?;
        let mut entry = PROCESSENTRY32::default();
        entry.dwSize = size_of::<PROCESSENTRY32>() as u32;
        Process32First(handle, &mut entry).ok()?;

        loop {
            if lstrcmpiA(PCSTR(entry.szExeFile.as_ptr() as _), s!("WeChat.exe")) == 0 {
                debug!("found target process pid={}", entry.th32ProcessID);
                break;
            }
            Process32Next(handle, &mut entry).ok()?;
        }

        let process_handle = OpenProcess(PROCESS_ALL_ACCESS, false, entry.th32ProcessID)?;
        debug!("open process success pHandle={:?}", process_handle);
        let mut wechatwin_base_addr = 0;
        let mut instance = [HINSTANCE::default(); 1024];
        let mut lpcb_needed = 0;
        K32EnumProcessModulesEx(
            process_handle,
            instance.as_mut_ptr(),
            size_of::<HINSTANCE>() as u32 * 1024,
            &mut lpcb_needed,
            LIST_MODULES_ALL,
        )
        .ok()?;
        debug!("lpcb_needed={}", lpcb_needed);
        for module in instance.iter() {
            let mut info = MODULEINFO::default();
            debug!("module={:?}", module);
            K32GetModuleInformation(
                process_handle,
                *module,
                &mut info,
                size_of::<MODULEINFO>() as _,
            )
            .ok()?;
            let mut name = vec![0 as u8; MAX_PATH as usize];
            let length = K32GetModuleBaseNameA(process_handle, *module, &mut name);
            let name = String::from_utf8(name[..length as usize].to_vec())?;
            if name == "WeChatWin.dll" {
                wechatwin_base_addr = info.lpBaseOfDll as usize;
                debug!("WeChatWin=0x{:x}", wechatwin_base_addr);
                break;
            }
        }

        let mut mem_basic_info = MEMORY_BASIC_INFORMATION::default();
        let mut start_addr = 0x327000;
        let reference;
        loop {
            let pubkey_addr = search_memory(SEARCH_STR.as_bytes(), process_handle, start_addr)?;
            debug!("pubkey_addr=0x{:x}", pubkey_addr);
            start_addr = pubkey_addr + 4;

            let mut buf = Vec::new();
            buf.write_u32::<LittleEndian>(pubkey_addr as u32)?;
            debug!("buf={:?}", buf);
            reference = match search_memory(&buf, process_handle, wechatwin_base_addr) {
                Ok(reference) => reference,
                Err(_) => continue,
            };
            debug!("reference=0x{:x}", reference);
            break;
        }

        let mut cursor = Cursor::new(read_process_memory(process_handle, reference - 0x5c, 4)?);
        let username_length = cursor.read_u32::<LittleEndian>()?;
        let username =
            read_process_memory(process_handle, reference - 0x6c, username_length as usize)?;
        info!("username={}", String::from_utf8(username)?);

        let mut cursor = Cursor::new(read_process_memory(process_handle, reference - 0x44, 4)?);
        let wxid_length = cursor.read_u32::<LittleEndian>()?;
        let mut cursor = Cursor::new(read_process_memory(process_handle, reference - 0x54, 4)?);
        let wxid_addr = cursor.read_u32::<LittleEndian>()?;

        let wxid = read_process_memory(process_handle, wxid_addr as usize, wxid_length as usize)?;
        info!("wxid={}", String::from_utf8(wxid)?);

        let mobile_type_length =
            Cursor::new(read_process_memory(process_handle, reference - 0xc, 4)?)
                .read_u32::<LittleEndian>()?;
        let mobile_type = read_process_memory(
            process_handle,
            reference - 0x1c,
            mobile_type_length as usize,
        )?;
        info!("mobile_type={}", String::from_utf8(mobile_type)?);

        // let tel_length = Cursor::new(read_process_memory(process_handle, reference - 0x47c, 4)?).read_u32::<LittleEndian>()?;
        // let tel = read_process_memory(process_handle, reference - 0x48c, tel_length as usize)?;
        // info!("tel={}", String::from_utf8(tel)?);

        let sqlite_key_length =
            Cursor::new(read_process_memory(process_handle, reference - 0x8c, 4)?)
                .read_u32::<LittleEndian>()?;
        let sqlite_key_addr =
            Cursor::new(read_process_memory(process_handle, reference - 0x90, 4)?)
                .read_u32::<LittleEndian>()?;
        let sqlite_key = read_process_memory(
            process_handle,
            sqlite_key_addr as usize,
            sqlite_key_length as usize,
        )?;
        // info!("sqlite_key={:?}", sqlite_key);
        let mut output = String::new();
        output += "[";
        for byte in sqlite_key.iter() {
            output += &format!("0x{:02x},", byte);
        }
        output += "]";
        info!("sqlite_key={}", output);

        let pubkey_length = Cursor::new(read_process_memory(process_handle, reference + 0x10, 4)?)
            .read_u32::<LittleEndian>()?;
        let pubkey_addr = Cursor::new(read_process_memory(process_handle, reference, 4)?)
            .read_u32::<LittleEndian>()?;
        let pubkey =
            read_process_memory(process_handle, pubkey_addr as usize, pubkey_length as usize)?;
        info!("pubkey={:?}", String::from_utf8(pubkey)?);

        let private_key_length =
            Cursor::new(read_process_memory(process_handle, reference + 0x28, 4)?)
                .read_u32::<LittleEndian>()?;
        let private_key_addr =
            Cursor::new(read_process_memory(process_handle, reference + 0x18, 4)?)
                .read_u32::<LittleEndian>()?;
        let private_key = read_process_memory(
            process_handle,
            private_key_addr as usize,
            private_key_length as usize,
        )?;
        info!("private_key={:?}", String::from_utf8(private_key)?);

        CloseHandle(handle);
        CloseHandle(process_handle);

        Ok(())
    }
}
