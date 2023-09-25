use std;
use std::ffi::{OsStr, OsString};
use std::io;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::ptr::null_mut;
use winapi::shared::minwindef::{DWORD, FALSE};
use winapi::um::dbghelp::{
    SymCleanup, SymFromNameW, SymInitializeW, SymLoadModuleExW, SymUnloadModule64, SYMBOL_INFOW,
};
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::memoryapi::VirtualQueryEx;
use winapi::um::processthreadsapi::OpenProcess;
use winapi::um::sysinfoapi::{GetSystemInfo, SYSTEM_INFO};
use winapi::um::tlhelp32::{CreateToolhelp32Snapshot, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32};
use winapi::um::tlhelp32::{Module32FirstW, Module32NextW, MODULEENTRY32W};
use winapi::um::winnt::{HANDLE, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};
use winapi::um::winnt::{MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_IMAGE};
use winapi::um::winnt::{PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE};
use winapi::um::winnt::{PAGE_EXECUTE_WRITECOPY, PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY};

use MapRangeImpl;

pub type Pid = u32;

#[derive(Debug, Clone, PartialEq)]
pub struct MapRange {
    base_addr: usize,
    base_size: usize,
    pathname: Option<PathBuf>,
    read: bool,
    write: bool,
    exec: bool,
}

impl MapRangeImpl for MapRange {
    fn size(&self) -> usize {
        self.base_size
    }
    fn start(&self) -> usize {
        self.base_addr
    }
    fn filename(&self) -> Option<&Path> {
        self.pathname.as_deref()
    }
    fn is_exec(&self) -> bool {
        self.exec
    }
    fn is_write(&self) -> bool {
        self.write
    }
    fn is_read(&self) -> bool {
        self.read
    }
}

pub fn get_process_maps(pid: Pid) -> io::Result<Vec<MapRange>> {
    let mut modules = get_process_modules(pid)?;
    modules.sort_by_key(|m| m.base_addr);
    let page_ranges = get_process_page_ranges(pid)?;
    let mut maps = Vec::<MapRange>::with_capacity(page_ranges.len());
    for page_range in page_ranges {
        maps.push(MapRange {
            base_addr: page_range.base_addr,
            base_size: page_range.base_size,
            pathname: find_pathname(&modules, &page_range),
            read: page_range.read,
            write: page_range.write,
            exec: page_range.exec,
        });
    }
    Ok(maps)
}

/// Find pathname of module containing this page range, if any.
/// Assumes that modules are sorted by base address and do not overlap.
fn find_pathname(modules: &Vec<Module>, page_range: &PageRange) -> Option<PathBuf> {
    if !page_range.image {
        return None;
    }

    // Find module with the same base address or that could contain it.
    let module: &Module = match modules.binary_search_by_key(&page_range.base_addr, |m| m.base_addr)
    {
        Ok(i) => &modules[i],
        Err(0) => return None,
        Err(i) => &modules[i - 1],
    };

    if module.contains(page_range) {
        Some(module.pathname.clone())
    } else {
        None
    }
}

/// The memory region where an executable or DLL was loaded.
struct Module {
    base_addr: usize,
    base_size: usize,
    pathname: PathBuf,
}

impl Module {
    fn contains(&self, page_range: &PageRange) -> bool {
        self.base_addr <= page_range.base_addr
            && page_range.base_addr + page_range.base_size <= self.base_addr + self.base_size
    }
}

/// Uses the Tool Help API to list all modules.
fn get_process_modules(pid: Pid) -> io::Result<Vec<Module>> {
    unsafe {
        let handle = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }

        let mut module = MODULEENTRY32W {
            ..Default::default()
        };
        module.dwSize = std::mem::size_of_val(&module) as u32;

        let mut success = Module32FirstW(handle, &mut module);
        if success == 0 {
            CloseHandle(handle);
            return Err(io::Error::last_os_error());
        }

        let mut vec = Vec::new();
        while success != 0 {
            vec.push(Module {
                base_addr: module.modBaseAddr as usize,
                base_size: module.modBaseSize as usize,
                pathname: PathBuf::from(wstr_to_string(&module.szExePath)),
            });

            success = Module32NextW(handle, &mut module);
        }
        CloseHandle(handle);
        Ok(vec)
    }
}

/// A range of pages in the virtual address space of a process.
struct PageRange {
    base_addr: usize,
    base_size: usize,
    image: bool,
    read: bool,
    write: bool,
    exec: bool,
}

/// Uses `VirtualQueryEx` to get info on *every* memory page range in the process.
fn get_process_page_ranges(pid: Pid) -> io::Result<Vec<PageRange>> {
    unsafe {
        let mut sysinfo = SYSTEM_INFO {
            ..Default::default()
        };
        GetSystemInfo(&mut sysinfo);

        let mut vec = Vec::new();

        let process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid as DWORD);
        if process == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }

        let mut meminfo = MEMORY_BASIC_INFORMATION {
            ..Default::default()
        };
        let buffer_size = std::mem::size_of_val(&meminfo);

        let mut address = sysinfo.lpMinimumApplicationAddress;
        while address < sysinfo.lpMaximumApplicationAddress {
            let bytes_returned = VirtualQueryEx(process, address, &mut meminfo, buffer_size);
            if bytes_returned != buffer_size {
                CloseHandle(process);
                return Err(io::Error::last_os_error());
            }

            if meminfo.State & MEM_COMMIT != 0 {
                // Skip free pages and pages that are reserved but not allocated.
                vec.push(PageRange {
                    base_addr: meminfo.BaseAddress as usize,
                    base_size: meminfo.RegionSize as usize,
                    image: meminfo.Type & MEM_IMAGE != 0,
                    read: meminfo.Protect
                        & (PAGE_EXECUTE_READ
                            | PAGE_EXECUTE_READWRITE
                            | PAGE_EXECUTE_WRITECOPY
                            | PAGE_READONLY
                            | PAGE_READWRITE
                            | PAGE_WRITECOPY)
                        != 0,
                    write: meminfo.Protect & (PAGE_EXECUTE_READWRITE | PAGE_READWRITE) != 0,
                    exec: meminfo.Protect
                        & (PAGE_EXECUTE
                            | PAGE_EXECUTE_READ
                            | PAGE_EXECUTE_READWRITE
                            | PAGE_EXECUTE_WRITECOPY)
                        != 0,
                });
            }

            address = (meminfo.BaseAddress as *mut u8).add(meminfo.RegionSize).cast(); // as winapi::um::winnt::PVOID;
        }

        CloseHandle(process);
        Ok(vec)
    }
}

// The rest of this code is utilities for loading windows symbols.
// This uses the dbghelp win32 api to load the symbols for a process,
// since just parsing the PE file with goblin isn't sufficient (symbols
// can be stored in a separate PDB file on Windows)
pub struct SymbolLoader {
    pub process: HANDLE,
}

pub struct SymbolModule<'a> {
    pub parent: &'a SymbolLoader,
    pub filename: &'a Path,
    pub base: u64,
}

impl SymbolLoader {
    pub fn new(pid: Pid) -> io::Result<Self> {
        unsafe {
            let process = OpenProcess(PROCESS_VM_READ, FALSE, pid as DWORD);
            if process == INVALID_HANDLE_VALUE {
                return Err(io::Error::last_os_error());
            }
            if SymInitializeW(process, null_mut(), FALSE) == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Self { process })
        }
    }

    pub fn address_from_name(&self, name: &str) -> io::Result<(u64, u64)> {
        // Need to allocate extra space for the SYMBOL_INFO structure, otherwise segfaults
        let size = std::mem::size_of::<SYMBOL_INFOW>() + 256;
        let buffer = vec![0; size];
        let info: *mut SYMBOL_INFOW = buffer.as_ptr() as *mut SYMBOL_INFOW;
        unsafe {
            (*info).SizeOfStruct = size as u32;
            if SymFromNameW(self.process, string_to_wstr(name).as_ptr(), info) == 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(((*info).ModBase, (*info).Address))
        }
    }

    /// Loads symbols for filename, returns a SymbolModule structure that must be kept alive
    pub fn load_module<'a>(&'a self, filename: &'a Path) -> io::Result<SymbolModule<'a>> {
        unsafe {
            let base = SymLoadModuleExW(
                self.process,
                null_mut(),
                path_to_wstr(filename).as_ptr(),
                null_mut(),
                0,
                0,
                null_mut(),
                0,
            );
            if base == 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(SymbolModule {
                parent: self,
                filename,
                base,
            })
        }
    }
}

impl Drop for SymbolLoader {
    fn drop(&mut self) {
        unsafe {
            SymCleanup(self.process);
            CloseHandle(self.process);
        }
    }
}

impl<'a> Drop for SymbolModule<'a> {
    fn drop(&mut self) {
        unsafe {
            SymUnloadModule64(self.parent.process, self.base);
        }
    }
}

fn wstr_to_string(full: &[u16]) -> OsString {
    let len = full.iter().position(|&x| x == 0).unwrap_or(full.len());
    OsString::from_wide(&full[..len])
}

fn string_to_wstr(val: &str) -> Vec<u16> {
    OsStr::new(val)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn path_to_wstr(val: &Path) -> Vec<u16> {
    OsStr::new(val)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}
