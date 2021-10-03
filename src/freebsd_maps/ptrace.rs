use libc::{c_int, c_long, c_char, uint32_t};
use libc::{waitpid, WIFSTOPPED, PT_ATTACH, PT_DETACH, PT_VM_ENTRY};
use std::{io, ptr};

use super::Pid;
use super::bindings::ptrace_vm_entry;

pub type vm_entry = ptrace_vm_entry;

impl Default for vm_entry {
    fn default() -> Self {
        Self {
            pve_entry: 0,
            pve_timestamp: 0,
            pve_start: 0,
            pve_end: 0,
            pve_offset: 0,
            pve_prot: 0,
            pve_pathlen: 0,
            pve_fileid: 0,
            pve_fsid: 0,
            pve_path: ptr::null_mut(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct VmEntry {
    pub pve_entry: i32,
    pub pve_timestamp: i32,
    pub pve_start: u64,
    pub pve_end: u64,
    pub pve_offset: u64,
    pub pve_prot: u32,
    pub pve_pathlen: u32,
    pub pve_fileid: i64,
    pub pve_fsid: u32,
    pub pve_path: Option<String>,
}

impl From<vm_entry> for VmEntry {
    fn from(vm_entry: vm_entry) -> Self {
        Self {
            pve_entry: vm_entry.pve_entry,
            pve_timestamp: vm_entry.pve_timestamp,
            pve_start: vm_entry.pve_start,
            pve_end: vm_entry.pve_end,
            pve_offset: vm_entry.pve_offset,
            pve_prot: vm_entry.pve_prot,
            pve_pathlen: vm_entry.pve_pathlen,
            pve_fileid: vm_entry.pve_fileid,
            pve_fsid: vm_entry.pve_fsid,
            pve_path: string_from_cstr_ptr(vm_entry.pve_path),
        }
    }
}

impl Default for VmEntry {
    fn default() -> Self {
        Self {
            pve_entry: 0,
            pve_timestamp: 0,
            pve_start: 0,
            pve_end: 0,
            pve_offset: 0,
            pve_prot: 0,
            pve_pathlen: 0,
            pve_fileid: 0,
            pve_fsid: 0,
            pve_path: None,
        }
    }
}

extern "C" {
    fn ptrace(request: c_int,
              pid: Pid,
              vm_entry: *const vm_entry,
              data: c_int) -> c_int;
}

/// Attach to a process `pid` and wait for the process to be stopped.
pub fn attach(pid: Pid) -> io::Result<()> {
    let attach_status = unsafe {
        ptrace(PT_ATTACH, pid, ptr::null(), 0)
    };

    if attach_status == -1 {
        return Err(io::Error::last_os_error())
    }

    let mut wait_status = 0;

    let stopped = unsafe {
        waitpid(pid, &mut wait_status as *mut _, 0);
        WIFSTOPPED(wait_status)
    };

    if !stopped {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Detach from the process `pid`.
pub fn detach(pid: Pid) -> io::Result<()> {
    let detach_status = unsafe {
        ptrace(PT_DETACH, pid, ptr::null(), 0)
    };

    if detach_status == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Read virtual memory entry
pub fn read_vm_entry(pid: Pid, vm_entry: vm_entry) -> io::Result<vm_entry> {
    let result = unsafe {
        ptrace(PT_VM_ENTRY, pid, &vm_entry as *const _, 0)
    };

    if result == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(vm_entry)
    }
}
