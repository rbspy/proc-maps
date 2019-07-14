mod ptrace;
mod protection;

use libc::{pid_t, c_int, c_char};
use std::iter::Iterator;
use std::ffi::CStr;
use std::convert::From;

pub type Pid = pid_t;

const FILE_NAME_BUFFER_LENGTH: usize = 4096;

#[derive(Debug, Clone)]
pub struct MapRange {
    range_start: usize,
    range_end: usize,
    protection: c_int,
    offset: usize,
    vnode: usize,
    pathname: Option<String>,
}

impl MapRange {
    pub fn size(&self) -> usize { self.range_end - self.range_start }
    pub fn start(&self) -> usize { self.range_start }
    pub fn filename(&self) -> &Option<String> { &self.pathname }

    pub fn is_read(&self) -> bool {
        self.protection & protection::VM_PROT_READ != 0
    }
    pub fn is_write(&self) -> bool {
        self.protection & protection::VM_PROT_WRITE != 0
    }
    pub fn is_exec(&self) -> bool {
        self.protection & protection::VM_PROT_EXECUTE != 0
    }
}

impl From<ptrace::vm_entry> for MapRange {
    fn from(vm_entry: ptrace::vm_entry) -> Self {
        let pathname = string_from_cstr_ptr(vm_entry.pve_path);

        Self {
            range_start: vm_entry.pve_start as usize,
            range_end: vm_entry.pve_end as usize,
            protection: vm_entry.pve_prot,
            offset: vm_entry.pve_offset as usize,
            vnode: vm_entry.pve_fileid as usize,
            pathname: pathname,
        }
    }
}

#[derive(Default)]
struct VmEntryIterator {
    current: c_int,
    pid: Pid,
}

impl VmEntryIterator {
    fn new(pid: Pid) -> std::io::Result<Self> {
        ptrace::attach(pid)?;

        Ok(Self { current: 0, pid })
    }
}

impl Drop for VmEntryIterator {
    fn drop(&mut self) {
        ptrace::detach(self.pid);
    }
}

impl Iterator for VmEntryIterator {
    type Item = ptrace::vm_entry;

    fn next(&mut self) -> Option<Self::Item> {
        let Self { current, pid } = *self;
        // If the region was mapped from a file, `pve_path` contains filename.
        let pve_pathlen = 4096;
        let pve_path: [c_char; FILE_NAME_BUFFER_LENGTH] =
            [0; FILE_NAME_BUFFER_LENGTH];

        let entry = Self::Item {
            pve_entry: current,
            pve_path: &pve_path as *const _,
            pve_pathlen: pve_pathlen,
            ..Default::default()
        };

        let result = ptrace::read_vm_entry(pid, entry);

        match result {
            Ok(entry) => {
                self.current = entry.pve_entry;
                Some(entry)
            }
            _ => None
        }
    }
}

fn string_from_cstr_ptr(pointer: *const c_char) -> Option<String> {
    if pointer.is_null() {
        None
    } else {
        unsafe {
            let result = CStr::from_ptr(pointer)
                .to_string_lossy()
                .into_owned();

            if result.len() > 0 {
                Some(result)
            } else {
                None
            }
        }
    }
}

pub fn get_process_maps(pid: Pid) -> std::io::Result<Vec<MapRange>> {
    let iter = VmEntryIterator::new(pid)?;

    Ok(iter.map(MapRange::from).collect())
}

#[test]
fn test_map_from_invoked_binary_present() -> () {
    use std::process::Command;
    let mut child = Command::new("/bin/cat")
        .spawn()
        .expect("failed to execute /bin/cat");


    let maps = get_process_maps(child.id() as Pid).unwrap();

    child.kill();

    let maybe_cat_region = maps
        .iter()
        .find(|x| x.filename() == &Some(String::from("/bin/cat")));

    assert!(
        maybe_cat_region.is_some(),
        "We should have a map from the binary we invoked!"
    );
}

#[test]
fn test_write_xor_execute_policy() -> () {
    use std::process::Command;
    let mut child = Command::new("/bin/cat")
        .spawn()
        .expect("failed to execute /bin/cat");

    let maps = get_process_maps(child.id() as Pid).unwrap();

    child.kill();

    let write_and_exec_regions = maps
        .iter()
        .any(|x| x.is_write() && x.is_exec());

    assert!(!write_and_exec_regions, "W^X violation!");
}
