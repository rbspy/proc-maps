use anyhow::Error;
use libc::{c_int, pid_t};
use libproc::libproc::proc_pid::regionfilename;
use mach2;
use mach2::kern_return::{kern_return_t, KERN_SUCCESS};
use mach2::mach_types::vm_task_entry_t;
use mach2::message::mach_msg_type_number_t;
use mach2::port::{mach_port_name_t, mach_port_t, MACH_PORT_NULL};
use mach2::vm_region::{
    vm_region_basic_info_data_64_t, vm_region_extended_info, vm_region_extended_info_data_t,
    vm_region_info_t, SM_EMPTY, VM_REGION_BASIC_INFO_64, VM_REGION_EXTENDED_INFO,
};
use mach2::vm_types::{mach_vm_address_t, mach_vm_size_t};
use std;
use std::ffi::{CStr, OsStr};
use std::io;
use std::mem;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use crate::MapRangeImpl;

mod dyld_bindings;
use self::dyld_bindings::{
    dyld_all_image_infos, dyld_image_info, mach_header_64, segment_command_64, task_dyld_info,
};

pub type Pid = pid_t;

#[derive(Debug, Clone)]
pub struct MapRange {
    size: mach_vm_size_t,
    info: vm_region_basic_info_data_64_t,
    start: mach_vm_address_t,
    #[allow(dead_code)]
    count: mach_msg_type_number_t,
    filename: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct Symbol {
    pub value: Option<usize>,
    pub typ: String,
    pub name: String,
}

fn parse_nm_output(output: &str) -> Vec<Symbol> {
    let mut vec = vec![];
    for line in output.split('\n') {
        let split: Vec<&str> = line.split_whitespace().collect();
        let sym = if split.len() == 2 {
            Symbol {
                value: None,
                typ: split[0].to_string(),
                name: split[1].to_string(),
            }
        } else if split.len() == 3 {
            let value = usize::from_str_radix(split[0], 16).unwrap();
            Symbol {
                value: Some(value),
                typ: split[1].to_string(),
                name: split[2].to_string(),
            }
        } else {
            continue;
        };
        vec.push(sym);
    }
    vec
}

pub fn get_symbols(filename: &str) -> Result<Vec<Symbol>, Error> {
    let output = std::process::Command::new("nm").arg(filename).output()?;
    Ok(parse_nm_output(&String::from_utf8_lossy(&output.stdout)))
}

impl MapRangeImpl for MapRange {
    fn size(&self) -> usize {
        self.size as usize
    }
    fn start(&self) -> usize {
        self.start as usize
    }
    fn filename(&self) -> Option<&Path> {
        self.filename.as_deref()
    }

    fn is_exec(&self) -> bool {
        self.info.protection & mach2::vm_prot::VM_PROT_EXECUTE != 0
    }
    fn is_write(&self) -> bool {
        self.info.protection & mach2::vm_prot::VM_PROT_WRITE != 0
    }
    fn is_read(&self) -> bool {
        self.info.protection & mach2::vm_prot::VM_PROT_READ != 0
    }
}

impl MapRange {
    fn end(&self) -> mach_vm_address_t {
        self.start + self.size as mach_vm_address_t
    }
}

/*
 * The way the `mach_vm_region` API works is a bit weird -- you give it an address, and then it
 * returns the first memory map in the process **after** that address. So we start by passing it `1`
 * to get the first memory map in the process, pass the end of that memory map to get the second
 * memory map, etc.
 */
pub fn get_process_maps(pid: Pid) -> io::Result<Vec<MapRange>> {
    let task = task_for_pid(pid)?;
    let init_region = match mach_vm_region(pid, task, 1) {
        Some(r) => r,
        None => return Ok(vec![]),
    };
    let mut vec = vec![];
    let mut region = init_region.clone();
    vec.push(init_region);
    loop {
        match mach_vm_region(pid, task, region.end()) {
            Some(r) => {
                vec.push(r.clone());
                region = r;
            }
            _ => return Ok(vec),
        }
    }
}

fn mach_vm_region(
    pid: Pid,
    target_task: mach_port_name_t,
    mut address: mach_vm_address_t,
) -> Option<MapRange> {
    let mut count = mem::size_of::<vm_region_basic_info_data_64_t>() as mach_msg_type_number_t;
    let mut object_name: mach_port_t = 0;
    let mut size = unsafe { mem::zeroed::<mach_vm_size_t>() };
    let mut info = unsafe { mem::zeroed::<vm_region_basic_info_data_64_t>() };
    let result = unsafe {
        mach2::vm::mach_vm_region(
            target_task as vm_task_entry_t,
            &mut address,
            &mut size,
            VM_REGION_BASIC_INFO_64,
            &mut info as *mut vm_region_basic_info_data_64_t as vm_region_info_t,
            &mut count,
            &mut object_name,
        )
    };
    if result != KERN_SUCCESS {
        return None;
    }
    // `proc_regionfilename` (via `regionfilename`) is unreliable for anonymous regions. For an
    // address that falls in a region with no backing file it often succeeds and returns the path of
    // a neighboring file-backed region instead of failing. `vmmap` avoids this by inspecting the
    // region's share mode, so we do the same here and only trust the filename when the region is not
    // anonymous.
    let is_anonymous = mach_vm_region_share_mode(target_task, address) == Some(SM_EMPTY);
    let filename = if is_anonymous {
        None
    } else {
        match regionfilename(pid, address) {
            Ok(s) => Some(PathBuf::from(s.as_str())),
            _ => None,
        }
    };
    Some(MapRange {
        size,
        info,
        start: address,
        count,
        filename,
    })
}

/// Returns the share mode (one of the `mach2::vm_region::SM_*` constants) for the region that
/// starts at `address`, or `None` if the extended region info could not be retrieved. This mirrors
/// the `SM=` column shown by `vmmap` and lets us tell anonymous regions (`SM_EMPTY`) apart from
/// file-backed ones.
fn mach_vm_region_share_mode(
    target_task: mach_port_name_t,
    address: mach_vm_address_t,
) -> Option<u8> {
    let mut address = address;
    let mut size = unsafe { mem::zeroed::<mach_vm_size_t>() };
    let mut object_name: mach_port_t = 0;
    let mut count = vm_region_extended_info::count();
    let mut info = unsafe { mem::zeroed::<vm_region_extended_info_data_t>() };
    let result = unsafe {
        mach2::vm::mach_vm_region(
            target_task as vm_task_entry_t,
            &mut address,
            &mut size,
            VM_REGION_EXTENDED_INFO,
            &mut info as *mut vm_region_extended_info_data_t as vm_region_info_t,
            &mut count,
            &mut object_name,
        )
    };
    if result != KERN_SUCCESS {
        return None;
    }
    Some(info.share_mode)
}

pub fn task_for_pid(pid: Pid) -> io::Result<mach_port_name_t> {
    let mut task: mach_port_name_t = MACH_PORT_NULL;
    // sleep for 10ms to make sure we don't get into a race between `task_for_pid` and execing a new
    // process. Races here can freeze the OS because of a Mac kernel bug on High Sierra.
    // See https://jvns.ca/blog/2018/01/28/mac-freeze/ for more.
    std::thread::sleep(std::time::Duration::from_millis(10));
    unsafe {
        let result =
            mach2::traps::task_for_pid(mach2::traps::mach_task_self(), pid as c_int, &mut task);
        if result != KERN_SUCCESS {
            return Err(task_for_pid_error(pid, result));
        }
    }

    Ok(task)
}

fn task_for_pid_error(pid: Pid, result: kern_return_t) -> io::Error {
    let mach_error = unsafe {
        let error = libc::mach_error_string(result);
        if error.is_null() {
            "unknown Mach error".to_string()
        } else {
            CStr::from_ptr(error).to_string_lossy().into_owned()
        }
    };
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!(
            "task_for_pid failed for pid {pid}: {mach_error} ({result}). \
             On macOS, reading another process's maps usually requires running as root, e.g. with sudo."
        ),
    )
}

#[derive(Debug, Clone)]
pub struct DyldInfo {
    pub filename: PathBuf,
    pub address: usize,
    pub file_mod_date: usize,
    pub segment: segment_command_64,
}

/// Returns basic information on modules loaded up by dyld. This lets
/// us get the filename/address of the system Ruby or Python frameworks for instance.
/// (which won't appear as a separate entry in vm_regions returned by get_process_maps)
pub fn get_dyld_info(pid: Pid) -> io::Result<Vec<DyldInfo>> {
    // Adapted from :
    // https://stackoverflow.com/questions/4309117/determining-programmatically-what-modules-are-loaded-in-another-process-os-x
    // https://blog.lse.epita.fr/articles/82-playing-with-mach-os-and-dyld.html

    // This gets addresses to TEXT sections ... but we really want addresses to DATA
    // this is a good start though
    // hmm
    use mach2::task::task_info;
    use mach2::task_info::{task_info_t, TASK_DYLD_INFO};

    let mut vec = Vec::new();
    let mut budget = DyldResourceBudget::default();
    let task = task_for_pid(pid)?;

    // Note: this seems to require macOS MAC_OS_X_VERSION_10_6 or greater
    // https://chromium.googlesource.com/breakpad/breakpad/+/master/src/client/mac/handler/dynamic_images.cc#388
    let mut dyld_info = task_dyld_info {
        all_image_info_addr: 0,
        all_image_info_size: 0,
        all_image_info_format: 0,
    };

    const TASK_DYLD_INFO_COUNT: mach_msg_type_number_t = (mem::size_of::<task_dyld_info>()
        / mem::size_of::<mach2::vm_types::natural_t>())
        as mach_msg_type_number_t;
    let mut count = TASK_DYLD_INFO_COUNT;
    unsafe {
        if task_info(
            task,
            TASK_DYLD_INFO,
            &mut dyld_info as *mut task_dyld_info as task_info_t,
            &mut count,
        ) != KERN_SUCCESS
        {
            return Err(io::Error::last_os_error());
        }
    }

    // Read in the dyld_all_image_infos information here.
    let mut image_infos = dyld_all_image_infos::default();
    let mut read_len = std::mem::size_of_val(&image_infos) as mach_vm_size_t;

    let result = unsafe {
        // While we could use the read_process_memory crate for this, this adds a dependency
        // for something that is pretty trivial
        vm_read_overwrite(
            task,
            dyld_info.all_image_info_addr,
            read_len,
            (&mut image_infos) as *mut dyld_all_image_infos as mach_vm_address_t,
            &mut read_len,
        )
    };
    if result != KERN_SUCCESS {
        return Err(io::Error::last_os_error());
    }

    // copy the infoArray element of dyld_all_image_infos over
    if image_infos.infoArrayCount > MAX_DYLD_IMAGE_COUNT {
        return Err(invalid_data(format!(
            "dyld reported {} images, which exceeds the limit of {MAX_DYLD_IMAGE_COUNT}",
            image_infos.infoArrayCount
        )));
    }
    let mut modules = vec![dyld_image_info::default(); image_infos.infoArrayCount as usize];
    let mut read_len = (std::mem::size_of::<dyld_image_info>()
        * image_infos.infoArrayCount as usize) as mach_vm_size_t;
    let result = unsafe {
        vm_read_overwrite(
            task,
            image_infos.infoArray as mach_vm_address_t,
            read_len,
            modules.as_mut_ptr() as mach_vm_address_t,
            &mut read_len,
        )
    };
    if result != KERN_SUCCESS {
        return Err(io::Error::last_os_error());
    }

    for module in modules {
        let mut read_len = 512_u64;
        let mut image_filename = [0_u8; 512];
        let result = unsafe {
            vm_read_overwrite(
                task,
                module.imageFilePath as mach_vm_address_t,
                read_len,
                image_filename.as_mut_ptr() as mach_vm_address_t,
                &mut read_len,
            )
        };
        if result != KERN_SUCCESS {
            return Err(io::Error::last_os_error());
        }

        let filename =
            path_from_c_buffer(&image_filename[..(read_len as usize).min(image_filename.len())]);

        // read in the mach header
        let mut header = mach_header_64::default();
        let mut read_len = std::mem::size_of_val(&header) as mach_vm_size_t;
        let result = unsafe {
            // While we could use the read_process_memory crate for this, this adds a dependency
            // for something that is pretty trivial
            vm_read_overwrite(
                task,
                module.imageLoadAddress as u64,
                read_len,
                (&mut header) as *mut mach_header_64 as mach_vm_address_t,
                &mut read_len,
            )
        };
        if result != KERN_SUCCESS {
            return Err(io::Error::last_os_error());
        }

        if header.sizeofcmds > MAX_SIZEOFCMDS {
            return Err(invalid_data(format!(
                "image at {:#x} has {} bytes of load commands, which exceeds the limit of \
                 {MAX_SIZEOFCMDS}",
                module.imageLoadAddress as usize, header.sizeofcmds
            )));
        }
        budget.add_load_command_bytes(header.sizeofcmds as usize)?;
        let commands_address = (module.imageLoadAddress as mach_vm_address_t)
            .checked_add(std::mem::size_of_val(&header) as mach_vm_address_t)
            .ok_or_else(|| invalid_data("image load address overflows".to_string()))?;
        let mut commands_buffer = vec![0_u8; header.sizeofcmds as usize];
        let mut read_len = mach_vm_size_t::from(header.sizeofcmds);
        let result = unsafe {
            vm_read_overwrite(
                task,
                commands_address,
                read_len,
                commands_buffer.as_mut_ptr() as mach_vm_address_t,
                &mut read_len,
            )
        };
        if result != KERN_SUCCESS {
            return Err(io::Error::last_os_error());
        }

        commands_buffer.truncate(read_len as usize);

        let segments = parse_segments(
            &commands_buffer,
            header.ncmds,
            module.imageLoadAddress as u64,
        );
        budget.add_segments(segments.len())?;
        for segment in segments {
            vec.push(DyldInfo {
                filename: filename.clone(),
                address: module.imageLoadAddress as usize,
                file_mod_date: module.imageFileModDate,
                segment,
            });
        }
    }
    Ok(vec)
}

/// Upper bound on the number of images we'll accept from a target's `dyld_all_image_infos`.
/// Real processes load a few thousand at most; this guards against huge allocations driven by a
/// corrupt or hostile target.
const MAX_DYLD_IMAGE_COUNT: u32 = 1 << 16;

/// Upper bound on the size of an image's load commands, for the same reason.
const MAX_SIZEOFCMDS: u32 = 16 * 1024 * 1024;

/// Aggregate bounds prevent a target from multiplying the generous per-image limits into
/// excessive work or output allocations by reporting many images with large command buffers.
const MAX_TOTAL_SIZEOFCMDS: usize = 256 * 1024 * 1024;
const MAX_DYLD_SEGMENT_COUNT: usize = 1 << 17;

#[derive(Default)]
struct DyldResourceBudget {
    load_command_bytes: usize,
    segment_count: usize,
}

impl DyldResourceBudget {
    fn add_load_command_bytes(&mut self, amount: usize) -> io::Result<()> {
        add_to_budget(
            &mut self.load_command_bytes,
            amount,
            MAX_TOTAL_SIZEOFCMDS,
            "dyld load command bytes",
        )
    }

    fn add_segments(&mut self, amount: usize) -> io::Result<()> {
        add_to_budget(
            &mut self.segment_count,
            amount,
            MAX_DYLD_SEGMENT_COUNT,
            "dyld segments",
        )
    }
}

fn add_to_budget(total: &mut usize, amount: usize, limit: usize, resource: &str) -> io::Result<()> {
    let new_total = total
        .checked_add(amount)
        .ok_or_else(|| invalid_data(format!("total {resource} overflowed")))?;
    if new_total > limit {
        return Err(invalid_data(format!(
            "total {resource} ({new_total}) exceeds the limit of {limit}"
        )));
    }
    *total = new_total;
    Ok(())
}

fn invalid_data(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// Converts a buffer holding a NUL-terminated path into a `PathBuf`. The buffer is read from
/// another process and might not contain a NUL, in which case the whole buffer is used.
fn path_from_c_buffer(buffer: &[u8]) -> PathBuf {
    let len = buffer.iter().position(|&b| b == 0).unwrap_or(buffer.len());
    PathBuf::from(OsStr::from_bytes(&buffer[..len]))
}

const LC_SEGMENT_64: u32 = 0x19;
const LOAD_COMMAND_HEADER_SIZE: usize = 2 * mem::size_of::<u32>();

/// Returns the `LC_SEGMENT_64` load commands in `commands`, with each segment's `vmaddr` adjusted
/// by the slide computed from the `__TEXT` segment. `commands` holds data read from another
/// process, so we treat it as untrusted.
fn parse_segments(commands: &[u8], ncmds: u32, load_address: u64) -> Vec<segment_command_64> {
    let mut segments = Vec::new();
    let mut offset: usize = 0;
    for _ in 0..ncmds {
        let header = match commands.get(offset..offset + LOAD_COMMAND_HEADER_SIZE) {
            Some(h) => h,
            None => break,
        };
        let cmd = u32::from_ne_bytes([header[0], header[1], header[2], header[3]]);
        let cmdsize = u32::from_ne_bytes([header[4], header[5], header[6], header[7]]) as usize;
        if cmdsize < LOAD_COMMAND_HEADER_SIZE || commands.len() - offset < cmdsize {
            break;
        }

        if cmd == LC_SEGMENT_64 && cmdsize >= mem::size_of::<segment_command_64>() {
            // The buffer has no alignment guarantees, so the segment must be read unaligned.
            // Safety: the bounds checks above ensure that `size_of::<segment_command_64>()`
            // bytes are available at `offset`, and the struct is plain old data.
            let segment = unsafe {
                std::ptr::read_unaligned(commands.as_ptr().add(offset) as *const segment_command_64)
            };
            segments.push(segment);
        }
        offset += cmdsize;
    }

    // Figure out the slide from the __TEXT segment if appropriate
    let slide = segments
        .iter()
        .find(|s| s.segname[0..7] == [95, 95, 84, 69, 88, 84, 0])
        .map_or(0, |s| load_address.wrapping_sub(s.vmaddr));
    for segment in &mut segments {
        segment.vmaddr = segment.vmaddr.wrapping_add(slide);
    }
    segments
}

extern "C" {
    fn vm_read_overwrite(
        target_task: mach_port_t,
        address: mach_vm_address_t,
        size: mach_vm_size_t,
        data: mach_vm_address_t,
        out_size: *mut mach_vm_size_t,
    ) -> kern_return_t;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn segment_bytes(segname: &[u8], vmaddr: u64) -> Vec<u8> {
        let mut segment = segment_command_64 {
            cmd: LC_SEGMENT_64,
            cmdsize: mem::size_of::<segment_command_64>() as u32,
            vmaddr,
            ..Default::default()
        };
        for (dst, src) in segment.segname.iter_mut().zip(segname) {
            *dst = *src as _;
        }
        let ptr = &segment as *const segment_command_64 as *const u8;
        unsafe { std::slice::from_raw_parts(ptr, mem::size_of::<segment_command_64>()) }.to_vec()
    }

    fn load_command_bytes(cmd: u32, cmdsize: u32) -> Vec<u8> {
        let mut bytes = cmd.to_ne_bytes().to_vec();
        bytes.extend_from_slice(&cmdsize.to_ne_bytes());
        bytes.resize(cmdsize.max(8) as usize, 0);
        bytes
    }

    #[test]
    fn test_get_dyld_info_for_current_process() {
        let infos = get_dyld_info(std::process::id() as Pid).unwrap();
        let text = infos
            .iter()
            .find(|info| {
                info.filename.to_string_lossy().contains("libSystem")
                    && info.segment.segname[0..7] == [95, 95, 84, 69, 88, 84, 0]
            })
            .expect("libSystem should have a __TEXT segment");
        assert_eq!(text.segment.vmaddr, text.address as u64);
    }

    #[test]
    fn test_dyld_resource_budget() {
        let mut budget = DyldResourceBudget::default();
        budget.add_load_command_bytes(MAX_TOTAL_SIZEOFCMDS).unwrap();
        assert_eq!(
            budget.add_load_command_bytes(1).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );

        budget.add_segments(MAX_DYLD_SEGMENT_COUNT).unwrap();
        assert_eq!(
            budget.add_segments(1).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn test_resource_budget_rejects_overflow() {
        let mut total = usize::MAX;
        assert_eq!(
            add_to_budget(&mut total, 1, usize::MAX, "test resource")
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn test_path_from_c_buffer() {
        assert_eq!(
            path_from_c_buffer(b"/usr/lib/a.dylib\0junk"),
            Path::new("/usr/lib/a.dylib")
        );
        assert_eq!(
            path_from_c_buffer(b"/no/terminator"),
            Path::new("/no/terminator")
        );
        assert_eq!(path_from_c_buffer(b""), Path::new(""));
        assert_eq!(
            path_from_c_buffer(b"/bad/utf8/\xff\0")
                .as_os_str()
                .as_bytes(),
            b"/bad/utf8/\xff"
        );
    }

    #[test]
    fn test_parse_segments_applies_slide() {
        let mut commands = segment_bytes(b"__PAGEZERO", 0);
        commands.extend(load_command_bytes(0x2, 24)); // LC_SYMTAB
        commands.extend(segment_bytes(b"__TEXT", 0x1000));
        commands.extend(segment_bytes(b"__DATA", 0x5000));

        let segments = parse_segments(&commands, 4, 0x10_1000);
        let vmaddrs: Vec<u64> = segments.iter().map(|s| s.vmaddr).collect();
        assert_eq!(vmaddrs, vec![0x10_0000, 0x10_1000, 0x10_5000]);
    }

    #[test]
    fn test_parse_segments_handles_unaligned_commands() {
        // A 4-byte-aligned load command leaves the following segment misaligned for u64 fields.
        let mut commands = load_command_bytes(0x2, 12);
        commands.extend(segment_bytes(b"__TEXT", 0x1000));

        let segments = parse_segments(&commands, 2, 0x1000);
        assert_eq!(segments.len(), 1);
        assert_eq!(segments[0].vmaddr, 0x1000);
    }

    #[test]
    fn test_parse_segments_stops_at_malformed_commands() {
        let text = segment_bytes(b"__TEXT", 0x1000);

        // ncmds claims more commands than the buffer holds
        assert_eq!(parse_segments(&text, 100, 0x1000).len(), 1);

        // Truncated segment command
        assert!(parse_segments(&text[..text.len() - 1], 1, 0x1000).is_empty());

        // Too short for even a load command header
        assert!(parse_segments(&text[..4], 1, 0x1000).is_empty());

        // cmdsize of zero would otherwise never advance
        let mut commands = load_command_bytes(0x2, 0);
        commands.extend(&text);
        assert!(parse_segments(&commands, 2, 0x1000).is_empty());

        // cmdsize past the end of the buffer
        let mut commands = text.clone();
        commands.extend(load_command_bytes(0x2, 8));
        commands[text.len() + 4..text.len() + 8].copy_from_slice(&u32::MAX.to_ne_bytes());
        assert_eq!(parse_segments(&commands, 2, 0x1000).len(), 1);

        // LC_SEGMENT_64 whose cmdsize is too small for a segment_command_64
        assert!(parse_segments(&load_command_bytes(LC_SEGMENT_64, 16), 1, 0x1000).is_empty());
    }

    #[test]
    fn test_parse_segments_slide_does_not_overflow() {
        let commands = segment_bytes(b"__TEXT", u64::MAX);
        let segments = parse_segments(&commands, 1, 0x1000);
        assert_eq!(segments[0].vmaddr, 0x1000);
    }
}
