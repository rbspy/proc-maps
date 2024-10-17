use libc;
use std;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use MapRangeImpl;

pub type Pid = libc::pid_t;

/// A struct representing a single virtual memory region.
///
/// While this structure is only for Linux, the macOS, Windows, and FreeBSD
/// variants have identical exposed methods
#[derive(Debug, Clone, PartialEq)]
pub struct MapRange {
    range_start: usize,
    range_end: usize,
    pub offset: usize,
    pub dev: String,
    pub flags: String,
    pub inode: usize,
    pathname: Option<PathBuf>,
}

impl MapRangeImpl for MapRange {
    fn size(&self) -> usize {
        self.range_end - self.range_start
    }
    fn start(&self) -> usize {
        self.range_start
    }
    fn filename(&self) -> Option<&Path> {
        self.pathname.as_deref()
    }
    fn is_exec(&self) -> bool {
        &self.flags[2..3] == "x"
    }
    fn is_write(&self) -> bool {
        &self.flags[1..2] == "w"
    }
    fn is_read(&self) -> bool {
        &self.flags[0..1] == "r"
    }
}

/// Gets a Vec of [`MapRange`](linux_maps/struct.MapRange.html) structs for
/// the passed in PID. (Note that while this function is for Linux, the macOS,
/// Windows, and FreeBSD variants have the same interface)
pub fn get_process_maps(pid: Pid) -> std::io::Result<Vec<MapRange>> {
    // Parses /proc/PID/maps into a Vec<MapRange>
    let maps_file = format!("/proc/{}/maps", pid);
    let mut file = File::open(maps_file)?;

    // Check that the file is not too big
    let metadata = file.metadata()?;
    if metadata.len() > 0x10000000 {
        return Err(std::io::Error::from_raw_os_error(libc::EFBIG));
    }

    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    parse_proc_maps(&contents)
}

fn parse_proc_maps(contents: &str) -> std::io::Result<Vec<MapRange>> {
    let mut vec: Vec<MapRange> = Vec::new();
    for line in contents.split("\n") {
        let mut split = line.split_whitespace();
        let range = match split.next() {
            None => break,
            Some(s) => s,
        };

        let mut range_split = range.split("-");
        let range_start = match range_split.next() {
            None => return Err(std::io::Error::from_raw_os_error(libc::EINVAL)),
            Some(s) => match usize::from_str_radix(s, 16) {
                Err(_) => return Err(std::io::Error::from_raw_os_error(libc::EINVAL)),
                Ok(i) => i,
            },
        };
        let range_end = match range_split.next() {
            None => return Err(std::io::Error::from_raw_os_error(libc::EINVAL)),
            Some(s) => match usize::from_str_radix(s, 16) {
                Err(_) => return Err(std::io::Error::from_raw_os_error(libc::EINVAL)),
                Ok(i) => i,
            },
        };
        if range_split.next().is_some() || range_start >= range_end {
            return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
        }

        let flags = match split.next() {
            None => return Err(std::io::Error::from_raw_os_error(libc::EINVAL)),
            Some(s) if s.len() < 3 => return Err(std::io::Error::from_raw_os_error(libc::EINVAL)),
            Some(s) => s.to_string(),
        };
        let offset = match split.next() {
            None => return Err(std::io::Error::from_raw_os_error(libc::EINVAL)),
            Some(s) => match usize::from_str_radix(s, 16) {
                Err(_) => return Err(std::io::Error::from_raw_os_error(libc::EINVAL)),
                // mmap: offset must be a multiple of the page size as returned by sysconf(_SC_PAGE_SIZE).
                Ok(i) if i & 0xfff != 0 => {
                    return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
                }
                Ok(i) => i,
            },
        };
        let dev = match split.next() {
            None => return Err(std::io::Error::from_raw_os_error(libc::EINVAL)),
            Some(s) => s.to_string(),
        };
        let inode = match split.next() {
            None => return Err(std::io::Error::from_raw_os_error(libc::EINVAL)),
            Some(s) => match usize::from_str_radix(s, 10) {
                Err(_) => return Err(std::io::Error::from_raw_os_error(libc::EINVAL)),
                Ok(i) => i,
            },
        };
        let pathname = match Some(split.collect::<Vec<&str>>().join(" ")).filter(|x| !x.is_empty())
        {
            Some(s) => Some(PathBuf::from(s)),
            None => None,
        };

        vec.push(MapRange {
            range_start,
            range_end,
            offset,
            dev,
            flags,
            inode,
            pathname,
        });
    }
    Ok(vec)
}

#[test]
fn test_parse_maps() {
    let contents = include_str!("../ci/testdata/map.txt");
    let vec = parse_proc_maps(contents).unwrap();
    let expected = vec![
        MapRange {
            range_start: 0x00400000,
            range_end: 0x00507000,
            offset: 0,
            dev: "00:14".to_string(),
            flags: "r-xp".to_string(),
            inode: 205736,
            pathname: Some(PathBuf::from("/usr/bin/fish")),
        },
        MapRange {
            range_start: 0x00708000,
            range_end: 0x0070a000,
            offset: 0,
            dev: "00:00".to_string(),
            flags: "rw-p".to_string(),
            inode: 0,
            pathname: None,
        },
        MapRange {
            range_start: 0x0178c000,
            range_end: 0x01849000,
            offset: 0,
            dev: "00:00".to_string(),
            flags: "rw-p".to_string(),
            inode: 0,
            pathname: Some(PathBuf::from("[heap]")),
        },
        MapRange {
            range_start: 0x7f438050,
            range_end: 0x7f438060,
            offset: 0,
            dev: "fd:01".to_string(),
            flags: "r--p".to_string(),
            inode: 59034409,
            pathname: Some(PathBuf::from(
                "/usr/lib/x86_64-linux-gnu/libgmodule-2.0.so.0.4200.6 (deleted)",
            )),
        },
    ];
    assert_eq!(vec, expected);

    // Also check that maps_contain_addr works as expected
    assert_eq!(super::maps_contain_addr(0x00400000, &vec), true);
    assert_eq!(super::maps_contain_addr(0x00300000, &vec), false);
}
