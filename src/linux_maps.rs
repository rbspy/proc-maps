use libc;
use regex::bytes::{Regex, RegexBuilder};
use std;
use std::str;
use std::fs::File;
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::io::{self, BufRead};
use std::path::{Path, PathBuf};
use MapRangeImpl;

pub type Pid = libc::pid_t;

/// A struct representing a single virtual memory region
/// While this structure only is for Linux, the OSX and Windows
/// variants have identical exposed methods
#[derive(Debug, Clone, PartialEq)]
pub struct MapRange {
    range_start: usize,
    range_end: usize,
    offset: u64,
    dev: (u32, u32),
    perms: Vec<u8>,
    inode: u64,
    pathname: Option<PathBuf>,
}

impl MapRangeImpl for MapRange {
    fn size(&self) -> usize { self.range_end - self.range_start }

    fn start(&self) -> usize { self.range_start }

    fn filename(&self) -> Option<&Path> { self.pathname.as_ref().map(|path| path.as_path()) }

    fn is_exec(&self) -> bool { self.perms[2] == b'x' }

    fn is_write(&self) -> bool { self.perms[1] == b'w' }

    fn is_read(&self) -> bool { self.perms[0] == b'r' }
}

/// Gets a Vec of [`MapRange`](linux_maps/struct.MapRange.html) structs for
/// the passed in PID. (Note that while this function is for linux, the OSX
/// and Windows variants have the same interface)
pub fn get_process_maps(pid: Pid) -> std::io::Result<Vec<MapRange>> {
    // Parses /proc/PID/maps into a Vec<MapRange>
    let maps_file = format!("/proc/{}/maps", pid);
    let file = io::BufReader::new(File::open(maps_file)?);
    parse_proc_maps(file)
}


fn parse_proc_maps<R: BufRead>(mut reader: R) -> io::Result<Vec<MapRange>> {
    lazy_static! {
        static ref LINE_REGEX: Regex = RegexBuilder::new(concat!(
            // Beginning of line
            "^",
            // Address Range
            "([0-9a-f]+)-([0-9a-f]+)", "[ \t]+",
            // Perms read, write, execute, and private/shared
            "([-r][-w][-x][ps])", "[ \t]+",
            // Offset
            "([0-9a-f]+)", "[ \t]+",
            // Dev (major:minor)
            "([0-9]+):([0-9]+)", "[ \t]+",
            // Inode (may not be a final field, space is optional)
            "([0-9]+)", "[ \t]*",
            "(.*)",
        )).case_insensitive(true).build().unwrap();
    }

    macro_rules! parse_byte_str {
        ($hex_iter:expr, $t:tt) => (
            parse_byte_str!($hex_iter, $t, 16)
        );
        ($hex_iter:expr, $t:tt, $radix:expr) => (
            // Safe because we validated all bytes are [0-9a-f], and all fields always participate
            $t::from_str_radix(unsafe { str::from_utf8_unchecked($hex_iter.next().unwrap().unwrap().as_bytes()) }, $radix)
        );
    }

    let mut vec: Vec<MapRange> = Vec::new();
    let mut line: Vec<u8> = Vec::new();
    loop {
        let bytes_read = reader.read_until(b'\n', &mut line)?;
        if bytes_read == 0 {
            break;
        }
        if let Some(captures) = LINE_REGEX.captures(&line) {
            let mut matches_iter = captures.iter();
            // Eat 0th match
            matches_iter.next().unwrap();
            let range_start = match parse_byte_str!(matches_iter, usize) {
                Ok(val) => val,
                Err(_) => continue,
            };
            let range_end = match parse_byte_str!(matches_iter, usize) {
                Ok(val) => val,
                Err(_) => continue,
            };
            let perms = matches_iter.next().unwrap().unwrap().as_bytes().to_vec();
            let offset = match parse_byte_str!(matches_iter, u64) {
                Ok(val) => val,
                Err(_) => continue,
            };
            let major = match parse_byte_str!(matches_iter, u32, 10) {
                Ok(val) => val,
                Err(_) => continue,
            };
            let minor = match parse_byte_str!(matches_iter, u32, 10) {
                Ok(val) => val,
                Err(_) => continue,
            };
            let dev = (major, minor);
            let inode = match parse_byte_str!(matches_iter, u64, 10) {
                Ok(val) => val,
                Err(_) => continue,
            };

            let pathname = matches_iter.next().unwrap().unwrap().as_bytes();
            let pathname = if !pathname.is_empty() {
                Some(PathBuf::from(OsStr::from_bytes(pathname)))
            } else {
                None
            };

            vec.push(MapRange {
                range_start,
                range_end,
                offset,
                dev,
                perms,
                inode,
                pathname,
            });
        }
        line.clear();
    }
    Ok(vec)
}

#[test]
fn test_parse_maps() {
    let contents = include_bytes!("../ci/testdata/map.txt");
    let vec = parse_proc_maps(&contents[..]).unwrap();
    let expected = vec![
        MapRange {
            range_start: 0x00400000,
            range_end: 0x00507000,
            offset: 0,
            dev: (0, 14),
            perms: b"r-xp".to_vec(),
            inode: 205736,
            pathname: Some(PathBuf::from("/usr/bin/fish")),
        },
        MapRange {
            range_start: 0x00708000,
            range_end: 0x0070a000,
            offset: 0,
            dev: (0, 0),
            perms: b"rw-p".to_vec(),
            inode: 0,
            pathname: None,
        },
        MapRange {
            range_start: 0x0178c000,
            range_end: 0x01849000,
            offset: 0,
            dev: (0, 0),
            perms: b"rw-p".to_vec(),
            inode: 0,
            pathname: Some(PathBuf::from("[heap]")),
        },
    ];
    assert_eq!(vec, expected);

    // Also check that maps_contain_addr works as expected
    assert_eq!(super::maps_contain_addr(0x00400000, &vec), true);
    assert_eq!(super::maps_contain_addr(0x00300000, &vec), false);
}
