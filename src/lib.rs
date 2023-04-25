//! Get virtual memory maps from another process
//!
//! This crate provides a function—[`get_process_maps`](linux_maps/fn.get_process_maps.html)
//! that returns a Vec of [`MapRange`](linux_maps/struct.MapRange.html) structs.
//!
//! This code works on Linux, macOS, and Windows. Each operating system has a different
//! implementation, but the functions and structs for all OSes share the same
//! interface - so this can be used generically across operating systems.
//!
//! Note: on macOS this requires root access, and even with root will still not
//! work on processes that have System Integrity Protection enabled
//! (anything in /usr/bin for example).
//!
//! # Example
//!
//! ```rust,no_run
//! use proc_maps::{get_process_maps, MapRange, Pid};
//!
//! let maps = get_process_maps(123456 as Pid).unwrap();
//! for map in maps {
//!    println!("Filename {:?} Address {} Size {}", map.filename(), map.start(), map.size());
//! }
//! ```

extern crate libc;

#[cfg(target_os = "macos")]
extern crate anyhow;
#[cfg(target_os = "macos")]
extern crate libproc;
#[cfg(target_os = "macos")]
extern crate mach2;
#[cfg(windows)]
extern crate winapi;

#[cfg(target_os = "macos")]
pub mod mac_maps;
#[cfg(target_os = "macos")]
pub use mac_maps::{get_process_maps, MapRange, Pid};

#[cfg(any(target_os = "linux", target_os = "android"))]
pub mod linux_maps;
#[cfg(any(target_os = "linux", target_os = "android"))]
pub use linux_maps::{get_process_maps, MapRange, Pid};

#[cfg(windows)]
pub mod win_maps;
#[cfg(windows)]
pub use win_maps::{get_process_maps, MapRange, Pid};

#[cfg(target_os = "freebsd")]
pub mod freebsd_maps;
#[cfg(target_os = "freebsd")]
pub use freebsd_maps::{get_process_maps, MapRange, Pid};

/// Trait to implement on MapRange, to provide an implementation.
///
/// By using a private trait, and providing an inherent implementation, we ensure the provided methods
/// are the same for all supported OSes.
trait MapRangeImpl {
    /// Returns the size of this MapRange in bytes
    fn size(&self) -> usize;
    /// Returns the address this MapRange starts at
    fn start(&self) -> usize;
    /// Returns the filename of the loaded module
    fn filename(&self) -> Option<&std::path::Path>;
    /// Returns whether this range contains executable code
    fn is_exec(&self) -> bool;
    /// Returns whether this range contains writeable memory
    fn is_write(&self) -> bool;
    /// Returns whether this range contains readable memory
    fn is_read(&self) -> bool;
}

impl MapRange {
    /// Returns the size of this MapRange in bytes
    #[inline]
    pub fn size(&self) -> usize {
        MapRangeImpl::size(self)
    }
    /// Returns the address this MapRange starts at
    #[inline]
    pub fn start(&self) -> usize {
        MapRangeImpl::start(self)
    }
    /// Returns the filename of the loaded module
    #[inline]
    pub fn filename(&self) -> Option<&std::path::Path> {
        MapRangeImpl::filename(self)
    }
    /// Returns whether this range contains executable code
    #[inline]
    pub fn is_exec(&self) -> bool {
        MapRangeImpl::is_exec(self)
    }
    /// Returns whether this range contains writeable memory
    #[inline]
    pub fn is_write(&self) -> bool {
        MapRangeImpl::is_write(self)
    }
    /// Returns whether this range contains readable memory
    #[inline]
    pub fn is_read(&self) -> bool {
        MapRangeImpl::is_read(self)
    }
}

fn map_contain_addr(map: &MapRange, addr: usize) -> bool {
    let start = map.start();
    (addr >= start) && (addr < (start + map.size()))
}

/// Returns whether or not any MapRange contains the given address
/// Note: this will only work correctly on macOS and Linux.
pub fn maps_contain_addr(addr: usize, maps: &[MapRange]) -> bool {
    maps.iter().any(|map| map_contain_addr(map, addr))
}

#[cfg(test)]
mod tests {
    use crate::get_process_maps;
    use crate::Pid;

    #[cfg(not(target_os = "windows"))]
    fn test_process_path() -> Option<std::path::PathBuf> {
        std::env::current_exe().ok().and_then(|p| {
            p.parent().map(|p| {
                p.with_file_name("test")
                    .with_extension(std::env::consts::EXE_EXTENSION)
            })
        })
    }

    #[cfg(not(target_os = "freebsd"))]
    #[test]
    fn test_map_from_test_binary_present() -> () {
        let maps = get_process_maps(std::process::id() as Pid).unwrap();

        let region = maps.iter().find(|map| {
            if let Some(filename) = map.filename() {
                filename.to_string_lossy().contains("proc_maps")
            } else {
                false
            }
        });

        assert!(
            region.is_some(),
            "We should have a map for the current test process"
        );
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn test_map_from_invoked_binary_present() -> () {
        let path = test_process_path().unwrap();
        if !path.exists() {
            println!("Skipping test because the 'test' binary hasn't been built");
            return;
        }

        let mut have_expected_map = false;
        // The maps aren't populated immediately on Linux, so retry a few times if needed
        for _ in 1..10 {
            let mut child = std::process::Command::new(&path)
                .spawn()
                .expect("failed to execute test process");

            let maps = get_process_maps(child.id() as Pid).unwrap();

            child.kill().expect("failed to kill test process");

            let region = maps.iter().find(|map| {
                if let Some(filename) = map.filename() {
                    filename.to_string_lossy().contains("/test")
                } else {
                    false
                }
            });

            if region.is_some() {
                have_expected_map = true;
                break;
            } else {
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }

        assert!(
            have_expected_map,
            "We should have a map from the binary we invoked!"
        );
    }
}
