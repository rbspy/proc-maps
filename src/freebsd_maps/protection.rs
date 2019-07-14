/// These values are not exposed via libc, yet.
/// Defined in FreeBSD source: /sys/vm/vm.h

use libc::int32_t;

pub const VM_PROT_READ: int32_t = 0x01;
pub const VM_PROT_WRITE: int32_t = 0x02;
pub const VM_PROT_EXECUTE: int32_t = 0x04;
