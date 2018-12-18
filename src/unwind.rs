use libc::pid_t;
use std::os::raw::{c_char, c_int};

#[repr(C)]
pub struct UnwArgT(pub usize);

#[repr(C)]
pub struct UnwArg(pub *const UnwArgT);

impl Drop for UnwArg {
    fn drop(&mut self) {
        unsafe {
            _UPT_destroy(self.0);
        }
    }
}

#[cfg(target_arch = "arm")]
const UNW_TDEP_SP: isize = 13;
#[cfg(target_arch = "arm")]
const UNW_TDEP_IP: isize = 14;
#[cfg(target_arch = "arm")]
const UNW_TDEP_CURSOR_LEN: usize = 4096;

#[cfg(target_arch = "x86_64")]
const UNW_TDEP_SP: isize = 7;
#[cfg(target_arch = "x86_64")]
const UNW_TDEP_IP: isize = 16;
#[cfg(target_arch = "x86_64")]
const UNW_TDEP_CURSOR_LEN: usize = 127;

#[repr(C)]
pub enum UnwRegnum {
    UnwRegIp = UNW_TDEP_IP,
    UnwRegSp = UNW_TDEP_SP,
}

pub type UnwWord = usize;

#[repr(C)]
pub struct UnwAddrSpaceT(pub usize);

#[repr(C)]
pub struct UnwAddrSpace(pub *const UnwAddrSpaceT);

impl Drop for UnwAddrSpace {
    fn drop(&mut self) {
        unsafe {
            unw_destroy_addr_space(self.0);
        }
    }
}

#[repr(C)]
pub struct UnwCursorT(pub [UnwWord; UNW_TDEP_CURSOR_LEN]);

impl UnwCursorT {
    pub fn new() -> UnwCursorT {
        UnwCursorT([0; UNW_TDEP_CURSOR_LEN])
    }
}

#[repr(C)]
pub struct UnwAccessorsT {
    pub find_proc_info: extern "C" fn(),
    pub put_unwind_info: extern "C" fn(),
    pub get_dyn_info_list_addr: extern "C" fn(),
    pub access_mem: extern "C" fn(),
    pub access_reg: extern "C" fn(),
    pub access_fpreg: extern "C" fn(),
    pub resume: extern "C" fn(),
    pub get_proc_name: extern "C" fn(),
}

pub const __LITTLE_ENDIAN: c_int = 1234;

#[link(name = "unwind-ptrace")]
extern "C" {
    pub fn _UPT_create(process: pid_t) -> *const UnwArgT;
    pub fn _UPT_destroy(arg: *const UnwArgT);

    pub static _UPT_accessors: UnwAccessorsT;
}

#[cfg(target_arch = "x86_64")]
#[link(name = "unwind")]
#[link(name = "unwind-x86_64")]
extern "C" {
    fn _Ux86_64_init_remote(
        cursor: *mut UnwCursorT,
        space: *const UnwAddrSpaceT,
        arg: *const UnwArgT,
    ) -> c_int;
    fn _Ux86_64_step(cursor: *mut UnwCursorT) -> c_int;
    fn _Ux86_64_get_reg(
        cursor: *const UnwCursorT,
        register: UnwRegnum,
        value: *mut UnwWord,
    ) -> c_int;
    fn _Ux86_64_get_proc_name(
        cursor: *const UnwCursorT,
        name: *mut c_char,
        name_length: usize,
        offset: *mut UnwWord,
    ) -> c_int;
    fn _Ux86_64_create_addr_space(
        accessors: *const UnwAccessorsT,
        byte_order: c_int,
    ) -> *const UnwAddrSpaceT;
    fn _Ux86_64_destroy_addr_space(space: *const UnwAddrSpaceT);
}

#[cfg(target_arch = "x86_64")]
pub unsafe fn unw_init_remote(
    cursor: *mut UnwCursorT,
    space: *const UnwAddrSpaceT,
    arg: *const UnwArgT,
) -> c_int {
    _Ux86_64_init_remote(cursor, space, arg)
}

#[cfg(target_arch = "x86_64")]
pub unsafe fn unw_step(cursor: *mut UnwCursorT) -> c_int {
    _Ux86_64_step(cursor)
}

#[cfg(target_arch = "x86_64")]
pub unsafe fn unw_get_reg(
    cursor: *const UnwCursorT,
    register: UnwRegnum,
    value: *mut UnwWord,
) -> c_int {
    _Ux86_64_get_reg(cursor, register, value)
}

#[cfg(target_arch = "x86_64")]
pub unsafe fn unw_get_proc_name(
    cursor: *const UnwCursorT,
    name: *mut c_char,
    name_length: usize,
    offset: *mut UnwWord,
) -> c_int {
    _Ux86_64_get_proc_name(cursor, name, name_length, offset)
}

#[cfg(target_arch = "x86_64")]
pub unsafe fn unw_create_addr_space(
    accessors: *const UnwAccessorsT,
    byte_order: c_int,
) -> *const UnwAddrSpaceT {
    _Ux86_64_create_addr_space(accessors, byte_order)
}

#[cfg(target_arch = "x86_64")]
pub unsafe fn unw_destroy_addr_space(space: *const UnwAddrSpaceT) {
    _Ux86_64_destroy_addr_space(space);
}

#[cfg(target_arch = "arm")]
#[link(name = "unwind")]
extern "C" {
    fn _Uarm_init_remote(
        cursor: *mut UnwCursorT,
        space: *const UnwAddrSpaceT,
        arg: *const UnwArgT,
    ) -> c_int;
    fn _Uarm_step(cursor: *mut UnwCursorT) -> c_int;
    fn _Uarm_get_reg(cursor: *const UnwCursorT, register: UnwRegnum, value: *mut UnwWord) -> c_int;
    fn _Uarm_get_proc_name(
        cursor: *const UnwCursorT,
        name: *mut c_char,
        name_length: usize,
        offset: *mut UnwWord,
    ) -> c_int;
    fn _Uarm_create_addr_space(
        accessors: *const UnwAccessorsT,
        byte_order: c_int,
    ) -> *const UnwAddrSpaceT;
    fn _Uarm_destroy_addr_space(space: *const UnwAddrSpaceT);
}

#[cfg(target_arch = "arm")]
pub unsafe fn unw_init_remote(
    cursor: *mut UnwCursorT,
    space: *const UnwAddrSpaceT,
    arg: *const UnwArgT,
) -> c_int {
    _Uarm_init_remote(cursor, space, arg)
}

#[cfg(target_arch = "arm")]
pub unsafe fn unw_step(cursor: *mut UnwCursorT) -> c_int {
    _Uarm_step(cursor)
}

#[cfg(target_arch = "arm")]
pub unsafe fn unw_get_reg(
    cursor: *const UnwCursorT,
    register: UnwRegnum,
    value: *mut UnwWord,
) -> c_int {
    _Uarm_get_reg(cursor, register, value)
}

#[cfg(target_arch = "arm")]
pub unsafe fn unw_get_proc_name(
    cursor: *const UnwCursorT,
    name: *mut c_char,
    name_length: usize,
    offset: *mut UnwWord,
) -> c_int {
    _Uarm_get_proc_name(cursor, name, name_length, offset)
}

#[cfg(target_arch = "arm")]
pub unsafe fn unw_create_addr_space(
    accessors: *const UnwAccessorsT,
    byte_order: c_int,
) -> *const UnwAddrSpaceT {
    _Uarm_create_addr_space(accessors, byte_order)
}

#[cfg(target_arch = "arm")]
pub unsafe fn unw_destroy_addr_space(space: *const UnwAddrSpaceT) {
    _Uarm_destroy_addr_space(space);
}
