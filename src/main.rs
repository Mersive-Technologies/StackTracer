#![deny(warnings)]

#[macro_use]
extern crate failure;
extern crate elf;
extern crate errno;
extern crate libc;
extern crate rustc_demangle;

use errno::errno;
use failure::Error;
use libc::{
    pid_t, ptrace, waitpid, ECHILD, PTRACE_ATTACH, PTRACE_CONT, PTRACE_DETACH, SIGSTOP, WIFSTOPPED, WSTOPSIG,
    WUNTRACED, __WCLONE,
};
use std::{
    collections::BTreeMap,
    ffi::CStr,
    fs,
    os::raw::{c_char, c_int},
    ptr,
};

#[repr(C)]
struct UnwArgT(usize);

#[repr(C)]
struct UnwArg(*const UnwArgT);

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
enum UnwRegnum {
    UnwRegIp = UNW_TDEP_IP,
    UnwRegSp = UNW_TDEP_SP,
}

type UnwWord = usize;

#[repr(C)]
struct UnwAddrSpaceT(usize);

#[repr(C)]
struct UnwAddrSpace(*const UnwAddrSpaceT);

impl Drop for UnwAddrSpace {
    fn drop(&mut self) {
        unsafe {
            unw_destroy_addr_space(self.0);
        }
    }
}

#[repr(C)]
struct UnwCursorT([UnwWord; UNW_TDEP_CURSOR_LEN]);

impl UnwCursorT {
    fn new() -> UnwCursorT {
        UnwCursorT([0; UNW_TDEP_CURSOR_LEN])
    }
}

#[repr(C)]
struct UnwAccessorsT {
    find_proc_info: extern "C" fn(),
    put_unwind_info: extern "C" fn(),
    get_dyn_info_list_addr: extern "C" fn(),
    access_mem: extern "C" fn(),
    access_reg: extern "C" fn(),
    access_fpreg: extern "C" fn(),
    resume: extern "C" fn(),
    get_proc_name: extern "C" fn(),
}

const __LITTLE_ENDIAN: c_int = 1234;

#[link(name = "unwind-ptrace")]
extern "C" {
    fn _UPT_create(process: pid_t) -> *const UnwArgT;
    fn _UPT_destroy(arg: *const UnwArgT);

    static _UPT_accessors: UnwAccessorsT;
}

#[cfg(target_arch = "x86_64")]
#[link(name = "unwind")]
#[link(name = "unwind-x86_64")]
extern "C" {
    fn _Ux86_64_init_remote(cursor: *mut UnwCursorT, space: *const UnwAddrSpaceT, arg: *const UnwArgT) -> c_int;
    fn _Ux86_64_step(cursor: *mut UnwCursorT) -> c_int;
    fn _Ux86_64_get_reg(cursor: *const UnwCursorT, register: UnwRegnum, value: *mut UnwWord) -> c_int;
    fn _Ux86_64_get_proc_name(
        cursor: *const UnwCursorT,
        name: *mut c_char,
        name_length: usize,
        offset: *mut UnwWord,
    ) -> c_int;
    fn _Ux86_64_create_addr_space(accessors: *const UnwAccessorsT, byte_order: c_int) -> *const UnwAddrSpaceT;
    fn _Ux86_64_destroy_addr_space(space: *const UnwAddrSpaceT);
}

#[cfg(target_arch = "x86_64")]
unsafe fn unw_init_remote(cursor: *mut UnwCursorT, space: *const UnwAddrSpaceT, arg: *const UnwArgT) -> c_int {
    _Ux86_64_init_remote(cursor, space, arg)
}

#[cfg(target_arch = "x86_64")]
unsafe fn unw_step(cursor: *mut UnwCursorT) -> c_int {
    _Ux86_64_step(cursor)
}

#[cfg(target_arch = "x86_64")]
unsafe fn unw_get_reg(cursor: *const UnwCursorT, register: UnwRegnum, value: *mut UnwWord) -> c_int {
    _Ux86_64_get_reg(cursor, register, value)
}

#[cfg(target_arch = "x86_64")]
unsafe fn unw_get_proc_name(
    cursor: *const UnwCursorT,
    name: *mut c_char,
    name_length: usize,
    offset: *mut UnwWord,
) -> c_int {
    _Ux86_64_get_proc_name(cursor, name, name_length, offset)
}

#[cfg(target_arch = "x86_64")]
unsafe fn unw_create_addr_space(accessors: *const UnwAccessorsT, byte_order: c_int) -> *const UnwAddrSpaceT {
    _Ux86_64_create_addr_space(accessors, byte_order)
}

#[cfg(target_arch = "x86_64")]
unsafe fn unw_destroy_addr_space(space: *const UnwAddrSpaceT) {
    _Ux86_64_destroy_addr_space(space);
}

#[cfg(target_arch = "x86_64")]
fn normalize(address: usize) -> usize {
    // empirically derived PIE offset (but be sure to turn off
    // address randomization)
    address - 0x555555554000
}

#[cfg(target_arch = "arm")]
#[link(name = "unwind")]
extern "C" {
    fn _Uarm_init_remote(cursor: *mut UnwCursorT, space: *const UnwAddrSpaceT, arg: *const UnwArgT) -> c_int;
    fn _Uarm_step(cursor: *mut UnwCursorT) -> c_int;
    fn _Uarm_get_reg(cursor: *const UnwCursorT, register: UnwRegnum, value: *mut UnwWord) -> c_int;
    fn _Uarm_get_proc_name(
        cursor: *const UnwCursorT,
        name: *mut c_char,
        name_length: usize,
        offset: *mut UnwWord,
    ) -> c_int;
    fn _Uarm_create_addr_space(accessors: *const UnwAccessorsT, byte_order: c_int) -> *const UnwAddrSpaceT;
    fn _Uarm_destroy_addr_space(space: *const UnwAddrSpaceT);
}

#[cfg(target_arch = "arm")]
unsafe fn unw_init_remote(cursor: *mut UnwCursorT, space: *const UnwAddrSpaceT, arg: *const UnwArgT) -> c_int {
    _Uarm_init_remote(cursor, space, arg)
}

#[cfg(target_arch = "arm")]
unsafe fn unw_step(cursor: *mut UnwCursorT) -> c_int {
    _Uarm_step(cursor)
}

#[cfg(target_arch = "arm")]
unsafe fn unw_get_reg(cursor: *const UnwCursorT, register: UnwRegnum, value: *mut UnwWord) -> c_int {
    _Uarm_get_reg(cursor, register, value)
}

#[cfg(target_arch = "arm")]
unsafe fn unw_get_proc_name(
    cursor: *const UnwCursorT,
    name: *mut c_char,
    name_length: usize,
    offset: *mut UnwWord,
) -> c_int {
    _Uarm_get_proc_name(cursor, name, name_length, offset)
}

#[cfg(target_arch = "arm")]
unsafe fn unw_create_addr_space(accessors: *const UnwAccessorsT, byte_order: c_int) -> *const UnwAddrSpaceT {
    _Uarm_create_addr_space(accessors, byte_order)
}

#[cfg(target_arch = "arm")]
unsafe fn unw_destroy_addr_space(space: *const UnwAddrSpaceT) {
    _Uarm_destroy_addr_space(space);
}

#[cfg(target_arch = "arm")]
fn normalize(address: usize) -> usize {
    address
}

struct Attach {
    thread: pid_t,
}

impl Drop for Attach {
    fn drop(&mut self) {
        let _ = detach(self.thread);
    }
}

fn strerror() -> Error {
    format_err!("{}", errno())
}

fn detach(thread: pid_t) -> Result<(), Error> {
    unsafe {
        if -1 == ptrace(PTRACE_DETACH, thread, 0, 0) {
            Err(strerror())
        } else {
            Ok(())
        }
    }
}

fn attach(thread: pid_t) -> Result<Attach, Error> {
    unsafe {
        if -1 == ptrace(PTRACE_ATTACH, thread, 0, 0) {
            return Err(strerror());
        }

        let attach = Attach { thread };

        let mut status = 0;
        if -1 == waitpid(thread, &mut status, WUNTRACED) {
            if ECHILD == errno().0 {
                loop {
                    let pid = waitpid(-1, &mut status, __WCLONE);

                    if thread == pid {
                        break;
                    } else if -1 == pid {
                        return Err(strerror());
                    }
                }
            }
        }

        if !WIFSTOPPED(status) || SIGSTOP != WSTOPSIG(status) {
            if WIFSTOPPED(status) {
                if -1 == ptrace(PTRACE_CONT, thread, 0, 0) {
                    return Err(strerror());
                }
            }

            return Err(format_err!("unable to attach to thread {}", thread));
        }

        Ok(attach)
    }
}

fn trace(attach: &Attach, space: &UnwAddrSpace) -> Result<Vec<UnwWord>, Error> {
    unsafe {
        let upt = UnwArg(_UPT_create(attach.thread));
        if upt.0 == ptr::null() {
            return Err(format_err!("_UPT_create failed"));
        }

        let mut cursor = UnwCursorT::new();
        let result = unw_init_remote(&mut cursor, space.0, upt.0);
        if 0 > result {
            return Err(format_err!("unw_init_remote failed: {}", result));
        }

        let limit = 1024;
        let mut count = 0;
        let mut trace = Vec::new();
        while count < limit {
            let mut ip = 0;
            let result = unw_get_reg(&cursor, UnwRegnum::UnwRegIp, &mut ip);
            if 0 > result {
                return Err(format_err!("unw_get_reg failed: {}", result));
            }

            let mut sp = 0;
            let result = unw_get_reg(&cursor, UnwRegnum::UnwRegSp, &mut sp);
            if 0 > result {
                return Err(format_err!("unw_get_reg failed: {}", result));
            }

            const SIZE: usize = 1024;
            let mut buffer = [0; SIZE];
            let mut offset = 0;
            let _result = unw_get_proc_name(&cursor, buffer.as_mut_ptr(), SIZE - 1, &mut offset);
            if false && 0 > result {
                return Err(format_err!("unw_get_proc_name failed: {}", result));
            }

            eprintln!("{:x} {:x} is {:?}", ip, sp, CStr::from_ptr(buffer.as_ptr()).to_str());

            trace.push(ip);
            count += 1;

            let result = unw_step(&mut cursor);
            if 0 == result {
                break;
            } else if 0 > result {
                return Err(format_err!("unw_step failed: {}", result));
            }
        }

        Ok(trace)
    }
}

fn run(process: pid_t) -> Result<(), Error> {
    let space = UnwAddrSpace(unsafe { unw_create_addr_space(&_UPT_accessors, __LITTLE_ENDIAN) });

    if space.0 == ptr::null() {
        return Err(format_err!("unw_create_addr_space failed"));
    }

    let mut symbols = BTreeMap::new();
    let exe = elf::File::open_path(format!("/proc/{}/exe", process)).map_err(|e| format_err!("open_path: {:?}", e))?;
    for section in &exe.sections {
        for symbol in exe
            .get_symbols(&section)
            .map_err(|e| format_err!("get_symbols: {:?}", e))?
        {
            // eprintln!("symbol {:x} {} {}", symbol.value, symbol.size, symbol.name);
            symbols.insert(symbol.value, symbol);
        }
    }

    for entry in fs::read_dir(format!("/proc/{}/task", process))? {
        let entry = entry?;
        if let Some(thread) = entry.file_name().to_str().and_then(|s| s.parse::<pid_t>().ok()) {
            eprintln!(
                "trace for thread {}: {:?}",
                thread,
                trace(&attach(thread)?, &space)?
                    .into_iter()
                    .map(|address| {
                        let address = normalize(address) as u64;
                        if let Some((_, symbol)) = symbols.range(..address).next_back() {
                            if address < symbol.value + symbol.size {
                                return rustc_demangle::demangle(&symbol.name).to_string();
                            }
                        }

                        format!("{:x}", address)
                    }).collect::<Vec<String>>()
            )
        }
    }

    Ok(())
}

fn main() {
    let mut args = std::env::args();
    let usage = format!("usage: {} <pid>", args.next().expect("program has no name?"));

    if let Err(e) = run(args.next().expect(&usage).parse::<pid_t>().expect(&usage)) {
        eprintln!("exit on error: {:?}", e)
    }
}
