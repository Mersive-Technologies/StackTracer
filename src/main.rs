#![deny(warnings)]

#[macro_use]
extern crate failure;
extern crate clap;
extern crate elf;
extern crate errno;
extern crate libc;
extern crate rustc_demangle;

mod unwind;

use clap::{App, Arg};
use elf::types::Symbol;
use errno::errno;
use failure::Error;
use libc::{
    pid_t, ptrace, waitpid, ECHILD, PTRACE_ATTACH, PTRACE_CONT, PTRACE_DETACH, SIGSTOP, WIFSTOPPED,
    WSTOPSIG, WUNTRACED, __WCLONE,
};
use std::{collections::BTreeMap, ffi::CStr, fs};
use unwind::{
    UnwAddrSpace, UnwArg, UnwCursorT, UnwRegnum, UnwWord, _UPT_accessors, _UPT_create,
    unw_create_addr_space, unw_get_proc_name, unw_get_reg, unw_init_remote, unw_step,
    __LITTLE_ENDIAN,
};

#[cfg(target_arch = "x86_64")]
fn normalize(address: usize) -> usize {
    // empirically derived PIE offset (but be sure to turn off
    // address randomization)
    address - 0x5555_5555_4000
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
        if -1 == waitpid(thread, &mut status, WUNTRACED) && ECHILD == errno().0 {
            loop {
                let pid = waitpid(-1, &mut status, __WCLONE);

                if thread == pid {
                    break;
                } else if -1 == pid {
                    return Err(strerror());
                }
            }
        }

        if !WIFSTOPPED(status) || SIGSTOP != WSTOPSIG(status) {
            if WIFSTOPPED(status) && -1 == ptrace(PTRACE_CONT, thread, 0, 0) {
                return Err(strerror());
            }

            return Err(format_err!("unable to attach to thread {}", thread));
        }

        Ok(attach)
    }
}

struct TraceElement {
    ip: UnwWord,
    proc_name: Option<String>,
}

impl TraceElement {
    fn to_string(&self, symbols: &BTreeMap<u64, Symbol>) -> String {
        let proc_name = self.proc_name.as_ref().cloned().or_else(|| {
            let address = normalize(self.ip) as u64;
            if let Some((_, symbol)) = symbols.range(..address).next_back() {
                if address < symbol.value + symbol.size {
                    return Some(symbol.name.to_owned());
                }
            }
            None
        });

        if let Some(name) = proc_name {
            format!(
                "{:#016x} {}",
                self.ip,
                rustc_demangle::demangle(&name).to_string()
            )
        } else {
            format!("{:#016x}", self.ip)
        }
    }
}

fn trace(attach: &Attach, space: &UnwAddrSpace) -> Result<Vec<TraceElement>, Error> {
    unsafe {
        let upt = UnwArg(_UPT_create(attach.thread));
        if upt.0.is_null() {
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
            let _ = unw_get_proc_name(&cursor, buffer.as_mut_ptr(), SIZE - 1, &mut offset);
            let proc_name = CStr::from_ptr(buffer.as_ptr()).to_str();

            trace.push(TraceElement {
                ip,
                proc_name: proc_name.ok().map(str::to_owned),
            });
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

fn main() -> Result<(), Error> {
    let matches = App::new(env!("CARGO_PKG_DESCRIPTION"))
        .version(env!("CARGO_PKG_VERSION"))
        .author(env!("CARGO_PKG_AUTHORS"))
        .arg(
            Arg::with_name("pid")
                .help("pid of process to get stack trace(s) for")
                .required(true),
        )
        .get_matches();

    let process = matches.value_of("pid").unwrap().parse::<pid_t>()?;

    let space = UnwAddrSpace(unsafe { unw_create_addr_space(&_UPT_accessors, __LITTLE_ENDIAN) });

    if space.0.is_null() {
        return Err(format_err!("unw_create_addr_space failed"));
    }

    let mut symbols = BTreeMap::new();

    let exe = elf::File::open_path(format!("/proc/{}/exe", process))
        .map_err(|e| format_err!("open_path: {:?}", e))?;

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
        if let Some(thread) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<pid_t>().ok())
        {
            eprintln!(
                "trace for thread {}:\n{}\n",
                thread,
                trace(&attach(thread)?, &space)?
                    .into_iter()
                    .map(|element| element.to_string(&symbols))
                    .collect::<Vec<String>>()
                    .join("\n")
            )
        }
    }

    Ok(())
}
