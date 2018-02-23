extern crate bcc;
extern crate failure;
extern crate goblin;
extern crate libc;

use std::ptr;
use std::fs::File;
use std::io::Read;
use std::process::Command;
use std::collections::HashSet;

use bcc::core::BPF;
use bcc::perf::init_perf_map;
use failure::Error;
use failure::ResultExt;

use libc::{pid_t, size_t};

#[repr(C)]
struct data_t {
    libc_function: [u8; 20], // name of function we traced
    // bytes we found when we dereferenced the first argument
    // this is because sometimes the first argument is a string
    // TODO: be a lot smarter about how we parse arguments
    arg1_contents: [u8; 20],
    arg1: size_t,
    arg2: size_t,
    arg3: size_t,
}

fn trace_with_bcc(pid: pid_t, functions: HashSet<String>, library: &str) -> Result<BPF, Error> {
    let mut bpf_code = "
        #include <uapi/linux/ptrace.h>
        #include <linux/blkdev.h>
        BPF_PERF_OUTPUT(events);
        struct data_t {
            char libc_function[20];
            char arg1_contents[20];
            size_t arg1;
            size_t arg2;
            size_t arg3;
        };
    "
        .to_string();
    // we generate C code at runtame that copies the name of the function into a struct and sends
    // it back to userspace with perf
    let template = "int trace_fun_NAME(struct pt_regs *ctx) {
        struct data_t data = {};
        data.arg3 = PT_REGS_PARM3(ctx);
        data.arg2 = PT_REGS_PARM2(ctx);
        data.arg1 = PT_REGS_PARM1(ctx);
        bpf_probe_read(&data.arg1_contents, sizeof(data.arg1_contents), (void *)data.arg1);
        strcpy(data.libc_function, \"NAME\");
        events.perf_submit(ctx, &data, sizeof(data));
        return 0;
    };";
    for ref name in &functions {
        bpf_code += &template.replace("NAME", name);
    }
    let mut module = BPF::new(&bpf_code)?;
    for ref name in &functions {
        let uprobe_name = &format!("trace_fun_{}", name);
        if let Ok(uprobe_code) = module.load_uprobe(uprobe_name) {
            if let Err(_) =
                module.attach_uprobe(library, name, uprobe_code, pid /* all PIDs */)
            {
                println!("failed to attach uprobe: {}", name);
            }
        } else {
            println!("failed to load uprobe: {}", name);
        }
    }
    Ok(module)
}

fn do_main() -> Result<(), Error> {
    let (pid, library) = match parse_args() {
        Some((pid, library)) => (pid, library),
        None => {
            return Ok(());
        }
    };
    let functions = linked_library_functions(pid, &library)?;
    let module = trace_with_bcc(pid, functions, &library)?;
    let table = module.table("events");
    // install a callback to print out file open events when they happen
    let mut perf_map = init_perf_map(table, perf_data_callback)?;
    println!("Starting to trace");
    // this `.poll()` loop is what makes our callback get called
    loop {
        perf_map.poll(200);
    }
}

fn parse_args() -> Option<(pid_t, String)> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() < 2 {
        println!("Usage: ltrace-bcc PID LIBRARY. ltrace-bcc PID will give you a list of possible libraries to trace");
        return None;
    }
    let pid = args[1]
        .parse::<libc::pid_t>()
        .expect(&format!("Error parsing pid: {}", &args[1]));
    let libraries = ldd(pid).unwrap();
    if args.len() == 2 {
        println!("Possible libraries:");
        for l in libraries {
            println!("{}", l);
        }
        return None;
    }
    let library = &args[2];
    Some((pid, library.to_string()))
}

fn ldd(pid: pid_t) -> Result<Vec<String>, Error> {
    let exe = &format!("/proc/{}/exe", pid);
    let stdout = Command::new("ldd").arg(exe).output()?.stdout;
    let output = String::from_utf8_lossy(&stdout);
    let mut libraries: Vec<String> = vec![];
    for x in output.split("\n") {
        let y: Vec<_> = x.split(" => ").collect();
        if y.len() >= 2 {
            if let Some(thing) = y[1].split(" ").next() {
                if thing.len() > 0 {
                    libraries.push(thing.to_string());
                }
            }
        }
    }
    Ok(libraries)
}

fn get_dynsyms(lib: &str) -> Result<HashSet<String>, Error> {
    let mut contents: Vec<u8> = vec![];
    let mut elf = File::open(lib)?;
    elf.read_to_end(&mut contents)?;
    let binary = goblin::elf::Elf::parse(&contents).context("failed to parse ELF file")?;
    let mut syms = HashSet::new();
    for sym in binary.dynsyms.iter() {
        let name = binary.dynstrtab.get(sym.st_name).unwrap()?;
        syms.insert(name.to_string());
    }
    Ok(syms)
}

/// Looks through the dynamic relocation table of the PID's exe to find all the functions that it
/// links to in a given library
fn linked_library_functions(pid: pid_t, library: &str) -> Result<HashSet<String>, Error> {
    let mut contents: Vec<u8> = vec![];
    let exe = &format!("/proc/{}/exe", pid);
    let mut elf = File::open(exe)?;
    elf.read_to_end(&mut contents)?;

    let library_syms = get_dynsyms(library)?;

    let binary = goblin::elf::Elf::parse(&contents).context("failed to parse ELF file")?;
    let mut functions = HashSet::new();
    for dynrel in binary.dynrelas {
        let sym = binary.dynsyms.get(dynrel.r_sym).unwrap();
        let name = binary.dynstrtab.get(sym.st_name).unwrap()?;
        if library_syms.contains(name) && name.len() > 0 {
            functions.insert(name.to_string());
        }
    }
    Ok(functions)
}

fn perf_data_callback() -> Box<FnMut(&[u8]) + Send> {
    Box::new(|x| {
        // This callback
        let data = parse_struct(x);
        println!(
            "{}({} [{}],{},{})",
            get_string(&data.libc_function),
            data.arg1,
            get_string(&data.arg1_contents),
            data.arg2,
            data.arg3
        );
    })
}

fn parse_struct(x: &[u8]) -> data_t {
    unsafe { ptr::read(x.as_ptr() as *const data_t) }
}

fn get_string(x: &[u8]) -> String {
    match x.iter().position(|&r| r == 0) {
        Some(zero_pos) => String::from_utf8_lossy(&x[0..zero_pos]).to_string(),
        None => String::from_utf8_lossy(x).to_string(),
    }
}

fn main() {
    match do_main() {
        Err(x) => {
            eprintln!("Error: {}", x);
            eprintln!("causes:");
            for c in x.causes() {
                println!("{}", c);
            }
            eprintln!("{}", x.backtrace());
            std::process::exit(1);
        }
        _ => {}
    }
}
