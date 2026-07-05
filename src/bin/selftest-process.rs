use std::io::{self, Write};
use std::process::Command;

const O_CLOEXEC: libc::c_int = 0x80000;
const FD_CLOEXEC: libc::c_int = 1;
const F_GETFD: libc::c_int = 1;

fn check(name: &str, result: io::Result<bool>, failures: &mut usize) {
    match result {
        Ok(true) => println!("ok selftest-process::{name}"),
        Ok(false) => {
            println!("not ok selftest-process::{name}");
            *failures += 1;
        }
        Err(error) => {
            println!("not ok selftest-process::{name}: {error}");
            *failures += 1;
        }
    }
}

fn command_status(path: &str) -> io::Result<i32> {
    let status = Command::new(path).status()?;
    Ok(status.code().unwrap_or(-1))
}

fn spawn_true() -> io::Result<bool> {
    Ok(command_status("/bin/true")? == 0)
}

fn spawn_false() -> io::Result<bool> {
    Ok(command_status("/bin/false")? == 1)
}

fn repeated_ls() -> io::Result<bool> {
    for _ in 0..8 {
        if command_status("/bin/ls")? != 0 {
            return Ok(false);
        }
    }
    Ok(true)
}

fn manifestless_child() -> io::Result<bool> {
    Ok(command_status("/bin/selftest-capability")? == 0)
}

fn pipe2_cloexec_roundtrip() -> io::Result<bool> {
    let mut fds = [-1i32; 2];
    let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), O_CLOEXEC) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }

    let read_fd = fds[0];
    let write_fd = fds[1];
    let flags_read = unsafe { libc::fcntl(read_fd, F_GETFD, 0) };
    let flags_write = unsafe { libc::fcntl(write_fd, F_GETFD, 0) };
    if flags_read < 0 || flags_write < 0 {
        unsafe {
            libc::close(read_fd);
            libc::close(write_fd);
        }
        return Err(io::Error::last_os_error());
    }

    let message = b"pipe-ok";
    let wrote = unsafe { libc::write(write_fd, message.as_ptr().cast(), message.len()) };
    if wrote < 0 {
        unsafe {
            libc::close(read_fd);
            libc::close(write_fd);
        }
        return Err(io::Error::last_os_error());
    }

    let mut buffer = [0u8; 7];
    let read = unsafe { libc::read(read_fd, buffer.as_mut_ptr().cast(), buffer.len()) };
    unsafe {
        libc::close(read_fd);
        libc::close(write_fd);
    }
    if read < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok((flags_read & FD_CLOEXEC) != 0
        && (flags_write & FD_CLOEXEC) != 0
        && read as usize == message.len()
        && buffer == *message)
}

fn main() {
    let _ = io::stdout().flush();
    let _ = io::stderr().flush();

    let mut failures = 0usize;
    check("spawn_true", spawn_true(), &mut failures);
    check("spawn_false_status", spawn_false(), &mut failures);
    check("repeated_ls", repeated_ls(), &mut failures);
    check(
        "pipe2_cloexec_roundtrip",
        pipe2_cloexec_roundtrip(),
        &mut failures,
    );
    check("manifestless_child", manifestless_child(), &mut failures);

    if failures == 0 {
        println!("selftest-process: pass");
    } else {
        eprintln!("selftest-process: {failures} failure(s)");
        std::process::exit(1);
    }
}
