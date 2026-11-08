//! The wrapper stays unprivileged. The common broker authenticates the user
//! and owns the exact retained command, arguments, scope and stdio references.
use std::{io, path::PathBuf};

fn main() {
    match run() {
        Ok(status) => std::process::exit(status),
        Err(error) => {
            eprintln!("sudo: {error}");
            std::process::exit(1);
        }
    }
}
fn run() -> io::Result<i32> {
    let mut arguments = std::env::args().skip(1).collect::<Vec<_>>();
    if matches!(arguments.first().map(String::as_str), Some("--help" | "-h")) {
        println!(
            "usage: sudo [-u root] [--] command [argument ...]\nAuthentication uses the protected system prompt; passwords are never read from stdin."
        );
        return Ok(0);
    }
    if matches!(arguments.first().map(String::as_str), Some("-u")) {
        if !matches!(arguments.get(1).map(String::as_str), Some("root" | "0")) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "only the root target is supported",
            ));
        }
        arguments.drain(..2);
    }
    if matches!(arguments.first().map(String::as_str), Some("--")) {
        arguments.remove(0);
    }
    if arguments.is_empty() || arguments[0].starts_with('-') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected a command; use sudo --help",
        ));
    }
    let command = resolve(&arguments[0])?;
    execute(
        command.to_str().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "command path must be UTF-8")
        })?,
        &arguments,
    )
}
fn resolve(command: &str) -> io::Result<PathBuf> {
    if command.contains('/') {
        return std::fs::canonicalize(command);
    }
    // Resolve under the caller's PATH, then capture it under the caller's
    // explicit read scope. No shell expansion or root-side PATH search occurs.
    for directory in std::env::split_paths(
        &std::env::var_os("PATH").unwrap_or_else(|| "/bin:/system/bin".into()),
    ) {
        let candidate = directory.join(command);
        if candidate.is_file() {
            return std::fs::canonicalize(candidate);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!("command not found: {command}"),
    ))
}
#[cfg(target_os = "mochios")]
fn execute(path: &str, arguments: &[String]) -> io::Result<i32> {
    use mochi_user_platform as p;
    use mochios_posix_client::{Client, SyscallEndpointTransport};
    struct Reference(u32);
    impl Drop for Reference {
        fn drop(&mut self) {
            let _ = p::handle::close(self.0);
        }
    }
    unsafe extern "C" {
        fn mochi_fd_export(
            fd: i32,
            rights: u64,
            output: *mut mochios_posix_protocol::ExportedFdHandle,
        ) -> i32;
    }
    let error = |e: p::syscall::SysError| {
        io::Error::from_raw_os_error(e.errno().unwrap_or(libc::EIO as u64) as i32)
    };
    let transport = SyscallEndpointTransport::from_launch_context().map_err(error)?;
    let client = Client::new(transport);
    let scope = client.create_read_scope().map_err(|_| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "cannot capture caller scope",
        )
    })?;
    let _scope = Reference(scope.handle);
    let mut owned = Vec::new();
    let mut stdio = [p::application::Descriptor {
        handle: 0,
        rights: 0,
        metadata: 0,
    }; 3];
    for (fd, descriptor) in stdio.iter_mut().enumerate() {
        let rights = p::handle::HANDLE_RIGHT_WAIT
            | p::handle::HANDLE_RIGHT_DUPLICATE
            | p::handle::HANDLE_RIGHT_TRANSFER
            | if fd == 0 {
                p::handle::HANDLE_RIGHT_READ
            } else {
                p::handle::HANDLE_RIGHT_WRITE
            };
        let mut exported = mochios_posix_protocol::ExportedFdHandle::default();
        // This C ABI only exports this process's own pinned descriptor.
        if unsafe { mochi_fd_export(fd as i32, rights, &mut exported) } != 0 {
            return Err(io::Error::last_os_error());
        }
        owned.push(Reference(exported.handle));
        *descriptor = p::application::Descriptor {
            handle: exported.handle,
            rights: exported.rights,
            metadata: exported.metadata,
        };
    }
    let destination = u32::try_from(p::process::find_by_name("capability.service").map_err(error)?)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid broker endpoint"))?;
    let argv = arguments.iter().map(String::as_str).collect::<Vec<_>>();
    let environment = std::env::vars()
        .filter(|(name, _)| {
            matches!(name.as_str(), "TERM" | "COLORTERM" | "LANG" | "TZ") || name.starts_with("LC_")
        })
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>();
    let envp = environment.iter().map(String::as_str).collect::<Vec<_>>();
    let pid = p::application::spawn_as_administrator(
        destination,
        path,
        &argv,
        &envp,
        p::ipc::IpcObjectHandle {
            handle: scope.handle,
            reserved: 0,
            rights: mochios_posix_protocol::read_scope::ATTACH_RIGHTS,
        },
        &stdio,
    )
    .map_err(error)?;
    let pid = i32::try_from(pid)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid child PID"))?;
    let mut status = 0;
    loop {
        if unsafe { libc::waitpid(pid, &mut status, 0) } == pid {
            break;
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EINTR) {
            return Err(error);
        }
    }
    if libc::WIFEXITED(status) {
        Ok(libc::WEXITSTATUS(status))
    } else if libc::WIFSIGNALED(status) {
        Ok(128 + libc::WTERMSIG(status))
    } else {
        Ok(1)
    }
}
#[cfg(not(target_os = "mochios"))]
fn execute(_path: &str, _arguments: &[String]) -> io::Result<i32> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "administrator execution is available only on mochiOS",
    ))
}
