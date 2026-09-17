use std::io;
use std::path::{Path, PathBuf};

use mochi_user_syscall as syscall;

const PACKAGE_SERVICE_NAME: &str = "package.service";
const INSTALL_REQUEST_OPCODE: u32 = 0x494e_5354;
const UPDATE_REQUEST_OPCODE: u32 = 0x5550_4454;
const REMOVE_REQUEST_OPCODE: u32 = 0x524d_4f56;

#[derive(Clone, Copy)]
enum Mutation {
    Install,
    Update,
    Remove,
}

impl Mutation {
    const fn opcode(self) -> u32 {
        match self {
            Self::Install => INSTALL_REQUEST_OPCODE,
            Self::Update => UPDATE_REQUEST_OPCODE,
            Self::Remove => REMOVE_REQUEST_OPCODE,
        }
    }

    const fn present_participle(self) -> &'static str {
        match self {
            Self::Install => "Installing",
            Self::Update => "Updating",
            Self::Remove => "Removing",
        }
    }

    const fn completion(self) -> &'static str {
        match self {
            Self::Install => "Installation complete.",
            Self::Update => "Update complete.",
            Self::Remove => "Removal complete.",
        }
    }
}

fn errno_io(errno: u64) -> io::Error {
    io::Error::from_raw_os_error(errno as i32)
}

fn find_package_service() -> io::Result<u64> {
    let name = PACKAGE_SERVICE_NAME.as_bytes();
    let tid = syscall::call2(
        syscall::SyscallNumber::FindProcessByName,
        name.as_ptr() as u64,
        name.len() as u64,
    )
    .map_err(|err| errno_io(err.errno().unwrap_or(libc::EIO as u64)))?;
    if tid == 0 {
        return Err(errno_io(libc::ENOENT as u64));
    }
    Ok(tid)
}

fn absolute_package_path(path: &Path) -> io::Result<PathBuf> {
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    Ok(std::env::current_dir()?.join(path))
}

fn mutate_via_package_service(mutation: Mutation, subject: &str) -> io::Result<()> {
    if subject.as_bytes().contains(&0)
        || (!matches!(mutation, Mutation::Remove) && !subject.starts_with('/'))
    {
        return Err(errno_io(libc::EINVAL as u64));
    }
    let service_tid = find_package_service()?;
    let mut request = Vec::with_capacity(4 + subject.len());
    request.extend_from_slice(&mutation.opcode().to_le_bytes());
    request.extend_from_slice(subject.as_bytes());
    let mut reply = [0u8; 8];
    let msg = syscall::call5(
        syscall::SyscallNumber::IpcCall,
        service_tid,
        request.as_ptr() as u64,
        request.len() as u64,
        reply.as_mut_ptr() as u64,
        reply.len() as u64,
    )
    .map_err(|err| errno_io(err.errno().unwrap_or(libc::EIO as u64)))?;
    let len = (msg & 0xffff_ffff) as usize;
    if len < 8 {
        return Err(errno_io(libc::EIO as u64));
    }
    let status = u64::from_le_bytes(reply);
    if status == 0 {
        Ok(())
    } else {
        Err(errno_io(status))
    }
}

fn main() -> io::Result<()> {
    let args = coreutils::args();
    let (mutation, package) = match args.as_slice() {
        [package] => (Mutation::Install, package.as_os_str()),
        [command, package] if command == "install" => (Mutation::Install, package.as_os_str()),
        [command, package] if command == "update" => (Mutation::Update, package.as_os_str()),
        [command, package] if command == "remove" => (Mutation::Remove, package.as_os_str()),
        _ => coreutils::usage("mpk", "[install|update] PACKAGE.mpkg | remove PACKAGE_ID"),
    };
    let package = package
        .to_str()
        .ok_or_else(|| errno_io(libc::EINVAL as u64))?;

    let subject = if matches!(mutation, Mutation::Remove) {
        package.to_string()
    } else {
        absolute_package_path(Path::new(package))?
            .to_string_lossy()
            .into_owned()
    };
    println!("{} {}...", mutation.present_participle(), subject);
    match mutate_via_package_service(mutation, &subject) {
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
            eprintln!(
                "mpk: Developer Trust or Revocation data is unavailable or expired; retry after update.service synchronizes"
            );
            Err(error)
        }
        Ok(()) => {
            println!("{}", mutation.completion());
            Ok(())
        }
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absolute_package_path_preserves_absolute_input() {
        let path = Path::new("/system/samples/example.mpkg");
        assert_eq!(absolute_package_path(path).unwrap(), path);
    }

    #[test]
    fn absolute_package_path_resolves_relative_input() {
        let relative = Path::new("system/samples/example.mpkg");
        assert_eq!(
            absolute_package_path(relative).unwrap(),
            std::env::current_dir().unwrap().join(relative)
        );
    }
}
