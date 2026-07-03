use std::io;

use mochi_user_syscall as syscall;

const PACKAGE_SERVICE_NAME: &str = "package.service";
const INSTALL_REQUEST_OPCODE: u32 = 0x494e_5354;

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

fn install_via_package_service(mpkg_path: &str) -> io::Result<()> {
    if !mpkg_path.starts_with('/') || mpkg_path.as_bytes().contains(&0) {
        return Err(errno_io(libc::EINVAL as u64));
    }
    let service_tid = find_package_service()?;
    let mut request = Vec::with_capacity(4 + mpkg_path.len());
    request.extend_from_slice(&INSTALL_REQUEST_OPCODE.to_le_bytes());
    request.extend_from_slice(mpkg_path.as_bytes());
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
    if args.len() != 1 {
        coreutils::usage("mpk", "PACKAGE.mpkg");
    }

    install_via_package_service(&args[0].to_string_lossy())
}
