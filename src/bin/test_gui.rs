use std::io;

use mochi_user_syscall as syscall;

const COMPOSITOR_SERVICE_NAME: &str = "compositor.service";
const OP_CREATE_SURFACE: u32 = 1;
const OP_ATTACH_BUFFER: u32 = 2;
const OP_DAMAGE: u32 = 3;
const OP_COMMIT: u32 = 4;
const ROLE_TOPLEVEL: u32 = 1;
const PIXEL_FORMAT_XRGB8888: u32 = 1;
const SURFACE_W: usize = 20;
const SURFACE_H: usize = 14;

fn errno_io(errno: u64) -> io::Error {
    io::Error::from_raw_os_error(errno as i32)
}

fn syscall_io<T>(result: syscall::SysResult<T>) -> io::Result<T> {
    result.map_err(|err| errno_io(err.errno().unwrap_or(libc::EIO as u64)))
}

fn find_compositor() -> io::Result<u64> {
    let name = COMPOSITOR_SERVICE_NAME.as_bytes();
    for _ in 0..64 {
        let tid = syscall_io(syscall::call2(
            syscall::SyscallNumber::FindProcessByName,
            name.as_ptr() as u64,
            name.len() as u64,
        ))?;
        if tid != 0 {
            return Ok(tid);
        }
        let _ = syscall::call0(syscall::SyscallNumber::ThreadYield);
    }
    Err(errno_io(libc::ENOENT as u64))
}

fn ipc_call(dest: u64, request: &[u8], reply: &mut [u8]) -> io::Result<usize> {
    let msg = syscall_io(syscall::call5(
        syscall::SyscallNumber::IpcCall,
        dest,
        request.as_ptr() as u64,
        request.len() as u64,
        reply.as_mut_ptr() as u64,
        reply.len() as u64,
    ))?;
    Ok((msg & 0xffff_ffff) as usize)
}

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn status_from(reply: &[u8]) -> io::Result<()> {
    if reply.len() < 4 {
        return Err(errno_io(libc::EIO as u64));
    }
    let status = u32::from_le_bytes([reply[0], reply[1], reply[2], reply[3]]);
    if status == 0 {
        Ok(())
    } else {
        Err(errno_io(status as u64))
    }
}

fn create_surface(compositor: u64, event_endpoint: u64) -> io::Result<u64> {
    let mut request = Vec::new();
    put_u32(&mut request, OP_CREATE_SURFACE);
    put_u32(&mut request, ROLE_TOPLEVEL);
    put_u32(&mut request, SURFACE_W as u32);
    put_u32(&mut request, SURFACE_H as u32);
    put_u64(&mut request, event_endpoint);
    let mut reply = [0u8; 16];
    let len = ipc_call(compositor, &request, &mut reply)?;
    if len < 12 {
        return Err(errno_io(libc::EIO as u64));
    }
    status_from(&reply[..4])?;
    Ok(u64::from_le_bytes([
        reply[4], reply[5], reply[6], reply[7], reply[8], reply[9], reply[10], reply[11],
    ]))
}

fn attach_buffer(compositor: u64, token: u64) -> io::Result<()> {
    let mut request = Vec::with_capacity(28 + SURFACE_W * SURFACE_H * 4);
    put_u32(&mut request, OP_ATTACH_BUFFER);
    put_u64(&mut request, token);
    put_u32(&mut request, SURFACE_W as u32);
    put_u32(&mut request, SURFACE_H as u32);
    put_u32(&mut request, SURFACE_W as u32);
    put_u32(&mut request, PIXEL_FORMAT_XRGB8888);
    for y in 0..SURFACE_H {
        for x in 0..SURFACE_W {
            let border = x == 0 || y == 0 || x + 1 == SURFACE_W || y + 1 == SURFACE_H;
            let pixel = if border {
                0xffff_ffffu32
            } else {
                let r = 0x30 + (x as u32 * 5);
                let g = 0x80 + (y as u32 * 6);
                let b = 0xc0u32;
                0xff00_0000 | (r << 16) | (g << 8) | b
            };
            request.extend_from_slice(&pixel.to_le_bytes());
        }
    }
    let mut reply = [0u8; 16];
    let len = ipc_call(compositor, &request, &mut reply)?;
    if len < 4 {
        return Err(errno_io(libc::EIO as u64));
    }
    status_from(&reply[..4])
}

fn simple_token_request(compositor: u64, opcode: u32, token: u64) -> io::Result<()> {
    let mut request = Vec::new();
    put_u32(&mut request, opcode);
    put_u64(&mut request, token);
    let mut reply = [0u8; 16];
    let len = ipc_call(compositor, &request, &mut reply)?;
    if len < 4 {
        return Err(errno_io(libc::EIO as u64));
    }
    status_from(&reply[..4])
}

fn main() -> io::Result<()> {
    let compositor = find_compositor()?;
    let event_endpoint = syscall_io(syscall::call2(syscall::SyscallNumber::IpcCreate, 0, 0))?;
    let token = create_surface(compositor, event_endpoint)?;
    attach_buffer(compositor, token)?;
    simple_token_request(compositor, OP_DAMAGE, token)?;
    simple_token_request(compositor, OP_COMMIT, token)?;
    println!("test_gui: committed surface token=0x{token:016x}");
    Ok(())
}
