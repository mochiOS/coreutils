use std::io;

use mochi_user_syscall as syscall;

const COMPOSITOR_SERVICE_NAME: &str = "compositor.service";
const OP_CREATE_SURFACE: u32 = 1;
const OP_ATTACH_BUFFER: u32 = 2;
const OP_DAMAGE: u32 = 3;
const OP_COMMIT: u32 = 4;
const OP_SET_POSITION: u32 = 5;
const ROLE_TOPLEVEL: u32 = 1;
const PIXEL_FORMAT_XRGB8888: u32 = 1;
const SURFACE_W: usize = 320;
const SURFACE_H: usize = 240;
const SURFACE_X: i32 = 32;
const SURFACE_Y: i32 = 24;
const PAGE_SIZE: usize = 4096;

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

fn alloc_shared_page_count(page_count: usize) -> io::Result<u64> {
    let virt = syscall_io(syscall::call4(
        syscall::SyscallNumber::AllocSharedPages,
        page_count as u64,
        0,
        0,
        0,
    ))?;
    if virt == 0 || (virt & (PAGE_SIZE as u64 - 1)) != 0 {
        return Err(errno_io(libc::EIO as u64));
    }
    Ok(virt)
}

fn send_pages(dest: u64, page_count: usize, local_base: u64) -> io::Result<()> {
    syscall_io(syscall::call4(
        syscall::SyscallNumber::IpcSendPages,
        dest,
        0,
        page_count as u64,
        local_base,
    ))?;
    Ok(())
}

fn put_u32(out: &mut [u8], offset: usize, value: u32) {
    out[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_i32(out: &mut [u8], offset: usize, value: i32) {
    out[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(out: &mut [u8], offset: usize, value: u64) {
    out[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
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

fn create_surface(
    compositor: u64,
    event_endpoint: u64,
    width: u32,
    height: u32,
) -> io::Result<u64> {
    let mut request = [0u8; 24];
    put_u32(&mut request, 0, OP_CREATE_SURFACE);
    put_u32(&mut request, 4, ROLE_TOPLEVEL);
    put_u32(&mut request, 8, width);
    put_u32(&mut request, 12, height);
    put_u64(&mut request, 16, event_endpoint);
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

fn attach_buffer(compositor: u64, token: u64, width: usize, height: usize) -> io::Result<()> {
    let byte_len = width
        .checked_mul(height)
        .and_then(|pixels| pixels.checked_mul(4))
        .ok_or_else(|| errno_io(libc::EINVAL as u64))?;
    let page_count = byte_len
        .checked_add(PAGE_SIZE - 1)
        .map(|len| len / PAGE_SIZE)
        .ok_or_else(|| errno_io(libc::EINVAL as u64))?;
    let virt = alloc_shared_page_count(page_count)?;
    let pixels = unsafe { std::slice::from_raw_parts_mut(virt as *mut u32, width * height) };
    for y in 0..height {
        for x in 0..width {
            let border = x == 0 || y == 0 || x + 1 == width || y + 1 == height;
            let pixel = if border {
                0xffff_ffffu32
            } else {
                let r = 0x30 + (x as u32 * 5 / width as u32);
                let g = 0x80 + (y as u32 * 6 / height as u32);
                let b = 0xc0u32;
                0xff00_0000 | (r << 16) | (g << 8) | b
            };
            pixels[y * width + x] = pixel;
        }
    }
    let mut request = [0u8; 28];
    put_u32(&mut request, 0, OP_ATTACH_BUFFER);
    put_u64(&mut request, 4, token);
    put_u32(&mut request, 12, width as u32);
    put_u32(&mut request, 16, height as u32);
    put_u32(&mut request, 20, width as u32);
    put_u32(&mut request, 24, PIXEL_FORMAT_XRGB8888);
    let mut reply = [0u8; 16];
    let len = ipc_call(compositor, &request, &mut reply)?;
    if len < 4 {
        return Err(errno_io(libc::EIO as u64));
    }
    status_from(&reply[..4])?;
    send_pages(compositor, page_count, virt)
}

fn set_position(compositor: u64, token: u64, x: i32, y: i32) -> io::Result<()> {
    let mut request = [0u8; 20];
    put_u32(&mut request, 0, OP_SET_POSITION);
    put_u64(&mut request, 4, token);
    put_i32(&mut request, 12, x);
    put_i32(&mut request, 16, y);
    let mut reply = [0u8; 16];
    let len = ipc_call(compositor, &request, &mut reply)?;
    if len < 4 {
        return Err(errno_io(libc::EIO as u64));
    }
    status_from(&reply[..4])
}

fn simple_token_request(compositor: u64, opcode: u32, token: u64) -> io::Result<()> {
    let mut request = [0u8; 12];
    put_u32(&mut request, 0, opcode);
    put_u64(&mut request, 4, token);
    let mut reply = [0u8; 16];
    let len = ipc_call(compositor, &request, &mut reply)?;
    if len < 4 {
        return Err(errno_io(libc::EIO as u64));
    }
    status_from(&reply[..4])
}

fn main() -> io::Result<()> {
    let compositor = find_compositor()?;
    let token = create_surface(compositor, 0, SURFACE_W as u32, SURFACE_H as u32)?;
    attach_buffer(compositor, token, SURFACE_W, SURFACE_H)?;
    set_position(compositor, token, SURFACE_X, SURFACE_Y)?;
    simple_token_request(compositor, OP_DAMAGE, token)?;
    simple_token_request(compositor, OP_COMMIT, token)?;
    println!("test_gui: committed surface token=0x{token:016x}");
    Ok(())
}
