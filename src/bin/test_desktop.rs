use std::io;
use std::io::Write;

use mochi_user_syscall as syscall;

const COMPOSITOR_SERVICE_NAME: &str = "compositor.service";
const WINDOW_OVERLAY_CAPABILITY: &str = "window.overlay";
const CAPABILITY_PROMPT_OPCODE: u32 = 0x4350_5251;
const OP_ATTACH_BUFFER: u32 = 2;
const OP_DAMAGE: u32 = 3;
const OP_COMMIT: u32 = 4;
const OP_DECOR_SUBSCRIBE: u32 = 100;
const OP_DECOR_CREATE_SURFACE: u32 = 101;
const OP_DECOR_ATTACH: u32 = 102;
const OP_DECOR_BEGIN_MOVE: u32 = 105;
const DECOR_EVENT_WINDOW: u32 = 0x5749_4e44;
const EVENT_POINTER_BUTTON: u32 = 5;
const PIXEL_FORMAT_XRGB8888: u32 = 1;
const PAGE_SIZE: usize = 4096;
const TITLE_BAR_HEIGHT: usize = 28;

static mut SUBSCRIBE_REQ: [u8; 12] = [0; 12];
static mut CREATE_DECOR_REQ: [u8; 28] = [0; 28];
static mut ATTACH_DECOR_REQ: [u8; 36] = [0; 36];
static mut BEGIN_MOVE_REQ: [u8; 28] = [0; 28];
static mut ATTACH_BUFFER_REQ: [u8; 28] = [0; 28];
static mut TOKEN_REQ: [u8; 12] = [0; 12];
static mut IPC_REPLY: [u8; 16] = [0; 16];
static mut EVENT_BUF: [u8; 128] = [0; 128];

#[repr(u32)]
#[derive(Clone, Copy)]
enum CapabilityClass {
    UserGrantable = 1,
}

#[repr(u32)]
#[derive(Clone, Copy)]
enum CapabilityDecision {
    AllowOnce = 1,
    AllowForProcess = 2,
    AllowPersistently = 3,
    AllowAllUserGrantable = 4,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ExecutableIdentity {
    path_len: u16,
    reserved: u16,
    digest: [u8; 32],
    path: [u8; 256],
}

impl Default for ExecutableIdentity {
    fn default() -> Self {
        Self {
            path_len: 0,
            reserved: 0,
            digest: [0; 32],
            path: [0; 256],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ResourceDescriptor {
    kind: u32,
    path_len: u16,
    reserved: u16,
    path: [u8; 256],
}

impl Default for ResourceDescriptor {
    fn default() -> Self {
        Self {
            kind: 0,
            path_len: 0,
            reserved: 0,
            path: [0; 256],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CapabilityRequest {
    opcode: u32,
    process_id: u64,
    executable: ExecutableIdentity,
    capability_class: CapabilityClass,
    capability_len: u16,
    resource: ResourceDescriptor,
    reason_len: u16,
    interactive: u8,
    decision_scope: u8,
    reserved0: u16,
    capability: [u8; 64],
    reason: [u8; 128],
}

#[derive(Clone, Copy)]
struct WindowInfo {
    token: u64,
    width: u32,
    height: u32,
}

fn errno_io(errno: u64) -> io::Error {
    io::Error::from_raw_os_error(errno as i32)
}

fn syscall_io<T>(result: syscall::SysResult<T>) -> io::Result<T> {
    result.map_err(|err| errno_io(err.errno().unwrap_or(libc::EIO as u64)))
}

fn context<T>(label: &str, result: io::Result<T>) -> io::Result<T> {
    result.map_err(|err| io::Error::new(err.kind(), format!("{label}: {err}")))
}

fn request_window_overlay_capability() -> io::Result<()> {
    eprintln!("test_desktop: requesting window.overlay");
    let shell_endpoint = match std::env::var("MOCHI_SHELL_ENDPOINT")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
    {
        Some(endpoint) if endpoint != 0 => endpoint,
        _ => return Err(errno_io(libc::EACCES as u64)),
    };
    let executable = std::env::var("MOCHI_EXECUTABLE_PATH").unwrap_or_else(|_| {
        std::env::args()
            .next()
            .unwrap_or_else(|| "/bin/test_desktop".to_string())
    });
    let exec_bytes = executable.as_bytes();
    let cap_bytes = WINDOW_OVERLAY_CAPABILITY.as_bytes();
    let reason = b"test desktop decoration manager";
    if exec_bytes.len() > 256 || cap_bytes.len() > 64 || reason.len() > 128 {
        return Err(errno_io(libc::EINVAL as u64));
    }
    eprintln!("test_desktop: requesting pid");
    let process_id = match syscall::call0(syscall::SyscallNumber::GetPid) {
        Ok(pid) if pid != 0 => {
            eprintln!("test_desktop: pid={pid}");
            pid
        }
        Ok(_) | Err(_) => {
            let tid = match syscall::call0(syscall::SyscallNumber::GetTid) {
                Ok(tid) => tid,
                Err(error) => {
                    return Err(errno_io(error.errno().unwrap_or(libc::EIO as u64)))
                }
            };
            if tid == 0 {
                return Err(errno_io(libc::EIO as u64));
            }
            eprintln!("test_desktop: pid fallback tid={tid}");
            tid
        }
    };
    let mut request = CapabilityRequest {
        opcode: CAPABILITY_PROMPT_OPCODE,
        process_id,
        executable: ExecutableIdentity::default(),
        capability_class: CapabilityClass::UserGrantable,
        capability_len: cap_bytes.len() as u16,
        resource: ResourceDescriptor::default(),
        reason_len: reason.len() as u16,
        interactive: 1,
        decision_scope: 0,
        reserved0: 0,
        capability: [0; 64],
        reason: [0; 128],
    };
    request.executable.path_len = exec_bytes.len() as u16;
    request.executable.path[..exec_bytes.len()].copy_from_slice(exec_bytes);
    request.capability[..cap_bytes.len()].copy_from_slice(cap_bytes);
    request.reason[..reason.len()].copy_from_slice(reason);

    let mut reply = [0u8; 8];
    eprintln!("test_desktop: sending capability request to shell endpoint={shell_endpoint}");
    let msg = syscall_io(syscall::call5(
        syscall::SyscallNumber::IpcCall,
        shell_endpoint,
        (&request as *const CapabilityRequest) as u64,
        core::mem::size_of::<CapabilityRequest>() as u64,
        reply.as_mut_ptr() as u64,
        reply.len() as u64,
    ))?;
    log_line("test_desktop: capability reply received");
    if (msg & 0xffff_ffff) < 4 {
        return Err(errno_io(libc::EIO as u64));
    }
    let decision = u32::from_le_bytes([reply[0], reply[1], reply[2], reply[3]]);
    if decision == CapabilityDecision::AllowOnce as u32
        || decision == CapabilityDecision::AllowForProcess as u32
        || decision == CapabilityDecision::AllowPersistently as u32
        || decision == CapabilityDecision::AllowAllUserGrantable as u32
    {
        log_line("test_desktop: capability decision accepted");
        let cap = WINDOW_OVERLAY_CAPABILITY.as_bytes();
        match syscall::call2(
            syscall::SyscallNumber::CapQuery,
            cap.as_ptr() as u64,
            cap.len() as u64,
        ) {
            Ok(1) => {
                eprintln!("test_desktop: capability query ok");
                Ok(())
            }
            Ok(_) => {
                log_error(
                    "test_desktop: capability query denied",
                    &errno_io(libc::EACCES as u64),
                );
                Err(errno_io(libc::EACCES as u64))
            }
            Err(err) => {
                let error = errno_io(err.errno().unwrap_or(libc::EIO as u64));
                log_error("test_desktop: capability query failed", &error);
                Err(error)
            }
        }
    } else {
        let error = errno_io(libc::EACCES as u64);
        log_error("test_desktop: capability decision rejected", &error);
        Err(error)
    }
}

fn log_line(message: &str) {
    println!("{message}");
    let _ = io::stdout().flush();
}

fn log_error(label: &str, error: &io::Error) {
    eprintln!("{label}: {error}");
    let _ = io::stderr().flush();
}

fn require_window_overlay_capability() -> io::Result<()> {
    match request_window_overlay_capability() {
        Ok(()) => {
            log_line("test_desktop: window.overlay granted");
            Ok(())
        }
        Err(error) => {
            log_error("test_desktop: window.overlay request failed", &error);
            Err(error)
        }
    }
}

fn subscribe_with_log(compositor: u64, event_endpoint: u64) -> io::Result<()> {
    match subscribe(compositor, event_endpoint) {
        Ok(()) => {
            log_line("test_desktop: subscribed decoration manager");
            Ok(())
        }
        Err(error) => {
            log_error("test_desktop: decoration subscribe failed", &error);
            Err(error)
        }
    }
}

fn wait_event_with_log(event: *mut u8, event_endpoint: u64) -> io::Result<usize> {
    match ipc_wait_raw(event, 128, event_endpoint) {
        Ok(len) => Ok(len),
        Err(error) => {
            log_error("test_desktop: event wait failed", &error);
            Err(error)
        }
    }
}

fn decorate_window_with_log(
    compositor: u64,
    event_endpoint: u64,
    window: WindowInfo,
) -> io::Result<()> {
    match decorate_window(compositor, event_endpoint, window) {
        Ok(()) => Ok(()),
        Err(error) => {
            log_error("test_desktop: decorate window failed", &error);
            Err(error)
        }
    }
}

fn begin_move_with_log(compositor: u64, window: u64, serial: u64) {
    if let Err(error) = begin_move(compositor, window, serial, 24, 24) {
        log_error("test_desktop: begin move failed", &error);
    }
}

fn find_compositor() -> io::Result<u64> {
    eprintln!("test_desktop: finding compositor");
    let name = COMPOSITOR_SERVICE_NAME.as_bytes();
    for _ in 0..64 {
        let tid = syscall_io(syscall::call2(
            syscall::SyscallNumber::FindProcessByName,
            name.as_ptr() as u64,
            name.len() as u64,
        ))?;
        if tid != 0 {
            eprintln!("test_desktop: compositor tid={tid}");
            return Ok(tid);
        }
        let _ = syscall::call0(syscall::SyscallNumber::ThreadYield);
    }
    Err(errno_io(libc::ENOENT as u64))
}

fn ipc_create() -> io::Result<u64> {
    eprintln!("test_desktop: creating event endpoint");
    let endpoint = syscall_io(syscall::call2(syscall::SyscallNumber::IpcCreate, 0, 0))?;
    eprintln!("test_desktop: event endpoint={endpoint}");
    Ok(endpoint)
}

fn ipc_call_raw(
    dest: u64,
    req_ptr: *const u8,
    req_len: usize,
    reply_ptr: *mut u8,
    reply_len: usize,
) -> io::Result<usize> {
    let msg = syscall_io(syscall::call5(
        syscall::SyscallNumber::IpcCall,
        dest,
        req_ptr as u64,
        req_len as u64,
        reply_ptr as u64,
        reply_len as u64,
    ))?;
    Ok((msg & 0xffff_ffff) as usize)
}

fn ipc_wait_raw(buf_ptr: *mut u8, buf_len: usize, endpoint: u64) -> io::Result<usize> {
    let msg = syscall_io(syscall::call3(
        syscall::SyscallNumber::IpcWait,
        buf_ptr as u64,
        buf_len as u64,
        endpoint,
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

unsafe fn zero_raw(ptr: *mut u8, len: usize) {
    core::ptr::write_bytes(ptr, 0, len);
}

unsafe fn put_u32_raw(ptr: *mut u8, offset: usize, value: u32) {
    core::ptr::copy_nonoverlapping(value.to_le_bytes().as_ptr(), ptr.add(offset), 4);
}

unsafe fn put_u64_raw(ptr: *mut u8, offset: usize, value: u64) {
    core::ptr::copy_nonoverlapping(value.to_le_bytes().as_ptr(), ptr.add(offset), 8);
}

unsafe fn read_u32_raw(ptr: *const u8, offset: usize) -> u32 {
    let mut bytes = [0u8; 4];
    core::ptr::copy_nonoverlapping(ptr.add(offset), bytes.as_mut_ptr(), 4);
    u32::from_le_bytes(bytes)
}

unsafe fn read_u64_raw(ptr: *const u8, offset: usize) -> u64 {
    let mut bytes = [0u8; 8];
    core::ptr::copy_nonoverlapping(ptr.add(offset), bytes.as_mut_ptr(), 8);
    u64::from_le_bytes(bytes)
}

fn status_from_raw(ptr: *const u8, len: usize) -> io::Result<()> {
    if len < 4 {
        return Err(errno_io(libc::EIO as u64));
    }
    let status = unsafe { read_u32_raw(ptr, 0) };
    if status == 0 {
        Ok(())
    } else {
        Err(errno_io(status as u64))
    }
}

fn subscribe(compositor: u64, event_endpoint: u64) -> io::Result<()> {
    let request = core::ptr::addr_of_mut!(SUBSCRIBE_REQ).cast::<u8>();
    let reply = core::ptr::addr_of_mut!(IPC_REPLY).cast::<u8>();
    unsafe {
        zero_raw(request, 12);
        put_u32_raw(request, 0, OP_DECOR_SUBSCRIBE);
        put_u64_raw(request, 4, event_endpoint);
        zero_raw(reply, 16);
    }
    let len = ipc_call_raw(compositor, request, 12, reply, 16)?;
    status_from_raw(reply, len)
}

fn parse_window_event(ptr: *const u8, len: usize) -> Option<WindowInfo> {
    if len < 48 {
        return None;
    }
    let opcode = unsafe { read_u32_raw(ptr, 0) };
    if opcode != DECOR_EVENT_WINDOW {
        return None;
    }
    Some(WindowInfo {
        token: unsafe { read_u64_raw(ptr, 4) },
        width: unsafe { read_u32_raw(ptr, 12) },
        height: unsafe { read_u32_raw(ptr, 16) },
    })
}

fn create_decoration(compositor: u64, event_endpoint: u64, window: WindowInfo) -> io::Result<u64> {
    let request = core::ptr::addr_of_mut!(CREATE_DECOR_REQ).cast::<u8>();
    let reply = core::ptr::addr_of_mut!(IPC_REPLY).cast::<u8>();
    unsafe {
        zero_raw(request, 28);
        put_u32_raw(request, 0, OP_DECOR_CREATE_SURFACE);
        put_u64_raw(request, 4, window.token);
        put_u32_raw(request, 12, window.width);
        put_u32_raw(request, 16, TITLE_BAR_HEIGHT as u32);
        put_u64_raw(request, 20, event_endpoint);
        zero_raw(reply, 16);
    }
    let len = ipc_call_raw(compositor, request, 28, reply, 16)?;
    if len < 12 {
        return Err(errno_io(libc::EIO as u64));
    }
    status_from_raw(reply, len)?;
    Ok(unsafe { read_u64_raw(reply, 4) })
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
            let button = x + 56 >= width && y >= 4 && y < 22;
            pixels[y * width + x] = if button {
                0xffb0_3030
            } else if y == 0 || y + 1 == height {
                0xffe0_e0e0
            } else {
                0xff38_4a62
            };
        }
    }
    let request = core::ptr::addr_of_mut!(ATTACH_BUFFER_REQ).cast::<u8>();
    let reply = core::ptr::addr_of_mut!(IPC_REPLY).cast::<u8>();
    unsafe {
        zero_raw(request, 28);
        put_u32_raw(request, 0, OP_ATTACH_BUFFER);
        put_u64_raw(request, 4, token);
        put_u32_raw(request, 12, width as u32);
        put_u32_raw(request, 16, height as u32);
        put_u32_raw(request, 20, width as u32);
        put_u32_raw(request, 24, PIXEL_FORMAT_XRGB8888);
        zero_raw(reply, 16);
    }
    let len = ipc_call_raw(compositor, request, 28, reply, 16)?;
    status_from_raw(reply, len)?;
    send_pages(compositor, page_count, virt)
}

fn simple_token_request(compositor: u64, opcode: u32, token: u64) -> io::Result<()> {
    let request = core::ptr::addr_of_mut!(TOKEN_REQ).cast::<u8>();
    let reply = core::ptr::addr_of_mut!(IPC_REPLY).cast::<u8>();
    unsafe {
        zero_raw(request, 12);
        put_u32_raw(request, 0, opcode);
        put_u64_raw(request, 4, token);
        zero_raw(reply, 16);
    }
    let len = ipc_call_raw(compositor, request, 12, reply, 16)?;
    status_from_raw(reply, len)
}

fn attach_decoration(compositor: u64, window: WindowInfo, decoration_token: u64) -> io::Result<()> {
    let request = core::ptr::addr_of_mut!(ATTACH_DECOR_REQ).cast::<u8>();
    let reply = core::ptr::addr_of_mut!(IPC_REPLY).cast::<u8>();
    unsafe {
        zero_raw(request, 36);
        put_u32_raw(request, 0, OP_DECOR_ATTACH);
        put_u64_raw(request, 4, window.token);
        put_u64_raw(request, 12, decoration_token);
        put_u32_raw(request, 20, 0);
        put_u32_raw(request, 24, TITLE_BAR_HEIGHT as u32);
        put_u32_raw(request, 28, 0);
        put_u32_raw(request, 32, 0);
        zero_raw(reply, 16);
    }
    let len = ipc_call_raw(compositor, request, 36, reply, 16)?;
    status_from_raw(reply, len)
}

fn begin_move(compositor: u64, window_token: u64, serial: u64, dx: i32, dy: i32) -> io::Result<()> {
    let request = core::ptr::addr_of_mut!(BEGIN_MOVE_REQ).cast::<u8>();
    let reply = core::ptr::addr_of_mut!(IPC_REPLY).cast::<u8>();
    unsafe {
        zero_raw(request, 28);
        put_u32_raw(request, 0, OP_DECOR_BEGIN_MOVE);
        put_u64_raw(request, 4, window_token);
        put_u64_raw(request, 12, serial);
        put_u32_raw(request, 20, dx as u32);
        put_u32_raw(request, 24, dy as u32);
        zero_raw(reply, 16);
    }
    let len = ipc_call_raw(compositor, request, 28, reply, 16)?;
    status_from_raw(reply, len)
}

fn decorate_window(compositor: u64, event_endpoint: u64, window: WindowInfo) -> io::Result<()> {
    if window.width == 0 || window.height == 0 {
        return Err(errno_io(libc::EINVAL as u64));
    }
    let decoration = create_decoration(compositor, event_endpoint, window)?;
    attach_buffer(
        compositor,
        decoration,
        window.width as usize,
        TITLE_BAR_HEIGHT,
    )?;
    simple_token_request(compositor, OP_DAMAGE, decoration)?;
    simple_token_request(compositor, OP_COMMIT, decoration)?;
    attach_decoration(compositor, window, decoration)?;
    println!(
        "test_desktop: decorated window=0x{:016x} decoration=0x{:016x}",
        window.token, decoration
    );
    Ok(())
}

fn main() -> io::Result<()> {
    eprintln!("test_desktop: start");
    require_window_overlay_capability()?;
    let compositor = context("find compositor", find_compositor())?;
    let event_endpoint = context("create event endpoint", ipc_create())?;
    subscribe_with_log(compositor, event_endpoint)?;
    log_line(&format!("test_desktop: waiting endpoint={event_endpoint}"));
    let mut active_window = 0u64;
    loop {
        let event = core::ptr::addr_of_mut!(EVENT_BUF).cast::<u8>();
        let len = wait_event_with_log(event, event_endpoint)?;
        if let Some(window) = parse_window_event(event, len) {
            let _ = decorate_window_with_log(compositor, event_endpoint, window);
            active_window = window.token;
            continue;
        }
        if len >= 16 && active_window != 0 {
            let kind = unsafe { read_u32_raw(event, 0) };
            if kind == EVENT_POINTER_BUTTON {
                let serial = unsafe { read_u32_raw(event, 12) } as u64;
                if serial != 0 {
                    begin_move_with_log(compositor, active_window, serial);
                }
            }
        }
    }
}
