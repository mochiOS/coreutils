use super::platform;
use platform::memory_object::{MemoryMapping, MemoryObject};
use std::io;

pub(super) struct GuiBuffer {
    _mapping: MemoryMapping,
    object: MemoryObject,
    capacity: u64,
}

fn error(error: platform::syscall::SysError) -> io::Error {
    io::Error::from_raw_os_error(error.errno().unwrap_or(5) as i32)
}

impl GuiBuffer {
    pub(super) fn new(
        width: usize,
        height: usize,
        mut pixel: impl FnMut(usize, usize) -> u32,
    ) -> io::Result<Self> {
        let capacity = width
            .checked_mul(height)
            .and_then(|pixels| pixels.checked_mul(4))
            .and_then(|bytes| bytes.checked_add(4095))
            .map(|bytes| bytes & !4095)
            .filter(|bytes| *bytes != 0)
            .ok_or_else(|| io::Error::from_raw_os_error(22))?;
        let object = MemoryObject::create(capacity as u64).map_err(error)?;
        let mut mapping = object
            .map(
                0,
                capacity as u64,
                platform::syscall::MEMORY_ACCESS_READ | platform::syscall::MEMORY_ACCESS_WRITE,
            )
            .map_err(error)?;
        for y in 0..height {
            for x in 0..width {
                // Storage is locally owned. The later receiver may alias it;
                // never manufacture an exclusive Rust slice over shared RAM.
                unsafe {
                    core::ptr::write_volatile(
                        mapping.as_mut_ptr().cast::<u32>().add(y * width + x),
                        pixel(x, y),
                    );
                }
            }
        }
        Ok(Self {
            _mapping: mapping,
            object,
            capacity: capacity as u64,
        })
    }

    pub(super) fn offer(&self, endpoint: u64) -> io::Result<()> {
        self.object
            .send_readonly(endpoint, 0, self.capacity)
            .map_err(error)
    }
}
