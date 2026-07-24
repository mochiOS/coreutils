use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Seek, SeekFrom, Write};

use mochi_user_syscall::{self as syscall, SyscallNumber};

const DATA_PATH: &str = "/tmp/ext2-write-data.bin";
const INDIRECT_PATH: &str = "/tmp/ext2-write-indirect.bin";
const LIMIT_PATH: &str = "/tmp/ext2-write-limit.bin";
const OVERWRITE_PATH: &str = "/tmp/ext2-write-overwrite.bin";
const EMPTY_PATH: &str = "/tmp/ext2-write-empty.bin";
const ENOSPC_PATH: &str = "/tmp/ext2-write-enospc.bin";
const ENOSPC_MODE_PATH: &str = "/tmp/ext2-write-enospc.mode";
const PREPARE_PASS_PATH: &str = "/tmp/ext2-write-prepare.pass";
const VERIFY_PASS_PATH: &str = "/tmp/ext2-write-verify.pass";
const BLOCK_SIZE: usize = 4096;
const SINGLE_INDIRECT_FILE_LEN: usize = 13 * BLOCK_SIZE;
const MAX_WRITABLE_SIZE: u64 = (12 + BLOCK_SIZE / 4) as u64 * BLOCK_SIZE as u64;
const PERSISTED: &[u8] = b"persistent-ext2\n";

fn require(condition: bool, message: &str) -> io::Result<()> {
    if condition {
        Ok(())
    } else {
        Err(io::Error::other(message))
    }
}

fn expect_errno(result: io::Result<()>, errno: i32, operation: &str) -> io::Result<()> {
    match result {
        Err(error) if error.raw_os_error() == Some(errno) => Ok(()),
        Err(error) => Err(io::Error::other(format!(
            "{operation}: expected errno {errno}, got {error}"
        ))),
        Ok(()) => Err(io::Error::other(format!(
            "{operation}: unexpectedly succeeded"
        ))),
    }
}

fn syscall_error(result: syscall::SysResult<u64>, errno: u64, operation: &str) -> io::Result<()> {
    match result {
        Err(error) if error.errno() == Some(errno) => Ok(()),
        Err(error) => Err(io::Error::other(format!(
            "{operation}: expected errno {errno}, got {}",
            error.raw()
        ))),
        Ok(value) => Err(io::Error::other(format!(
            "{operation}: unexpectedly succeeded with {value}"
        ))),
    }
}

fn syscall_value(result: syscall::SysResult<u64>, operation: &str) -> io::Result<u64> {
    result.map_err(|error| {
        io::Error::other(format!("{operation}: syscall failed with {}", error.raw()))
    })
}

fn verify_create_and_overwrite() -> io::Result<()> {
    println!("selftest-ext2-write: create and overwrite");
    drop(
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(EMPTY_PATH)?,
    );
    require(fs::metadata(EMPTY_PATH)?.len() == 0, "empty file size")?;

    fs::write(OVERWRITE_PATH, vec![b'a'; BLOCK_SIZE * 2])?;
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(OVERWRITE_PATH)?;
    file.write_all(b"HEAD")?;
    file.seek(SeekFrom::Start(BLOCK_SIZE as u64 - 2))?;
    file.write_all(b"EDGE")?;
    file.sync_all()?;
    drop(file);

    let bytes = fs::read(OVERWRITE_PATH)?;
    require(bytes.len() == BLOCK_SIZE * 2, "overwrite retained size")?;
    require(&bytes[..4] == b"HEAD", "existing file overwrite")?;
    require(
        bytes[4..BLOCK_SIZE - 2].iter().all(|byte| *byte == b'a'),
        "partial block retained contents",
    )?;
    require(
        &bytes[BLOCK_SIZE - 2..BLOCK_SIZE + 2] == b"EDGE",
        "block boundary write",
    )?;
    require(
        bytes[BLOCK_SIZE + 2..].iter().all(|byte| *byte == b'a'),
        "second block retained contents",
    )
}

fn verify_fd_errors() -> io::Result<()> {
    println!("selftest-ext2-write: fd errors");
    let path = CString::new(DATA_PATH).map_err(io::Error::other)?;
    let fd = syscall_value(
        syscall::call4(
            SyscallNumber::FileOpenAt,
            (-100i64) as u64,
            path.as_ptr() as u64,
            0,
            0,
        ),
        "open read-only fd",
    )?;
    let byte = b'x';
    syscall_error(
        syscall::call3(SyscallNumber::FileWrite, fd, (&byte as *const u8) as u64, 1),
        13,
        "read-only fd write",
    )?;
    syscall_value(
        syscall::call1(SyscallNumber::FileClose, fd),
        "close read-only fd",
    )?;
    syscall_error(
        syscall::call3(SyscallNumber::FileWrite, fd, (&byte as *const u8) as u64, 1),
        9,
        "closed fd write",
    )?;
    syscall_error(
        syscall::call3(
            SyscallNumber::FileWrite,
            u64::MAX,
            (&byte as *const u8) as u64,
            1,
        ),
        9,
        "invalid fd write",
    )
}

fn verify_hole_and_truncate() -> io::Result<()> {
    println!("selftest-ext2-write: sparse create");
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(DATA_PATH)?;
    file.write_all(b"head")?;
    file.seek(SeekFrom::Start(2 * BLOCK_SIZE as u64 + 3))?;
    file.write_all(b"Z")?;
    file.sync_all()?;
    drop(file);

    println!("selftest-ext2-write: sparse read");
    let mut bytes = fs::read(DATA_PATH)?;
    require(bytes.len() == 2 * BLOCK_SIZE + 4, "sparse file size")?;
    require(&bytes[..4] == b"head", "sparse prefix")?;
    require(
        bytes[4..2 * BLOCK_SIZE + 3].iter().all(|byte| *byte == 0),
        "hole zero fill",
    )?;
    require(bytes[2 * BLOCK_SIZE + 3] == b'Z', "sparse suffix")?;

    println!("selftest-ext2-write: seek append");
    let mut seek_append = OpenOptions::new().write(true).open(DATA_PATH)?;
    seek_append.seek(SeekFrom::End(0))?;
    seek_append.write_all(b"seek-tail")?;
    seek_append.sync_all()?;
    drop(seek_append);
    bytes = fs::read(DATA_PATH)?;
    require(bytes.ends_with(b"Zseek-tail"), "seek append at eof")?;

    println!("selftest-ext2-write: O_APPEND");
    let mut append = OpenOptions::new().append(true).open(DATA_PATH)?;
    append.seek(SeekFrom::Start(0))?;
    append.write_all(b"append-tail")?;
    append.sync_all()?;
    drop(append);
    bytes = fs::read(DATA_PATH)?;
    require(
        bytes.ends_with(b"Zseek-tailappend-tail"),
        "O_APPEND used current eof",
    )?;

    println!("selftest-ext2-write: truncate resize");
    let file = OpenOptions::new().write(true).open(DATA_PATH)?;
    file.set_len(5)?;
    file.set_len(BLOCK_SIZE as u64 + 1)?;
    file.sync_all()?;
    drop(file);
    bytes = fs::read(DATA_PATH)?;
    require(bytes.len() == BLOCK_SIZE + 1, "truncate extension size")?;
    require(&bytes[..4] == b"head", "truncate retained prefix")?;
    require(
        bytes[4..].iter().all(|byte| *byte == 0),
        "truncate extension zero fill",
    )?;

    println!("selftest-ext2-write: truncate rewrite");
    let mut file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(DATA_PATH)?;
    file.write_all(PERSISTED)?;
    file.sync_all()
}

fn verify_single_indirect() -> io::Result<()> {
    println!("selftest-ext2-write: indirect write");
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(INDIRECT_PATH)?;
    let mut block = [0u8; BLOCK_SIZE];
    for index in 0..13usize {
        block.fill(index as u8);
        file.write_all(&block)?;
    }
    file.sync_all()?;
    drop(file);

    let bytes = fs::read(INDIRECT_PATH)?;
    require(
        bytes.len() == SINGLE_INDIRECT_FILE_LEN,
        "single indirect size",
    )?;
    for index in 0..13usize {
        require(
            bytes[index * BLOCK_SIZE..(index + 1) * BLOCK_SIZE]
                .iter()
                .all(|byte| *byte == index as u8),
            "single indirect contents",
        )?;
    }
    Ok(())
}

fn verify_errors() -> io::Result<()> {
    println!("selftest-ext2-write: error cases");
    expect_errno(
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(DATA_PATH)
            .map(|_| ()),
        17,
        "O_EXCL",
    )?;
    expect_errno(
        OpenOptions::new().write(true).open("/tmp").map(|_| ()),
        21,
        "directory write",
    )?;

    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(LIMIT_PATH)?;
    file.seek(SeekFrom::Start(MAX_WRITABLE_SIZE))?;
    expect_errno(file.write_all(b"x"), 27, "single indirect limit")?;
    file.seek(SeekFrom::Start(0))?;
    expect_errno(
        file.seek(SeekFrom::Current(-1)).map(|_| ()),
        22,
        "negative seek",
    )
}

fn prepare() -> io::Result<()> {
    verify_create_and_overwrite()?;
    verify_hole_and_truncate()?;
    verify_single_indirect()?;
    verify_errors()?;
    verify_fd_errors()?;
    println!("selftest-ext2-write: prepare marker");
    fs::write(PREPARE_PASS_PATH, b"pass\n")?;
    File::open(PREPARE_PASS_PATH)?.sync_all()
}

fn verify_enospc() -> io::Result<()> {
    println!("selftest-ext2-write: enospc");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(ENOSPC_PATH)?;
    let block = [0x5au8; BLOCK_SIZE];
    let mut written = 0usize;
    loop {
        match file.write(&block) {
            Ok(0) => return Err(io::Error::other("ENOSPC write returned zero")),
            Ok(count) => written += count,
            Err(error) if error.raw_os_error() == Some(28) => break,
            Err(error) => return Err(error),
        }
    }
    require(written != 0, "ENOSPC test made no progress")?;
    file.sync_all()?;
    drop(file);
    let persisted_len = fs::read(ENOSPC_PATH)?.len();
    if persisted_len != written {
        return Err(io::Error::other(format!(
            "ENOSPC partial write size: returned={written} persisted={persisted_len}"
        )));
    }
    println!("selftest-ext2-write: pass enospc");
    Ok(())
}

fn verify() -> io::Result<()> {
    println!("selftest-ext2-write: reboot verify");
    require(fs::read(DATA_PATH)? == PERSISTED, "reboot data persistence")?;
    let bytes = fs::read(INDIRECT_PATH)?;
    require(
        bytes.len() == SINGLE_INDIRECT_FILE_LEN,
        "reboot indirect size",
    )?;
    require(
        bytes[12 * BLOCK_SIZE..].iter().all(|byte| *byte == 12),
        "reboot indirect contents",
    )?;
    fs::write(VERIFY_PASS_PATH, b"pass\n")?;
    File::open(VERIFY_PASS_PATH)?.sync_all()
}

fn main() {
    let mode = std::env::args().nth(1);
    let result = match mode.as_deref() {
        Some("prepare") => prepare(),
        Some("verify") => verify(),
        Some("enospc") => verify_enospc(),
        _ if fs::metadata(ENOSPC_MODE_PATH).is_ok() => verify_enospc(),
        _ if fs::metadata(PREPARE_PASS_PATH).is_ok() => verify(),
        _ => prepare(),
    };
    if let Err(error) = result {
        eprintln!("selftest-ext2-write: {error}");
        std::process::exit(1);
    }
    if fs::metadata(ENOSPC_MODE_PATH).is_err() {
        println!(
            "selftest-ext2-write: pass {}",
            if fs::metadata(VERIFY_PASS_PATH).is_ok() {
                "verify"
            } else {
                "prepare"
            }
        );
    }
}
