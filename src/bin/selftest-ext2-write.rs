use std::fs::{self, File, OpenOptions};
use std::io::{self, Seek, SeekFrom, Write};

const DATA_PATH: &str = "/tmp/ext2-write-data.bin";
const INDIRECT_PATH: &str = "/tmp/ext2-write-indirect.bin";
const LIMIT_PATH: &str = "/tmp/ext2-write-limit.bin";
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

    println!("selftest-ext2-write: append");
    let mut append = OpenOptions::new().append(true).open(DATA_PATH)?;
    append.write_all(b"tail")?;
    append.sync_all()?;
    drop(append);
    bytes = fs::read(DATA_PATH)?;
    require(bytes.ends_with(b"Ztail"), "append at eof")?;

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
    verify_hole_and_truncate()?;
    verify_single_indirect()?;
    verify_errors()?;
    println!("selftest-ext2-write: prepare marker");
    fs::write(PREPARE_PASS_PATH, b"pass\n")?;
    File::open(PREPARE_PASS_PATH)?.sync_all()
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
        _ if fs::metadata(PREPARE_PASS_PATH).is_ok() => verify(),
        _ => prepare(),
    };
    if let Err(error) = result {
        eprintln!("selftest-ext2-write: {error}");
        std::process::exit(1);
    }
    println!(
        "selftest-ext2-write: pass {}",
        if fs::metadata(VERIFY_PASS_PATH).is_ok() {
            "verify"
        } else {
            "prepare"
        }
    );
}
