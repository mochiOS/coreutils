use std::fs::{self, OpenOptions};
use std::io;

const DATA_FONT: &str = "/libraries/fonts/kvm-layout-test.font";
const EROFS: i32 = 30;

fn expect_read_only(result: io::Result<()>, operation: &str) -> io::Result<()> {
    match result {
        Err(error) if error.raw_os_error() == Some(EROFS) => Ok(()),
        Err(error) => Err(io::Error::other(format!("{operation}: expected EROFS, got {error}"))),
        Ok(()) => Err(io::Error::other(format!("{operation}: unexpectedly succeeded"))),
    }
}

fn run() -> io::Result<()> {
    let system_font = fs::metadata("/system/libraries/fonts/InterVariable.ttf")?;
    if !system_font.is_file() || system_font.len() == 0 { return Err(io::Error::other("system font missing")); }
    if fs::metadata("/libraries/fonts/InterVariable.ttf").is_ok() {
        return Err(io::Error::other("system font leaked into Data libraries"));
    }
    fs::write(DATA_FONT, b"data-font-fixture\n")?;
    if fs::read(DATA_FONT)? != b"data-font-fixture\n" { return Err(io::Error::other("Data library write mismatch")); }
    expect_read_only(fs::write("/system/.installed", b"tampered\n"), "overwrite /system")?;
    expect_read_only(
        OpenOptions::new().write(true).truncate(true).open("/bin/msh").map(|_| ()),
        "overwrite System command through /bin",
    )?;
    println!("selftest-system-layout: pass");
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("selftest-system-layout: FAIL {error}");
        std::process::exit(1);
    }
}
