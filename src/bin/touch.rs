use std::fs::OpenOptions;
use std::io;

fn main() -> io::Result<()> {
    let args = coreutils::args();
    if args.is_empty() {
        coreutils::usage("touch", "FILE...");
    }
    for arg in args {
        OpenOptions::new().create(true).append(true).open(&arg)?;
    }
    Ok(())
}
