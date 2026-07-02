use std::fs;
use std::io;

fn main() -> io::Result<()> {
    let args = coreutils::args();
    if args.is_empty() {
        coreutils::usage("rm", "FILE...");
    }
    for arg in args {
        fs::remove_file(&arg)?;
    }
    Ok(())
}
