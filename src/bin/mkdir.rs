use std::fs;
use std::io;

fn main() -> io::Result<()> {
    let args = coreutils::args();
    if args.is_empty() {
        coreutils::usage("mkdir", "DIR...");
    }
    for arg in args {
        fs::create_dir(&arg)?;
    }
    Ok(())
}
