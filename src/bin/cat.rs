use std::fs::File;
use std::io::{self, Read, Write};

fn main() -> io::Result<()> {
    let args = coreutils::args();
    if args.is_empty() {
        coreutils::usage("cat", "FILE...");
    }

    let mut stdout = io::stdout().lock();
    let mut buffer = [0_u8; 4096];

    for arg in args {
        let mut file = File::open(&arg)?;
        loop {
            let read = file.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            stdout.write_all(&buffer[..read])?;
        }
    }
    Ok(())
}
