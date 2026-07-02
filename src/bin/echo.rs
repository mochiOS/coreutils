use std::io::{self, Write};

fn main() -> io::Result<()> {
    let args = coreutils::args();
    let mut stdout = io::stdout().lock();
    for (index, arg) in args.iter().enumerate() {
        if index > 0 {
            stdout.write_all(b" ")?;
        }
        stdout.write_all(arg.to_string_lossy().as_bytes())?;
    }
    stdout.write_all(b"\n")?;
    Ok(())
}
