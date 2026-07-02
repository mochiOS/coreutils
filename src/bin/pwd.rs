use std::env;
use std::io;

fn main() -> io::Result<()> {
    let args = coreutils::args();
    if !args.is_empty() {
        coreutils::usage("pwd", "");
    }
    println!("{}", env::current_dir()?.display());
    Ok(())
}
