use std::fs;
use std::io;
use std::path::Path;

fn list_dir(path: &Path, multi: bool) -> io::Result<()> {
    if multi {
        println!("{}:", path.display());
    }
    for entry in coreutils::sorted_dir_entries(path)? {
        println!("{}", entry.file_name().to_string_lossy());
    }
    Ok(())
}

fn list_path(path: &Path, multi: bool) -> io::Result<()> {
    let metadata = fs::metadata(path)?;
    if metadata.is_dir() {
        list_dir(path, multi)
    } else {
        println!("{}", path.display());
        Ok(())
    }
}

fn main() -> io::Result<()> {
    let args = coreutils::args();
    let paths = coreutils::parse_paths(&args, true);
    let multi = paths.len() > 1;

    for (index, path) in paths.iter().enumerate() {
        if index > 0 && multi {
            println!();
        }
        list_path(path, multi)?;
    }
    Ok(())
}
