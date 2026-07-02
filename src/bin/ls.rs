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
    match fs::read_dir(path) {
        Ok(entries) => {
            if multi {
                println!("{}:", path.display());
            }
            let mut entries = entries.collect::<Result<Vec<_>, _>>()?;
            entries.sort_by_key(|entry| entry.file_name());
            for entry in entries {
                println!("{}", entry.file_name().to_string_lossy());
            }
            Ok(())
        }
        Err(error) if error.kind() == io::ErrorKind::NotADirectory => {
            fs::metadata(path)?;
            println!("{}", path.display());
            Ok(())
        }
        Err(error) => Err(error),
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
