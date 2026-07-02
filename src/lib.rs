use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub fn args() -> Vec<OsString> {
    std::env::args_os().skip(1).collect()
}

pub fn usage(command: &str, synopsis: &str) -> ! {
    eprintln!("usage: {command} {synopsis}");
    std::process::exit(1);
}

pub fn unsupported(message: &str) -> ! {
    eprintln!("{message}");
    std::process::exit(1);
}

pub fn parse_paths(arguments: &[OsString], empty_current_dir: bool) -> Vec<PathBuf> {
    if arguments.is_empty() && empty_current_dir {
        vec![PathBuf::from(".")]
    } else {
        arguments.iter().map(PathBuf::from).collect()
    }
}

pub fn sorted_dir_entries(path: &Path) -> io::Result<Vec<fs::DirEntry>> {
    let mut entries = fs::read_dir(path)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    Ok(entries)
}
