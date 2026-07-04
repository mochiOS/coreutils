use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

fn transient_pause() {
    for _ in 0..256 {
        core::hint::spin_loop();
    }
}

fn collect_dir_entries(entries: fs::ReadDir) -> io::Result<Vec<fs::DirEntry>> {
    let mut out = Vec::new();
    for entry in entries {
        match entry {
            Ok(entry) => out.push(entry),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                transient_pause();
                continue;
            }
            Err(error) => return Err(error),
        }
    }
    out.sort_by_key(|entry| entry.file_name());
    Ok(out)
}

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
    let mut last_error = None;
    for _ in 0..8 {
        match fs::read_dir(path) {
            Ok(entries) => return collect_dir_entries(entries),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                last_error = Some(error);
                transient_pause();
            }
            Err(error) => return Err(error),
        }
    }
    match fs::read_dir(path) {
        Ok(entries) => collect_dir_entries(entries),
        Err(error) => Err(last_error.unwrap_or(error)),
    }
}
