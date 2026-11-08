use std::io;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy)]
enum Mutation {
    Install,
    Update,
    Remove,
}

impl Mutation {
    const fn present_participle(self) -> &'static str {
        match self {
            Self::Install => "Installing",
            Self::Update => "Updating",
            Self::Remove => "Removing",
        }
    }

    const fn completion(self) -> &'static str {
        match self {
            Self::Install => "Installation complete.",
            Self::Update => "Update complete.",
            Self::Remove => "Removal complete.",
        }
    }
}

fn errno_io(errno: u64) -> io::Error {
    io::Error::from_raw_os_error(errno as i32)
}

fn absolute_package_path(path: &Path) -> io::Result<PathBuf> {
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    Ok(std::env::current_dir()?.join(path))
}

fn mutate_via_package_service(mutation: Mutation, subject: &str) -> io::Result<()> {
    use mochios_package_protocol::Request;
    mochios_package_client::mutate(
        match mutation {
            Mutation::Install => Request::Install(subject),
            Mutation::Update => Request::Update(subject),
            Mutation::Remove => Request::Remove(subject),
        },
        None,
    )
}

fn main() -> io::Result<()> {
    let args = coreutils::args();
    let (mutation, package) = match args.as_slice() {
        [package] => (Mutation::Install, package.as_os_str()),
        [command, package] if command == "install" => (Mutation::Install, package.as_os_str()),
        [command, package] if command == "update" => (Mutation::Update, package.as_os_str()),
        [command, package] if command == "remove" => (Mutation::Remove, package.as_os_str()),
        _ => coreutils::usage("mpk", "[install|update] PACKAGE.mpkg | remove PACKAGE_ID"),
    };
    let package = package
        .to_str()
        .ok_or_else(|| errno_io(libc::EINVAL as u64))?;

    let subject = if matches!(mutation, Mutation::Remove) {
        package.to_string()
    } else {
        absolute_package_path(Path::new(package))?
            .to_string_lossy()
            .into_owned()
    };
    println!("{} {}...", mutation.present_participle(), subject);
    match mutate_via_package_service(mutation, &subject) {
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
            eprintln!(
                "mpk: Package state or trust data changed or authorization expired; retry to request fresh authorization"
            );
            Err(error)
        }
        Ok(()) => {
            println!("{}", mutation.completion());
            Ok(())
        }
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absolute_package_path_preserves_absolute_input() {
        let path = Path::new("/system/samples/example.mpkg");
        assert_eq!(absolute_package_path(path).unwrap(), path);
    }

    #[test]
    fn absolute_package_path_resolves_relative_input() {
        let relative = Path::new("system/samples/example.mpkg");
        assert_eq!(
            absolute_package_path(relative).unwrap(),
            std::env::current_dir().unwrap().join(relative)
        );
    }
}
