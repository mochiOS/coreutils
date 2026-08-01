use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use mochios_user_database::{DATABASE_PATH, UserDatabase, UserRecord};

const STANDARD_HOME_DIRECTORIES: [&str; 6] = [
    "Desktop",
    "Documents",
    "Downloads",
    "Movies",
    "Music",
    "Pictures",
];

pub fn require_root() -> io::Result<()> {
    let uid = unsafe { libc::geteuid() };
    if uid == 0 {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "user management requires the root account",
        ))
    }
}

pub fn load_database() -> io::Result<UserDatabase> {
    load_database_at(Path::new(DATABASE_PATH))
}

pub fn save_database(database: &UserDatabase) -> io::Result<()> {
    save_database_at(Path::new(DATABASE_PATH), database)
}

pub fn create_home(record: &UserRecord) -> io::Result<()> {
    let home = Path::new(&record.home);
    if !is_managed_home(home, &record.name) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "home must be /home/<user name>",
        ));
    }
    fs::create_dir_all(home)?;
    for name in STANDARD_HOME_DIRECTORIES {
        fs::create_dir_all(home.join(name))?;
    }
    Ok(())
}

pub fn remove_home(record: &UserRecord) -> io::Result<()> {
    let home = Path::new(&record.home);
    if !is_managed_home(home, &record.name) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "refusing to remove an unmanaged home directory",
        ));
    }
    match fs::symlink_metadata(home) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "refusing to follow a home directory symlink",
        )),
        Ok(metadata) if metadata.is_dir() => remove_directory_tree(home),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "home path is not a directory",
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn load_database_at(path: &Path) -> io::Result<UserDatabase> {
    match fs::read(path) {
        Ok(bytes) => parse_database(&bytes),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            for recovery in [temporary_path(path), backup_path(path)] {
                match fs::read(&recovery) {
                    Ok(bytes) => return parse_database(&bytes),
                    Err(candidate) if candidate.kind() == io::ErrorKind::NotFound => {}
                    Err(candidate) => return Err(candidate),
                }
            }
            Ok(UserDatabase::with_root())
        }
        Err(error) => Err(error),
    }
}

fn save_database_at(path: &Path, database: &UserDatabase) -> io::Result<()> {
    let bytes = database
        .encode()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "user database has no parent")
    })?;
    fs::create_dir_all(parent)?;

    let temporary = temporary_path(path);
    let backup = backup_path(path);
    remove_if_present(&temporary)?;
    write_synced(&temporary, &bytes)?;
    remove_if_present(&backup)?;

    let had_database = match fs::rename(path, &backup) {
        Ok(()) => true,
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(error) => {
            remove_if_present(&temporary)?;
            return Err(error);
        }
    };

    if let Err(error) = fs::rename(&temporary, path) {
        if had_database {
            let _ = fs::rename(&backup, path);
        }
        return Err(error);
    }
    if had_database {
        remove_if_present(&backup)?;
    }
    Ok(())
}

fn parse_database(bytes: &[u8]) -> io::Result<UserDatabase> {
    UserDatabase::parse(bytes).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

fn write_synced(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

fn remove_if_present(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn remove_directory_tree(path: &Path) -> io::Result<()> {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let child = entry.path();
        let metadata = fs::symlink_metadata(&child)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            fs::remove_file(child)?;
        } else {
            remove_directory_tree(&child)?;
        }
    }
    fs::remove_dir(path)
}

fn temporary_path(path: &Path) -> PathBuf {
    path.with_extension("db.new")
}

fn backup_path(path: &Path) -> PathBuf {
    path.with_extension("db.backup")
}

fn is_managed_home(path: &Path, name: &str) -> bool {
    path == Path::new("/home").join(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temporary_database_path(test: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "mochios-user-database-{}-{test}-{nonce}.db",
            std::process::id()
        ))
    }

    #[test]
    fn persistence_round_trips_and_removes_backup() {
        let path = temporary_database_path("round-trip");
        let mut database = UserDatabase::with_root();
        database
            .add(UserRecord::regular("alice", 1000, 1000))
            .unwrap();
        save_database_at(&path, &database).unwrap();
        assert_eq!(load_database_at(&path).unwrap(), database);
        assert!(!backup_path(&path).exists());
        assert!(!temporary_path(&path).exists());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn missing_primary_recovers_valid_backup() {
        let path = temporary_database_path("backup");
        let database = UserDatabase::with_root();
        write_synced(&backup_path(&path), &database.encode().unwrap()).unwrap();
        assert_eq!(load_database_at(&path).unwrap(), database);
        fs::remove_file(backup_path(&path)).unwrap();
    }

    #[test]
    fn home_removal_is_limited_to_matching_user_path() {
        assert!(is_managed_home(Path::new("/home/alice"), "alice"));
        assert!(!is_managed_home(Path::new("/home/bob"), "alice"));
        assert!(!is_managed_home(Path::new("/"), "root"));
    }
}
