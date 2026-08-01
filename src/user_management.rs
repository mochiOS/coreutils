use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use mochios_user_database::{UserDatabase, UserRecord};

#[cfg(not(target_os = "mochios"))]
use mochios_user_database::DATABASE_PATH;

#[cfg(target_os = "mochios")]
use mochios_user_protocol::{
    AddUser, MAX_CHUNK_LEN, MAX_MESSAGE_LEN, RemoveUser, SnapshotChunk, SnapshotChunkRequest,
    SnapshotInfo, SnapshotRequest, Status,
};

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
    #[cfg(target_os = "mochios")]
    {
        return load_database_from_service();
    }
    #[cfg(not(target_os = "mochios"))]
    load_database_at(Path::new(DATABASE_PATH))
}

#[cfg(not(target_os = "mochios"))]
pub fn save_database(database: &UserDatabase) -> io::Result<()> {
    save_database_at(Path::new(DATABASE_PATH), database)
}

pub fn add_user(user: UserRecord) -> io::Result<()> {
    #[cfg(target_os = "mochios")]
    {
        let encoded = user
            .encode()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        return mutate_service(|request_id, output| {
            AddUser {
                request_id,
                encoded_record: &encoded,
            }
            .encode(output)
        });
    }
    #[cfg(not(target_os = "mochios"))]
    {
        let mut database = load_database()?;
        database
            .add(user)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        save_database(&database)
    }
}

pub fn remove_user(name: &str) -> io::Result<UserRecord> {
    let database = load_database()?;
    let user = database
        .find_name(name)
        .cloned()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "user was not found"))?;
    #[cfg(target_os = "mochios")]
    {
        mutate_service(|request_id, output| RemoveUser { request_id, name }.encode(output))?;
        return Ok(user);
    }
    #[cfg(not(target_os = "mochios"))]
    {
        let mut database = database;
        database
            .remove(name)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        save_database(&database)?;
        Ok(user)
    }
}

#[cfg(target_os = "mochios")]
fn load_database_from_service() -> io::Result<UserDatabase> {
    const MAX_DATABASE_BYTES: usize = 1024 * 1024;
    for _ in 0..3 {
        let service = find_user_service()?;
        let request_id = next_request_id();
        let mut request = [0u8; mochios_user_protocol::SNAPSHOT_REQUEST_LEN];
        let request_len = SnapshotRequest { request_id }
            .encode(&mut request)
            .map_err(protocol_encode_error)?;
        let mut reply = [0u8; MAX_MESSAGE_LEN];
        let reply_len = ipc_call(service, &request[..request_len], &mut reply)?;
        if let Ok(status) = Status::decode(&reply[..reply_len]) {
            return Err(status_error(status));
        }
        let info = SnapshotInfo::decode(&reply[..reply_len]).map_err(protocol_decode_error)?;
        if info.request_id != request_id {
            return Err(invalid_response("snapshot request ID mismatch"));
        }
        let total_len = usize::try_from(info.total_len)
            .ok()
            .filter(|length| *length > 0 && *length <= MAX_DATABASE_BYTES)
            .ok_or_else(|| invalid_response("invalid snapshot length"))?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(total_len)
            .map_err(|_| io::Error::from_raw_os_error(libc::ENOMEM))?;
        while bytes.len() < total_len {
            let requested = (total_len - bytes.len()).min(MAX_CHUNK_LEN);
            let chunk_request = SnapshotChunkRequest {
                request_id,
                offset: bytes.len() as u64,
                length: requested as u32,
            };
            let mut request = [0u8; mochios_user_protocol::CHUNK_REQUEST_LEN];
            let request_len = chunk_request
                .encode(&mut request)
                .map_err(protocol_encode_error)?;
            let reply_len = ipc_call(service, &request[..request_len], &mut reply)?;
            if let Ok(status) = Status::decode(&reply[..reply_len]) {
                return Err(status_error(status));
            }
            let chunk =
                SnapshotChunk::decode(&reply[..reply_len]).map_err(protocol_decode_error)?;
            if chunk.request_id != request_id
                || chunk.offset != bytes.len() as u64
                || chunk.generation != info.generation
                || chunk.bytes.len() > total_len - bytes.len()
            {
                bytes.clear();
                break;
            }
            bytes.extend_from_slice(chunk.bytes);
        }
        if bytes.len() == total_len {
            return UserDatabase::parse(&bytes)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error));
        }
    }
    Err(invalid_response("user database changed during snapshot"))
}

#[cfg(target_os = "mochios")]
fn mutate_service(
    encode: impl FnOnce(u64, &mut [u8]) -> Result<usize, mochios_user_protocol::EncodeError>,
) -> io::Result<()> {
    let service = find_user_service()?;
    let request_id = next_request_id();
    let mut request = [0u8; MAX_MESSAGE_LEN];
    let request_len = encode(request_id, &mut request).map_err(protocol_encode_error)?;
    let mut reply = [0u8; mochios_user_protocol::STATUS_LEN];
    let reply_len = ipc_call(service, &request[..request_len], &mut reply)?;
    let status = Status::decode(&reply[..reply_len]).map_err(protocol_decode_error)?;
    if status.request_id != request_id {
        return Err(invalid_response("mutation request ID mismatch"));
    }
    if status.status == 0 {
        Ok(())
    } else {
        Err(status_error(status))
    }
}

#[cfg(target_os = "mochios")]
fn find_user_service() -> io::Result<u64> {
    const NAME: &str = "user.service";
    for _ in 0..64 {
        let endpoint = mochi_user_syscall::call2(
            mochi_user_syscall::SyscallNumber::FindProcessByName,
            NAME.as_ptr() as u64,
            NAME.len() as u64,
        )
        .map_err(syscall_error)?;
        if endpoint != 0 {
            return Ok(endpoint);
        }
        let _ = mochi_user_syscall::call0(mochi_user_syscall::SyscallNumber::ThreadYield);
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "user.service was not found",
    ))
}

#[cfg(target_os = "mochios")]
fn ipc_call(destination: u64, request: &[u8], reply: &mut [u8]) -> io::Result<usize> {
    let length = mochi_user_syscall::call5(
        mochi_user_syscall::SyscallNumber::IpcCall,
        destination,
        request.as_ptr() as u64,
        request.len() as u64,
        reply.as_mut_ptr() as u64,
        reply.len() as u64,
    )
    .map_err(syscall_error)?;
    usize::try_from(length).map_err(|_| invalid_response("invalid IPC reply length"))
}

#[cfg(target_os = "mochios")]
fn next_request_id() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed).max(1)
}

#[cfg(target_os = "mochios")]
fn status_error(status: Status) -> io::Error {
    let errno = status.status.checked_neg().unwrap_or(libc::EIO);
    io::Error::from_raw_os_error(errno)
}

#[cfg(target_os = "mochios")]
fn syscall_error(error: mochi_user_syscall::SysError) -> io::Error {
    io::Error::from_raw_os_error(error.errno().unwrap_or(libc::EIO as u64) as i32)
}

#[cfg(target_os = "mochios")]
fn protocol_encode_error(error: mochios_user_protocol::EncodeError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, format!("{error:?}"))
}

#[cfg(target_os = "mochios")]
fn protocol_decode_error(error: mochios_user_protocol::DecodeError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("{error:?}"))
}

#[cfg(target_os = "mochios")]
fn invalid_response(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
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

#[cfg(not(target_os = "mochios"))]
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

#[cfg(not(target_os = "mochios"))]
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
