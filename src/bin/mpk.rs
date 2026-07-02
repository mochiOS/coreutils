use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use std::fs;
use std::io;
use std::path::Path;

#[derive(Clone)]
struct MpkgHeader {
    header_size: usize,
    compression: u8,
    expanded_size: usize,
}

#[derive(Clone)]
struct TarEntry {
    path: String,
    kind: u8,
    data: Vec<u8>,
}

#[derive(Default)]
struct PackageInfo {
    id: String,
    name: String,
    kind: Option<String>,
}

fn invalid_data() -> io::Error {
    io::Error::from_raw_os_error(libc::EINVAL)
}

fn permission_denied() -> io::Error {
    io::Error::from_raw_os_error(libc::EACCES)
}

fn parse_octal(bytes: &[u8]) -> io::Result<usize> {
    let mut out = 0usize;
    let mut seen = false;
    for &byte in bytes {
        if byte == 0 || byte == b' ' {
            break;
        }
        if !(b'0'..=b'7').contains(&byte) {
            return Err(invalid_data());
        }
        seen = true;
        out = out
            .checked_mul(8)
            .and_then(|value| value.checked_add((byte - b'0') as usize))
            .ok_or_else(invalid_data)?;
    }
    if seen { Ok(out) } else { Ok(0) }
}

fn trim_cstr(bytes: &[u8]) -> &[u8] {
    let len = bytes.iter().position(|&byte| byte == 0).unwrap_or(bytes.len());
    &bytes[..len]
}

fn is_valid_rel_path(path: &str) -> bool {
    if path.is_empty()
        || path.starts_with('/')
        || path.contains('\\')
        || path.contains('\0')
        || path.contains("//")
        || path.ends_with('/')
    {
        return false;
    }
    path.split('/')
        .all(|seg| !seg.is_empty() && seg != "." && seg != "..")
}

fn parse_header(bytes: &[u8]) -> io::Result<MpkgHeader> {
    if bytes.len() < 32 || &bytes[..4] != b"MPKG" {
        return Err(invalid_data());
    }
    let major = u16::from_le_bytes([bytes[4], bytes[5]]);
    let header_size = u16::from_le_bytes([bytes[8], bytes[9]]) as usize;
    let compression = bytes[10];
    let flags = bytes[11];
    let expanded_size = u64::from_le_bytes([
        bytes[12], bytes[13], bytes[14], bytes[15], bytes[16], bytes[17], bytes[18], bytes[19],
    ]) as usize;
    if major != 1 || header_size != 32 || flags != 0 || compression > 1 {
        return Err(invalid_data());
    }
    if bytes[20..32].iter().any(|&byte| byte != 0) {
        return Err(invalid_data());
    }
    Ok(MpkgHeader {
        header_size,
        compression,
        expanded_size,
    })
}

fn parse_tar_stream(bytes: &[u8]) -> io::Result<Vec<TarEntry>> {
    let mut entries = Vec::new();
    let mut offset = 0usize;
    while offset + 512 <= bytes.len() {
        let block = &bytes[offset..offset + 512];
        if block.iter().all(|&byte| byte == 0) {
            break;
        }
        let name = trim_cstr(&block[0..100]);
        let prefix = trim_cstr(&block[345..500]);
        let mut path = String::new();
        if !prefix.is_empty() {
            path.push_str(std::str::from_utf8(prefix).map_err(|_| invalid_data())?);
            path.push('/');
        }
        path.push_str(std::str::from_utf8(name).map_err(|_| invalid_data())?);
        if !is_valid_rel_path(&path) {
            return Err(invalid_data());
        }
        let size = parse_octal(&block[124..136])?;
        let kind = block[156];
        let payload_start = offset + 512;
        let payload_end = payload_start.checked_add(size).ok_or_else(invalid_data)?;
        if payload_end > bytes.len() {
            return Err(invalid_data());
        }
        if kind != b'0' && kind != 0 && kind != b'5' {
            return Err(invalid_data());
        }
        if entries.iter().any(|entry: &TarEntry| entry.path == path) {
            return Err(invalid_data());
        }
        if path != "manifest.toml" && !path.starts_with("signatures/") && !path.starts_with("payload/") {
            return Err(invalid_data());
        }
        entries.push(TarEntry {
            path,
            kind,
            data: bytes[payload_start..payload_end].to_vec(),
        });
        offset = payload_end.div_ceil(512) * 512;
    }
    Ok(entries)
}

fn entry_by_path<'a>(entries: &'a [TarEntry], path: &str) -> io::Result<&'a TarEntry> {
    entries
        .iter()
        .find(|entry| entry.path == path)
        .ok_or_else(|| io::Error::from_raw_os_error(libc::ENOENT))
}

fn unquote(value: &str) -> &str {
    value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .unwrap_or(value)
}

fn parse_manifest(text: &str) -> io::Result<PackageInfo> {
    let mut info = PackageInfo::default();
    let mut in_package = false;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line == "[package]" {
            in_package = true;
            continue;
        }
        if line.starts_with('[') {
            in_package = false;
            continue;
        }
        if !in_package {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = unquote(value.trim()).to_string();
        match key {
            "id" => info.id = value,
            "name" => info.name = value,
            "kind" => info.kind = Some(value),
            _ => {}
        }
    }
    if info.id.is_empty() || info.name.is_empty() {
        return Err(invalid_data());
    }
    match info.kind.as_deref() {
        None | Some("binary") | Some("application") => Ok(info),
        _ => Err(invalid_data()),
    }
}

fn decode_cert(bytes: &[u8]) -> io::Result<VerifyingKey> {
    if bytes.len() == 32 {
        let mut key = [0u8; 32];
        key.copy_from_slice(bytes);
        return VerifyingKey::from_bytes(&key).map_err(|_| invalid_data());
    }
    Err(invalid_data())
}

fn verify_manifest(entries: &[TarEntry], manifest_text: &str) -> io::Result<()> {
    let sig = entry_by_path(entries, "signatures/manifest.sig")?;
    let cert = entry_by_path(entries, "signatures/developer.cert")?;
    let verifier = decode_cert(&cert.data)?;
    let signature_bytes: [u8; 64] = sig
        .data
        .as_slice()
        .try_into()
        .map_err(|_| invalid_data())?;
    let signature = Signature::from_bytes(&signature_bytes);
    let digest = Sha256::digest(manifest_text.as_bytes());
    let mut msg = Vec::with_capacity(32 + digest.len());
    msg.extend_from_slice(b"mochios-mpkg-manifest-v1\0");
    msg.extend_from_slice(&digest);
    verifier.verify(&msg, &signature).map_err(|_| permission_denied())
}

fn join_path(prefix: &str, suffix: &str) -> String {
    if prefix.is_empty() {
        return suffix.to_string();
    }
    if suffix.is_empty() {
        return prefix.to_string();
    }
    format!("{}/{}", prefix.trim_end_matches('/'), suffix.trim_start_matches('/'))
}

fn write_file(path: &str, data: &[u8]) -> io::Result<()> {
    if let Some(parent) = Path::new(path).parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    fs::write(path, data)
}

fn install_package(mpkg_path: &str) -> io::Result<()> {
    let bytes = fs::read(mpkg_path)?;
    let header = parse_header(&bytes)?;
    if header.compression != 0 {
        return Err(io::Error::from_raw_os_error(libc::ENOTSUP));
    }
    let tar = bytes.get(header.header_size..).ok_or_else(invalid_data)?;
    if tar.len() != header.expanded_size {
        return Err(invalid_data());
    }
    let entries = parse_tar_stream(tar)?;
    let manifest_entry = entry_by_path(&entries, "manifest.toml")?;
    let manifest_text = std::str::from_utf8(&manifest_entry.data).map_err(|_| invalid_data())?;
    let manifest = parse_manifest(manifest_text)?;
    verify_manifest(&entries, manifest_text)?;

    let package_root = format!("/system/packages/{}", manifest.id);
    write_file(&format!("{}/manifest.toml", package_root), &manifest_entry.data)?;

    let install_root = if manifest.kind.as_deref() == Some("application") {
        format!("/applications/{}.app", manifest.name)
    } else {
        String::new()
    };

    for entry in entries {
        if entry.path == "manifest.toml" || entry.path.starts_with("signatures/") {
            continue;
        }
        if entry.kind == b'5' {
            continue;
        }
        let target = if let Some(rel) = entry.path.strip_prefix("payload/root/") {
            join_path("/", rel)
        } else if let Some(rel) = entry.path.strip_prefix("payload/bundle/") {
            if install_root.is_empty() {
                return Err(invalid_data());
            }
            join_path(&install_root, rel)
        } else {
            return Err(invalid_data());
        };
        let allowed = target.starts_with("/bin/")
            || target.starts_with("/libraries/")
            || target.starts_with("/binary/services/")
            || target.starts_with("/binary/resources/")
            || target.starts_with("/system/services/")
            || (target.starts_with("/applications/") && install_root.starts_with("/applications/"));
        if !allowed {
            return Err(invalid_data());
        }
        write_file(&target, &entry.data)?;
    }
    Ok(())
}

fn main() -> io::Result<()> {
    let args = coreutils::args();
    if args.len() != 1 {
        coreutils::usage("mpk", "PACKAGE.mpkg");
    }

    install_package(&args[0].to_string_lossy())
}
