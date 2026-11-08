//! The KVM quality suite runs through the same launch and capability policy as
//! any other installed command. Reports use the ordinary diagnostic console.
#[cfg(not(target_os = "mochios"))]
fn main() {
    eprintln!("os-test requires mochiOS; use mmake host-test on the host");
    std::process::exit(77);
}

#[cfg(target_os = "mochios")]
fn main() {
    use mochios_test_support::{Reporter, run_case, run_suite};
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.as_slice() {
        [flag, id] if flag == "--case" => run_case(native::CASES, id),
        [run_id] => (|| {
            let mut reporter = Reporter::new(native::ReportWriter::default(), run_id)
                .map_err(|e| e.to_string())?;
            let status = run_suite(native::CASES, &mut reporter)
                .map(|passed| if passed { 0 } else { 1 })
                .map_err(|e| e.to_string())?;
            native::finish_report(run_id, status).map_err(|e| e.to_string())?;
            Ok::<_, String>(status)
        })()
        .unwrap_or_else(|e| {
            eprintln!("os-test: {e}");
            1
        }),
        _ => {
            eprintln!("usage: os-test RUN_ID");
            2
        }
    };
    std::process::exit(result);
}

#[cfg(target_os = "mochios")]
mod native {
    use mochi_user_platform as p;
    use mochios_test_support::{Case, TestResult, require};
    use std::{
        fs,
        io::{self, Read, Seek, SeekFrom, Write},
        process::Command,
        thread,
    };

    /// Flush one complete framed record in a single diagnostic write. Other
    /// process logs cannot split it between a JSON field and its newline.
    #[derive(Default)]
    pub struct ReportWriter(Vec<u8>);
    impl Write for ReportWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.0.len().saturating_add(bytes.len()) > 65536 {
                return Err(io::Error::other("test report exceeded its frame limit"));
            }
            self.0.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            if self.0.is_empty() {
                return Ok(());
            }
            let mut framed = b"\nMOCHIOS_TEST_JSON ".to_vec();
            framed.extend_from_slice(&self.0);
            p::io::stdout(&framed).map_err(|e| io::Error::other(format!("{e:?}")))?;
            self.0.clear();
            Ok(())
        }
    }
    pub fn finish_report(run_id: &str, status: i32) -> io::Result<()> {
        p::io::stdout(format!("\nMOCHIOS_TEST_FINISH {run_id} {status}\n").as_bytes())
            .map_err(|e| io::Error::other(format!("{e:?}")))
    }

    pub const CASES: &[Case] = &[
        Case {
            id: "native.identity",
            timeout_seconds: 30,
            run: identity,
        },
        Case {
            id: "native.handle-rights",
            timeout_seconds: 30,
            run: handle_rights,
        },
        Case {
            id: "native.ipc-transfer",
            timeout_seconds: 30,
            run: ipc_transfer,
        },
        Case {
            id: "posix.files",
            timeout_seconds: 30,
            run: files,
        },
        Case {
            id: "posix.fd-sharing",
            timeout_seconds: 30,
            run: fd_sharing,
        },
        Case {
            id: "posix.process",
            timeout_seconds: 60,
            run: process,
        },
        Case {
            id: "posix.threads",
            timeout_seconds: 30,
            run: threads,
        },
        Case {
            id: "security.launch-authorization",
            timeout_seconds: 30,
            run: launch_authorization,
        },
        Case {
            id: "security.signed-image",
            timeout_seconds: 30,
            run: signed_image,
        },
    ];
    fn error(e: impl std::fmt::Debug) -> String {
        format!("{e:?}")
    }
    struct Handle(u32);
    impl Drop for Handle {
        fn drop(&mut self) {
            let _ = p::handle::close(self.0);
        }
    }
    struct Scratch(std::path::PathBuf);
    impl Scratch {
        fn new() -> Result<Self, String> {
            let path = std::env::temp_dir().join(format!("mochios-test-{}", std::process::id()));
            fs::create_dir(&path).map_err(error)?;
            Ok(Self(path))
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn identity() -> TestResult {
        let image = p::process::image_info(None).map_err(error)?;
        let context = p::process::thread_security_context(0).map_err(error)?;
        require(
            image.process_id != 0 && image.process_id == context.process_id,
            "native image and security context disagree",
        )?;
        require(
            image.digest_kind == p::syscall::PROCESS_IMAGE_DIGEST_SHA256 && image.digest != [0; 32],
            "missing native image measurement",
        )
    }
    fn handle_rights() -> TestResult {
        let object = p::memory_object::MemoryObject::create_resizable(16).map_err(error)?;
        p::handle::write_at(object.handle(), b"test", 0).map_err(error)?;
        let read = Handle(
            p::handle::duplicate(
                object.handle(),
                p::handle::HANDLE_RIGHT_READ | p::handle::HANDLE_RIGHT_DUPLICATE,
            )
            .map_err(error)?,
        );
        let mut bytes = [0; 4];
        require(
            p::handle::read_at(read.0, &mut bytes, 0).map_err(error)? == 4 && bytes == *b"test",
            "restricted read failed",
        )?;
        require(
            matches!(p::handle::write_at(read.0,b"bad",0),Err(e) if e.raw()==p::syscall::NativeError::AccessDenied.into_raw() as i64),
            "read-only handle allowed write",
        )?;
        require(
            matches!(p::handle::duplicate(read.0,p::handle::HANDLE_RIGHT_WRITE),Err(e) if e.raw()==p::syscall::NativeError::AccessDenied.into_raw() as i64),
            "duplicate widened handle rights",
        )
    }
    fn ipc_transfer() -> TestResult {
        let (tx, rx) = std::sync::mpsc::channel();
        let worker = thread::spawn(move || -> TestResult {
            let endpoint = Handle(p::ipc::create_handle().map_err(error)?);
            tx.send(endpoint.0).map_err(error)?;
            let mut request = [0; 8];
            let mut handles = p::ipc::IpcObjectHandles::default();
            let message =
                p::ipc::wait_object_handles(u64::from(endpoint.0), &mut request, &mut handles)
                    .map_err(error)?;
            require(handles.count == 1, "IPC attachment missing")?;
            let received = Handle(handles.handles[0].handle);
            require(
                handles.handles[0].rights == p::handle::HANDLE_RIGHT_READ,
                "IPC broadened rights",
            )?;
            let mut bytes = [0; 4];
            require(
                p::handle::read_at(received.0, &mut bytes, 0).map_err(error)? == 4
                    && bytes == *b"test",
                "transferred object differs",
            )?;
            require(
                p::handle::write_at(received.0, b"bad", 0).is_err(),
                "transferred read-only object allowed write",
            )?;
            p::ipc::reply(message >> 32, b"ok").map_err(error)?;
            Ok(())
        });
        let endpoint = rx.recv().map_err(error)?;
        let object = p::memory_object::MemoryObject::create_resizable(4).map_err(error)?;
        p::handle::write_at(object.handle(), b"test", 0).map_err(error)?;
        let mut attached = p::ipc::IpcObjectHandles::default();
        attached.count = 1;
        attached.handles[0] = p::ipc::IpcObjectHandle {
            handle: object.handle(),
            reserved: 0,
            rights: p::handle::HANDLE_RIGHT_READ,
        };
        let mut reply = [0; 8];
        let result = p::ipc::call_object_handles(endpoint, b"read", &mut reply, &mut attached)
            .map_err(error)?;
        require(
            result as u32 == 2 && &reply[..2] == b"ok" && attached.count == 0,
            "bad IPC reply",
        )?;
        worker
            .join()
            .map_err(|_| "IPC worker panicked".to_string())?
    }
    fn files() -> TestResult {
        let dir = Scratch::new()?;
        let before = dir.0.join("before");
        let after = dir.0.join("after");
        fs::write(&before, b"contents").map_err(error)?;
        let mut open = fs::File::open(&before).map_err(error)?;
        fs::rename(&before, &after).map_err(error)?;
        fs::remove_file(&after).map_err(error)?;
        let mut bytes = Vec::new();
        open.read_to_end(&mut bytes).map_err(error)?;
        require(
            bytes == b"contents" && !after.exists(),
            "unlink invalidated an open file",
        )?;
        require(
            fs::write("/system/mochios-test-forbidden", b"forbidden").is_err(),
            "ordinary command could write System",
        )
    }
    fn fd_sharing() -> TestResult {
        let dir = Scratch::new()?;
        let path = dir.0.join("offset");
        fs::write(&path, b"abcdef").map_err(error)?;
        let mut first = fs::File::open(&path).map_err(error)?;
        let mut second = first.try_clone().map_err(error)?;
        let mut a = [0; 2];
        let mut b = [0; 2];
        first.read_exact(&mut a).map_err(error)?;
        second.read_exact(&mut b).map_err(error)?;
        require(
            a == *b"ab" && b == *b"cd",
            "duplicate file did not share offset",
        )?;
        second.seek(SeekFrom::Start(0)).map_err(error)?;
        first.read_exact(&mut a).map_err(error)?;
        require(
            a == *b"ab",
            "seek did not update the shared open-file description",
        )
    }
    fn process() -> TestResult {
        for (path, expected) in [("/bin/true", 0), ("/bin/false", 1)] {
            let status = Command::new(path).status().map_err(error)?;
            require(
                status.code() == Some(expected),
                &format!("wrong exit status from {path}: {status}"),
            )?;
        }
        Ok(())
    }
    fn threads() -> TestResult {
        let count = std::sync::Arc::new(std::sync::Mutex::new(0));
        let mut workers = Vec::new();
        for _ in 0..4 {
            let count = count.clone();
            workers.push(thread::spawn(move || {
                for _ in 0..100 {
                    *count.lock().unwrap() += 1;
                }
            }));
        }
        for worker in workers {
            worker.join().map_err(|_| "thread failed".to_string())?;
        }
        let value = *count.lock().map_err(error)?;
        require(value == 400, "lost synchronized updates")
    }
    fn broker() -> Result<u32, String> {
        u32::try_from(p::process::find_by_name("capability.service").map_err(error)?).map_err(error)
    }
    fn launch_authorization() -> TestResult {
        for name in ["process.spawn", "fs.read.all"] {
            require(
                p::capability::query(name.as_ptr() as u64, name.len() as u64).map_err(error)? == 1,
                "missing launch-test prerequisites",
            )?;
        }
        let name = "capabilities.manage";
        require(
            p::capability::query(name.as_ptr() as u64, name.len() as u64).map_err(error)? == 0,
            "launch test unexpectedly has policy-management authority",
        )?;
        for class in [2, 3] {
            let request =
                p::capability::encode_resolve_execution_security_request(class, "/bin/true")
                    .map_err(error)?;
            let mut reply = [0; 1024];
            let mut returned = p::ipc::IpcObjectHandles::default();
            let message =
                p::ipc::call_object_handles(broker()?, &request, &mut reply, &mut returned)
                    .map_err(error)?;
            let response = p::capability::decode_resolve_execution_security_reply(
                &reply[..message as u32 as usize],
            )
            .map_err(error)?;
            require(
                response.status == 13
                    && response.identity.is_empty()
                    && response.capabilities.is_empty()
                    && returned.count == 0,
                "unmeasured command obtained a system spawn permit",
            )?;
        }
        Ok(())
    }
    fn signature_fixture() -> Vec<u8> {
        let names = b"\0.shstrtab\0.text\0";
        let mut elf = vec![0; 0x100 + 3 * 64];
        elf[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        elf[16..18].copy_from_slice(&2u16.to_le_bytes());
        elf[18..20].copy_from_slice(&62u16.to_le_bytes());
        elf[20..24].copy_from_slice(&1u32.to_le_bytes());
        elf[24..32].copy_from_slice(&0x80u64.to_le_bytes());
        elf[40..48].copy_from_slice(&0x100u64.to_le_bytes());
        elf[52..54].copy_from_slice(&64u16.to_le_bytes());
        elf[58..60].copy_from_slice(&64u16.to_le_bytes());
        elf[60..62].copy_from_slice(&3u16.to_le_bytes());
        elf[62..64].copy_from_slice(&1u16.to_le_bytes());
        elf[0x80..0x84].copy_from_slice(&[0x90, 0x90, 0xc3, 0]);
        elf[0x90..0x90 + names.len()].copy_from_slice(names);
        for (index, name, kind, offset, size, align) in [
            (1, 1u32, 3u32, 0x90u64, names.len() as u64, 1u64),
            (2, 11, 1, 0x80, 4, 16),
        ] {
            let h = 0x100 + index * 64;
            elf[h..h + 4].copy_from_slice(&name.to_le_bytes());
            elf[h + 4..h + 8].copy_from_slice(&kind.to_le_bytes());
            elf[h + 24..h + 32].copy_from_slice(&offset.to_le_bytes());
            elf[h + 32..h + 40].copy_from_slice(&size.to_le_bytes());
            elf[h + 48..h + 56].copy_from_slice(&align.to_le_bytes());
        }
        elf
    }
    fn authorize(bytes: &[u8]) -> Result<u64, String> {
        let image =
            p::memory_object::MemoryObject::create_resizable(bytes.len() as u64).map_err(error)?;
        require(
            p::handle::write_at(image.handle(), bytes, 0).map_err(error)? == bytes.len(),
            "short image write",
        )?;
        let mut request = [0; 256];
        let length = p::capability::signed_image::encode(
            &p::capability::signed_image::Request {
                source_length: bytes.len() as u64,
                public_key: None,
                identity: "os-test:signed",
            },
            &mut request,
        )
        .map_err(error)?;
        let mut attached = p::ipc::IpcObjectHandles::default();
        attached.count = 1;
        attached.handles[0] = p::ipc::IpcObjectHandle {
            handle: image.handle(),
            reserved: 0,
            rights: p::memory_object::READONLY_BUFFER_RIGHTS,
        };
        let mut reply = [0; 8];
        let message =
            p::ipc::call_object_handles(broker()?, &request[..length], &mut reply, &mut attached)
                .map_err(error)?;
        require(
            message as u32 == 8 && attached.count == 0,
            "malformed image authorization response",
        )?;
        Ok(u64::from_le_bytes(reply))
    }
    fn signed_image() -> TestResult {
        let unsigned = signature_fixture();
        let signed = mochios_elf_signature::sign_adhoc(&unsigned).map_err(error)?;
        require(
            authorize(&signed)? == 0,
            "valid ad-hoc control image was rejected",
        )?;
        let mut changed = signed;
        changed[0x80] ^= 1;
        require(
            authorize(&changed)? == 13,
            "changed signed image was authorized",
        )?;
        require(authorize(&unsigned)? == 13, "unsigned image was authorized")
    }
}
