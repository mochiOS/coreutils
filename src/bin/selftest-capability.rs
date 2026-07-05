#[repr(u32)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum CapabilityClass {
    #[default]
    UserGrantable = 1,
    Privileged = 2,
    SystemOnly = 3,
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum CapabilityDecision {
    AllowOnce = 1,
    AllowForProcess = 2,
    AllowPersistently = 3,
    AllowAllUserGrantable = 4,
    #[default]
    Deny = 5,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ExecutableIdentity {
    path_len: u16,
    reserved: u16,
    digest: [u8; 32],
    path: [u8; 256],
}

impl Default for ExecutableIdentity {
    fn default() -> Self {
        Self {
            path_len: 0,
            reserved: 0,
            digest: [0; 32],
            path: [0; 256],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ResourceDescriptor {
    kind: u32,
    path_len: u16,
    reserved: u16,
    path: [u8; 256],
}

impl Default for ResourceDescriptor {
    fn default() -> Self {
        Self {
            kind: 0,
            path_len: 0,
            reserved: 0,
            path: [0; 256],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CapabilityRequest {
    opcode: u32,
    process_id: u64,
    executable: ExecutableIdentity,
    capability_class: CapabilityClass,
    capability_len: u16,
    resource: ResourceDescriptor,
    reason_len: u16,
    interactive: u8,
    decision_scope: u8,
    reserved0: u16,
    capability: [u8; 64],
    reason: [u8; 128],
}

impl Default for CapabilityRequest {
    fn default() -> Self {
        Self {
            opcode: 0,
            process_id: 0,
            executable: ExecutableIdentity::default(),
            capability_class: CapabilityClass::UserGrantable,
            capability_len: 0,
            resource: ResourceDescriptor::default(),
            reason_len: 0,
            interactive: 0,
            decision_scope: 0,
            reserved0: 0,
            capability: [0; 64],
            reason: [0; 128],
        }
    }
}

const CAPABILITY_PROMPT_OPCODE: u32 = 0x4350_5251;
const CAPABILITY_PERSISTENT_QUERY_OPCODE: u32 = 0x4350_5150;

fn request_new(
    process_id: u64,
    executable_path: &str,
    digest: [u8; 32],
    capability: &str,
    resource_path: Option<&str>,
    reason: Option<&str>,
    interactive: bool,
    capability_class: CapabilityClass,
) -> Option<CapabilityRequest> {
    let mut request = CapabilityRequest {
        opcode: CAPABILITY_PROMPT_OPCODE,
        process_id,
        executable: ExecutableIdentity::default(),
        capability_class,
        capability_len: 0,
        resource: ResourceDescriptor::default(),
        reason_len: 0,
        interactive: interactive as u8,
        decision_scope: 0,
        reserved0: 0,
        capability: [0; 64],
        reason: [0; 128],
    };

    let exec_bytes = executable_path.as_bytes();
    if exec_bytes.len() > request.executable.path.len() || exec_bytes.len() > u16::MAX as usize {
        return None;
    }
    request.executable.path_len = exec_bytes.len() as u16;
    request.executable.path[..exec_bytes.len()].copy_from_slice(exec_bytes);
    request.executable.digest = digest;

    let cap_bytes = capability.as_bytes();
    if cap_bytes.len() > request.capability.len() || cap_bytes.len() > u16::MAX as usize {
        return None;
    }
    request.capability_len = cap_bytes.len() as u16;
    request.capability[..cap_bytes.len()].copy_from_slice(cap_bytes);

    if let Some(resource_path) = resource_path {
        let res_bytes = resource_path.as_bytes();
        if res_bytes.len() > request.resource.path.len() || res_bytes.len() > u16::MAX as usize {
            return None;
        }
        request.resource.kind = 1;
        request.resource.path_len = res_bytes.len() as u16;
        request.resource.path[..res_bytes.len()].copy_from_slice(res_bytes);
    }

    if let Some(reason) = reason {
        let reason_bytes = reason.as_bytes();
        if reason_bytes.len() > request.reason.len() || reason_bytes.len() > u16::MAX as usize {
            return None;
        }
        request.reason_len = reason_bytes.len() as u16;
        request.reason[..reason_bytes.len()].copy_from_slice(reason_bytes);
    }

    Some(request)
}

fn capability_from_string(name: &str) -> CapabilityClass {
    match name {
        "fs.read.user" | "fs.write.user" | "net.connect" | "settings.read" => {
            CapabilityClass::UserGrantable
        }
        "package.install" | "service.control" | "fs.write.all" => CapabilityClass::Privileged,
        _ => CapabilityClass::SystemOnly,
    }
}

fn is_manifestless_dynamic_candidate(executable_path: &str, package_binaries: &[&str]) -> bool {
    !package_binaries.iter().any(|path| *path == executable_path)
}

fn dynamic_decision_allowed(
    request: &CapabilityRequest,
    decision: CapabilityDecision,
    package_binaries: &[&str],
) -> bool {
    if request.opcode != CAPABILITY_PROMPT_OPCODE
        || request.process_id == 0
        || request.interactive == 0
        || decision == CapabilityDecision::Deny
        || request.capability_class != CapabilityClass::UserGrantable
    {
        return false;
    }
    let Some(executable) = field_str(&request.executable.path, request.executable.path_len) else {
        return false;
    };
    is_manifestless_dynamic_candidate(executable, package_binaries)
}

fn persistent_key(
    executable_path: &str,
    digest: &[u8; 32],
    capability: &str,
    resource: Option<&str>,
) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::new();
    out.push_str(executable_path);
    out.push('\t');
    for byte in digest {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out.push('\t');
    out.push_str(capability);
    out.push('\t');
    out.push_str(resource.unwrap_or(""));
    out
}

fn field_str(buf: &[u8], len: u16) -> Option<&str> {
    core::str::from_utf8(&buf[..len as usize]).ok()
}

fn check(name: &str, condition: bool, failures: &mut usize) {
    if condition {
        println!("ok selftest-capability::{name}");
    } else {
        println!("not ok selftest-capability::{name}");
        *failures += 1;
    }
}

fn check_request(
    name: &str,
    request: Option<CapabilityRequest>,
    predicate: impl FnOnce(&CapabilityRequest) -> bool,
    failures: &mut usize,
) {
    match request {
        Some(request) => check(name, predicate(&request), failures),
        None => check(name, false, failures),
    }
}

fn main() {
    let mut failures = 0usize;
    let request = request_new(
        42,
        "/bin/tool",
        [7; 32],
        "fs.read.user",
        Some("/home/user/file.txt"),
        Some("file access"),
        true,
        CapabilityClass::UserGrantable,
    );
    check("build_request", request.is_some(), &mut failures);

    if let Some(request) = request {
        check(
            "opcode",
            request.opcode == CAPABILITY_PROMPT_OPCODE,
            &mut failures,
        );
        check("pid", request.process_id == 42, &mut failures);
        check(
            "digest",
            request.executable.digest == [7; 32],
            &mut failures,
        );
        check(
            "executable_path",
            field_str(&request.executable.path, request.executable.path_len) == Some("/bin/tool"),
            &mut failures,
        );
        check(
            "capability",
            field_str(&request.capability, request.capability_len) == Some("fs.read.user"),
            &mut failures,
        );
        check(
            "resource_path",
            field_str(&request.resource.path, request.resource.path_len)
                == Some("/home/user/file.txt"),
            &mut failures,
        );
        check(
            "reason",
            field_str(&request.reason, request.reason_len) == Some("file access"),
            &mut failures,
        );
        check("interactive", request.interactive == 1, &mut failures);
    }

    let long_path = "x".repeat(257);
    check(
        "reject_long_path",
        request_new(
            1,
            &long_path,
            [0; 32],
            "fs.read.user",
            None,
            None,
            false,
            CapabilityClass::UserGrantable,
        )
        .is_none(),
        &mut failures,
    );

    let long_capability = "x".repeat(65);
    check(
        "reject_long_capability",
        request_new(
            1,
            "/bin/tool",
            [0; 32],
            &long_capability,
            None,
            None,
            false,
            CapabilityClass::UserGrantable,
        )
        .is_none(),
        &mut failures,
    );

    check(
        "class_user_grantable",
        capability_from_string("fs.read.user") == CapabilityClass::UserGrantable,
        &mut failures,
    );
    check(
        "class_privileged",
        capability_from_string("package.install") == CapabilityClass::Privileged,
        &mut failures,
    );
    check(
        "class_system_only",
        capability_from_string("capabilities.manage") == CapabilityClass::SystemOnly,
        &mut failures,
    );

    let package_binaries = ["/bin/ls", "/bin/msh"];
    check(
        "manifestless_candidate",
        is_manifestless_dynamic_candidate("/bin/selftest-capability", &package_binaries),
        &mut failures,
    );
    check(
        "manifest_registered_not_dynamic",
        !is_manifestless_dynamic_candidate("/bin/ls", &package_binaries),
        &mut failures,
    );

    let dynamic_request = request_new(
        7,
        "/bin/selftest-capability",
        [9; 32],
        "fs.read.user",
        Some("/home/user/example.txt"),
        Some("file access"),
        true,
        CapabilityClass::UserGrantable,
    );
    check_request(
        "allow_once_manifestless",
        dynamic_request,
        |request| {
            dynamic_decision_allowed(request, CapabilityDecision::AllowOnce, &package_binaries)
        },
        &mut failures,
    );
    check_request(
        "allow_session_manifestless",
        dynamic_request,
        |request| {
            dynamic_decision_allowed(
                request,
                CapabilityDecision::AllowForProcess,
                &package_binaries,
            )
        },
        &mut failures,
    );
    check_request(
        "deny_manifest_binary",
        request_new(
            7,
            "/bin/ls",
            [9; 32],
            "fs.read.user",
            None,
            None,
            true,
            CapabilityClass::UserGrantable,
        ),
        |request| {
            !dynamic_decision_allowed(request, CapabilityDecision::AllowOnce, &package_binaries)
        },
        &mut failures,
    );
    check_request(
        "deny_noninteractive",
        request_new(
            7,
            "/bin/selftest-capability",
            [9; 32],
            "fs.read.user",
            None,
            None,
            false,
            CapabilityClass::UserGrantable,
        ),
        |request| {
            !dynamic_decision_allowed(request, CapabilityDecision::AllowOnce, &package_binaries)
        },
        &mut failures,
    );
    check_request(
        "deny_privileged_dynamic",
        request_new(
            7,
            "/bin/selftest-capability",
            [9; 32],
            "package.install",
            None,
            None,
            true,
            CapabilityClass::Privileged,
        ),
        |request| {
            !dynamic_decision_allowed(
                request,
                CapabilityDecision::AllowPersistently,
                &package_binaries,
            )
        },
        &mut failures,
    );
    check_request(
        "deny_forged_zero_pid",
        request_new(
            0,
            "/bin/selftest-capability",
            [9; 32],
            "fs.read.user",
            None,
            None,
            true,
            CapabilityClass::UserGrantable,
        ),
        |request| {
            !dynamic_decision_allowed(request, CapabilityDecision::AllowOnce, &package_binaries)
        },
        &mut failures,
    );
    check(
        "persistent_query_opcode_distinct",
        CAPABILITY_PERSISTENT_QUERY_OPCODE != CAPABILITY_PROMPT_OPCODE,
        &mut failures,
    );
    check(
        "persistent_key_includes_digest",
        persistent_key(
            "/bin/selftest-capability",
            &[1; 32],
            "fs.read.user",
            Some("/home/user/example.txt"),
        ) != persistent_key(
            "/bin/selftest-capability",
            &[2; 32],
            "fs.read.user",
            Some("/home/user/example.txt"),
        ),
        &mut failures,
    );

    if failures == 0 {
        println!("selftest-capability: pass");
    } else {
        eprintln!("selftest-capability: {failures} failure(s)");
        std::process::exit(1);
    }
}
