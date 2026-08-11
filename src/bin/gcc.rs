use std::env;
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicU64, Ordering};

use mboot_protocol::{
    Argument, Body, Destination, ErrorCode, KnownCommand, Message, MessageType, decode_line,
    encode_to_string,
};
use mochi_user_platform as platform;

const AGENT_NAME: &str = "mboot-agent.service";
const MAX_SOURCE_SIZE: usize = 1024 * 1024;
const TRANSFER_CHUNK_SIZE: usize = 1024;
static NEXT_REQUEST_ID: AtomicU64 = AtomicU64::new(1);

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("gcc: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> io::Result<()> {
    let arguments: Vec<String> = env::args().skip(1).collect();
    if arguments == ["--version"] {
        println!("gcc (mochiOS mBoot broker) 1.0");
        return Ok(());
    }
    let invocation = Invocation::parse(&arguments)?;
    let source = fs::read(&invocation.source)?;
    if source.is_empty() || source.len() > MAX_SOURCE_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "source must contain between 1 byte and 1 MiB",
        ));
    }
    let agent = find_agent()?;
    let transaction = allocate_request_id();
    request_ok(
        agent,
        KnownCommand::DeveloperBegin,
        vec![
            Argument::new("transaction", transaction.to_string()),
            Argument::new("size", source.len().to_string()),
        ],
    )?;
    let result = compile_transaction(agent, transaction, &source, &invocation.output);
    let _ = request_ok(
        agent,
        KnownCommand::DeveloperCancel,
        vec![Argument::new("transaction", transaction.to_string())],
    );
    result
}

fn compile_transaction(
    agent: u64,
    transaction: u64,
    source: &[u8],
    output_path: &PathBuf,
) -> io::Result<()> {
    for (index, chunk) in source.chunks(TRANSFER_CHUNK_SIZE).enumerate() {
        request_ok(
            agent,
            KnownCommand::DeveloperChunk,
            vec![
                Argument::new("transaction", transaction.to_string()),
                Argument::new("offset", (index * TRANSFER_CHUNK_SIZE).to_string()),
                Argument::new("data", encode_hex(chunk)),
            ],
        )?;
    }
    let response = request_ok(
        agent,
        KnownCommand::DeveloperCompile,
        vec![Argument::new("transaction", transaction.to_string())],
    )?;
    let status = response_i32(&response, "status")?;
    let output_size = response_usize(&response, "output_size")?;
    let diagnostics_size = response_usize(&response, "diagnostics_size")?;
    if diagnostics_size != 0 {
        let diagnostics = download(agent, transaction, "diagnostics", diagnostics_size)?;
        io::stderr().write_all(&diagnostics)?;
    }
    if status != 0 {
        return Err(io::Error::other(format!(
            "mBoot GCC exited with status {status}"
        )));
    }
    if output_size == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "mBoot GCC returned an empty executable",
        ));
    }
    let executable = download(agent, transaction, "output", output_size)?;
    fs::write(output_path, executable)?;
    fs::set_permissions(output_path, fs::Permissions::from_mode(0o755))
}

fn download(agent: u64, transaction: u64, stream: &str, size: usize) -> io::Result<Vec<u8>> {
    let mut output = Vec::with_capacity(size);
    while output.len() < size {
        let response = request_ok(
            agent,
            KnownCommand::DeveloperRead,
            vec![
                Argument::new("transaction", transaction.to_string()),
                Argument::new("stream", stream),
                Argument::new("offset", output.len().to_string()),
                Argument::new("maximum", TRANSFER_CHUNK_SIZE.to_string()),
            ],
        )?;
        let total = response_usize(&response, "total_size")?;
        if total != size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "mBoot stream size changed during transfer",
            ));
        }
        let data = response
            .argument("data")
            .ok_or_else(invalid_response)
            .and_then(decode_hex)?;
        if data.is_empty() || output.len().saturating_add(data.len()) > size {
            return Err(invalid_response());
        }
        output.extend_from_slice(&data);
    }
    Ok(output)
}

fn request_ok(agent: u64, command: KnownCommand, arguments: Vec<Argument>) -> io::Result<Message> {
    let request_id = allocate_request_id();
    let request = Message::command(
        Destination::Mboot,
        MessageType::Request,
        request_id,
        command,
        arguments,
    );
    let encoded = encode_to_string(&request).map_err(|_| invalid_response())?;
    let mut reply = [0u8; mboot_protocol::MAX_MESSAGE_LEN];
    let received = call_with_wait(agent, encoded.as_bytes(), &mut reply)?;
    let length = (received & 0xffff_ffff) as usize;
    let response = reply
        .get(..length)
        .ok_or_else(invalid_response)
        .and_then(|bytes| decode_line(bytes).map_err(|_| invalid_response()))?;
    if response.destination != Destination::Mochios
        || response.message_type != MessageType::Response
        || response.request_id != request_id
    {
        return Err(invalid_response());
    }
    match &response.body {
        Body::Ok => Ok(response),
        Body::Error(error) => Err(protocol_error(*error)),
        Body::Command(_) => Err(invalid_response()),
    }
}

fn call_with_wait(destination: u64, request: &[u8], reply: &mut [u8]) -> io::Result<u64> {
    match platform::ipc::call(destination, request, reply) {
        Ok(message) => Ok(message),
        Err(error) if error.raw() == mochi_user_syscall::EAGAIN as i64 => loop {
            match platform::ipc::try_wait(reply) {
                Ok(message) => break Ok(message),
                Err(error) if error.raw() == mochi_user_syscall::EAGAIN as i64 => {
                    platform::thread::yield_now();
                }
                Err(error) => break Err(syscall_error(error)),
            }
        },
        Err(error) => Err(syscall_error(error)),
    }
}

fn find_agent() -> io::Result<u64> {
    for _ in 0..64 {
        if let Ok(endpoint) = platform::process::find_by_name(AGENT_NAME)
            && endpoint != 0
        {
            return Ok(endpoint);
        }
        platform::thread::yield_now();
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "mboot-agent.service is unavailable",
    ))
}

fn response_usize(response: &Message, key: &str) -> io::Result<usize> {
    response
        .argument(key)
        .and_then(|value| value.parse().ok())
        .ok_or_else(invalid_response)
}

fn response_i32(response: &Message, key: &str) -> io::Result<i32> {
    response
        .argument(key)
        .and_then(|value| value.parse().ok())
        .ok_or_else(invalid_response)
}

fn allocate_request_id() -> u64 {
    loop {
        let id = NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed);
        if id != 0 {
            return id;
        }
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}

fn decode_hex(value: &str) -> io::Result<Vec<u8>> {
    if value.len() % 2 != 0 {
        return Err(invalid_response());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_digit(pair[0]).ok_or_else(invalid_response)?;
            let low = hex_digit(pair[1]).ok_or_else(invalid_response)?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn hex_digit(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn protocol_error(error: ErrorCode) -> io::Error {
    let kind = match error {
        ErrorCode::PermissionDenied => io::ErrorKind::PermissionDenied,
        ErrorCode::Busy => io::ErrorKind::WouldBlock,
        ErrorCode::InvalidArgument => io::ErrorKind::InvalidInput,
        ErrorCode::InvalidState => io::ErrorKind::NotConnected,
        _ => io::ErrorKind::Other,
    };
    io::Error::new(kind, format!("mBoot developer service returned {error:?}"))
}

fn syscall_error(error: mochi_user_syscall::SysError) -> io::Error {
    io::Error::from_raw_os_error(error.errno().unwrap_or(mochi_user_syscall::EIO) as i32)
}

fn invalid_response() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid mBoot developer response",
    )
}

struct Invocation {
    source: PathBuf,
    output: PathBuf,
}

impl Invocation {
    fn parse(arguments: &[String]) -> io::Result<Self> {
        let mut source = None;
        let mut output = PathBuf::from("a.out");
        let mut index = 0;
        while index < arguments.len() {
            if arguments[index] == "-o" {
                index += 1;
                let value = arguments.get(index).ok_or_else(usage_error)?;
                output = PathBuf::from(value);
            } else if arguments[index].starts_with('-') || source.is_some() {
                return Err(usage_error());
            } else {
                source = Some(PathBuf::from(&arguments[index]));
            }
            index += 1;
        }
        Ok(Self {
            source: source.ok_or_else(usage_error)?,
            output,
        })
    }
}

fn usage_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "usage: gcc INPUT.c [-o OUTPUT]",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_gcc_invocation() {
        let invocation =
            Invocation::parse(&["hello.c".into(), "-o".into(), "hello".into()]).unwrap();
        assert_eq!(invocation.source, PathBuf::from("hello.c"));
        assert_eq!(invocation.output, PathBuf::from("hello"));
    }

    #[test]
    fn hex_round_trip() {
        let input = [0, 1, 0x7f, 0x80, 0xff];
        assert_eq!(decode_hex(&encode_hex(&input)).unwrap(), input);
    }
}
