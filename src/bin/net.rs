use std::io;
use std::net::Ipv4Addr;

use mochi_user_syscall as syscall;
use mochios_net_device_protocol::{
    HEADER_LEN, HTTP_CLOSE_REQUEST_LEN, HTTP_READ_REQUEST_LEN, HttpFailure, HttpMethod, HttpStream,
    MAX_HOSTNAME_LEN, MAX_HTTP_IPC_DATA_LEN, MAX_HTTP_URL_LEN, MAX_TCP_IO_LEN, Opcode,
    PING_REQUEST_LEN, PING_RESULT_LEN, RESOLVE_RESULT_LEN, SECURITY_STATISTICS_LEN,
    STACK_STATISTICS_LEN, TCP_CLOSE_REQUEST_LEN, TCP_CONNECT_RESULT_LEN, TCP_IO_RESULT_LEN,
    TCP_RECEIVE_REQUEST_LEN, TLS_IO_RESULT_LEN, decode_http_read_result,
    decode_http_request_result, decode_ping_result, decode_resolve_ipv4_result,
    decode_security_statistics, decode_stack_statistics, decode_tcp_connect_result,
    decode_tcp_io_result, decode_tcp_receive_result, decode_tls_connect_result,
    decode_tls_io_result, encode_empty, encode_http_close, encode_http_read, encode_http_request,
    encode_ping, encode_resolve_ipv4, encode_tcp_close, encode_tcp_connect, encode_tcp_receive,
    encode_tcp_send, encode_tls_close, encode_tls_connect,
};

const DEFAULT_TIMEOUT_MS: u32 = 5_000;
const TCP_EXCHANGE_TIMEOUT_MS: u32 = 10_000;
const MAX_BODY_DISPLAY: usize = 64 * 1024;

fn io_errno(errno: u64) -> io::Error {
    io::Error::from_raw_os_error(errno as i32)
}

fn network_service() -> io::Result<u64> {
    let name = b"network.service";
    let thread = syscall::call2(
        syscall::SyscallNumber::FindProcessByName,
        name.as_ptr() as u64,
        name.len() as u64,
    )
    .map_err(|error| io_errno(error.errno().unwrap_or(syscall::EIO)))?;
    if thread == 0 {
        Err(io_errno(syscall::ENOENT))
    } else {
        Ok(thread)
    }
}

fn call(request: &[u8], reply: &mut [u8]) -> io::Result<usize> {
    let result = syscall::call5(
        syscall::SyscallNumber::IpcCall,
        network_service()?,
        request.as_ptr() as u64,
        request.len() as u64,
        reply.as_mut_ptr() as u64,
        reply.len() as u64,
    )
    .map_err(|error| io_errno(error.errno().unwrap_or(syscall::EIO)))?;
    let length = (result & 0xffff_ffff) as usize;
    if length > reply.len() {
        Err(io_errno(syscall::EIO))
    } else {
        Ok(length)
    }
}

fn ping(address: Ipv4Addr) -> io::Result<()> {
    let request_id = 1;
    let mut request = [0u8; PING_REQUEST_LEN];
    encode_ping(request_id, address.octets(), &mut request)
        .map_err(|_| io_errno(syscall::EINVAL))?;
    let mut reply = [0u8; PING_RESULT_LEN];
    let length = call(&request, &mut reply)?;
    let (reply_id, status, rtt) =
        decode_ping_result(&reply[..length]).map_err(|_| io_errno(syscall::EIO))?;
    if reply_id != request_id || status != 0 {
        return Err(io_errno(status.unsigned_abs() as u64));
    }
    println!("reply from {address}: time={rtt}ms");
    Ok(())
}

fn statistics() -> io::Result<()> {
    let mut request = [0u8; HEADER_LEN];
    encode_empty(Opcode::GetStackStatistics, 1, &mut request)
        .map_err(|_| io_errno(syscall::EINVAL))?;
    let mut reply = [0u8; STACK_STATISTICS_LEN];
    let length = call(&request, &mut reply)?;
    let (_, stats) =
        decode_stack_statistics(&reply[..length]).map_err(|_| io_errno(syscall::EIO))?;
    println!(
        "rx_packets={} rx_bytes={} rx_dropped={} rx_errors={}",
        stats.rx_packets, stats.rx_bytes, stats.rx_dropped, stats.rx_errors
    );
    println!(
        "tx_packets={} tx_bytes={} tx_dropped={} tx_errors={}",
        stats.tx_packets, stats.tx_bytes, stats.tx_dropped, stats.tx_errors
    );
    println!(
        "arp_requests={} arp_cache_hits={} arp_cache_misses={}",
        stats.arp_requests, stats.arp_cache_hits, stats.arp_cache_misses
    );
    println!(
        "ipv4_checksum_errors={} icmp_echo_requests={} icmp_echo_replies={}",
        stats.ipv4_checksum_errors, stats.icmp_echo_requests, stats.icmp_echo_replies
    );
    println!(
        "dhcp_attempts={} dhcp_successes={} dhcp_failures={}",
        stats.dhcp_attempts, stats.dhcp_successes, stats.dhcp_failures
    );
    println!(
        "dns_queries={} dns_cache_hits={} dns_cache_misses={} dns_timeouts={} dns_failures={}",
        stats.dns_queries,
        stats.dns_cache_hits,
        stats.dns_cache_misses,
        stats.dns_timeouts,
        stats.dns_failures
    );
    println!(
        "tcp_connections_attempted={} tcp_connections_established={} tcp_connections_failed={}",
        stats.tcp_connections_attempted,
        stats.tcp_connections_established,
        stats.tcp_connections_failed
    );
    println!(
        "tcp_segments_sent={} tcp_segments_received={} tcp_retransmissions={} tcp_checksum_errors={}",
        stats.tcp_segments_sent,
        stats.tcp_segments_received,
        stats.tcp_retransmissions,
        stats.tcp_checksum_errors
    );
    println!(
        "tcp_resets={} tcp_timeouts={} tcp_receive_drops={} tcp_send_drops={}",
        stats.tcp_resets, stats.tcp_timeouts, stats.tcp_receive_drops, stats.tcp_send_drops
    );
    encode_empty(Opcode::GetSecurityStatistics, 2, &mut request)
        .map_err(|_| io_errno(syscall::EINVAL))?;
    let mut security_reply = [0u8; SECURITY_STATISTICS_LEN];
    let length = call(&request, &mut security_reply)?;
    let (request_id, security) = decode_security_statistics(&security_reply[..length])
        .map_err(|_| io_errno(syscall::EIO))?;
    if request_id != 2 {
        return Err(io_errno(syscall::EIO));
    }
    println!(
        "tls_connections_attempted={} tls_connections_established={} tls_connections_failed={}",
        security.tls_connections_attempted,
        security.tls_connections_established,
        security.tls_connections_failed
    );
    println!(
        "tls_handshake_failures={} tls_certificate_failures={} tls_hostname_failures={}",
        security.tls_handshake_failures,
        security.tls_certificate_failures,
        security.tls_hostname_failures
    );
    println!(
        "tls_records_sent={} tls_records_received={} tls_decrypt_failures={}",
        security.tls_records_sent, security.tls_records_received, security.tls_decrypt_failures
    );
    println!(
        "http_requests={} http_responses={} http_failures={} http_redirects={}",
        security.http_requests,
        security.http_responses,
        security.http_failures,
        security.http_redirects
    );
    println!(
        "http_header_errors={} http_body_limit_errors={} http_chunk_errors={}",
        security.http_header_errors, security.http_body_limit_errors, security.http_chunk_errors
    );
    Ok(())
}

fn resolve(hostname: &str) -> io::Result<Ipv4Addr> {
    let mut request = [0u8; 32 + MAX_HOSTNAME_LEN];
    let request_length = encode_resolve_ipv4(1, hostname, DEFAULT_TIMEOUT_MS, &mut request)
        .map_err(|_| io_errno(syscall::EINVAL))?;
    let mut reply = [0u8; RESOLVE_RESULT_LEN];
    let reply_length = call(&request[..request_length], &mut reply)?;
    let (request_id, status, address, _) =
        decode_resolve_ipv4_result(&reply[..reply_length]).map_err(|_| io_errno(syscall::EIO))?;
    if request_id != 1 {
        return Err(io_errno(syscall::EIO));
    }
    if status != 0 {
        return Err(io_errno(status.unsigned_abs() as u64));
    }
    let address = Ipv4Addr::from(address);
    println!("{hostname} -> {address}");
    Ok(address)
}

fn tcp_connect(host: &str, port: u16) -> io::Result<(u64, Ipv4Addr)> {
    let mut request = [0u8; 32 + MAX_HOSTNAME_LEN];
    let request_length = encode_tcp_connect(1, host, port, DEFAULT_TIMEOUT_MS, &mut request)
        .map_err(|_| io_errno(syscall::EINVAL))?;
    let mut reply = [0u8; TCP_CONNECT_RESULT_LEN];
    let reply_length = call(&request[..request_length], &mut reply)?;
    let (request_id, status, handle, address, reply_port) =
        decode_tcp_connect_result(&reply[..reply_length]).map_err(|_| io_errno(syscall::EIO))?;
    if request_id != 1 || reply_port != port {
        return Err(io_errno(syscall::EIO));
    }
    if status != 0 {
        return Err(io_errno(status.unsigned_abs() as u64));
    }
    let address = Ipv4Addr::from(address);
    println!("Connected to {host}:{port} ({address})");
    Ok((handle, address))
}

fn tcp_send(handle: u64, data: &[u8]) -> io::Result<usize> {
    let mut request = vec![0u8; 40 + data.len()];
    let request_length = encode_tcp_send(2, handle, TCP_EXCHANGE_TIMEOUT_MS, data, &mut request)
        .map_err(|_| io_errno(syscall::EINVAL))?;
    let mut reply = [0u8; TCP_IO_RESULT_LEN];
    let reply_length = call(&request[..request_length], &mut reply)?;
    let (request_id, status, transferred) =
        decode_tcp_io_result(Opcode::TcpSendResult, &reply[..reply_length])
            .map_err(|_| io_errno(syscall::EIO))?;
    if request_id != 2 {
        return Err(io_errno(syscall::EIO));
    }
    if status != 0 {
        return Err(io_errno(status.unsigned_abs() as u64));
    }
    Ok(transferred as usize)
}

fn tcp_receive(handle: u64, out: &mut [u8]) -> io::Result<(usize, bool)> {
    let maximum = out.len().min(MAX_TCP_IO_LEN);
    let mut request = [0u8; TCP_RECEIVE_REQUEST_LEN];
    encode_tcp_receive(
        3,
        handle,
        TCP_EXCHANGE_TIMEOUT_MS,
        maximum as u32,
        &mut request,
    )
    .map_err(|_| io_errno(syscall::EINVAL))?;
    let mut reply = vec![0u8; 40 + maximum];
    let reply_length = call(&request, &mut reply)?;
    let (request_id, status, closed, data) =
        decode_tcp_receive_result(&reply[..reply_length]).map_err(|_| io_errno(syscall::EIO))?;
    if request_id != 3 || data.len() > out.len() {
        return Err(io_errno(syscall::EIO));
    }
    if status != 0 {
        return Err(io_errno(status.unsigned_abs() as u64));
    }
    out[..data.len()].copy_from_slice(data);
    Ok((data.len(), closed))
}

fn tcp_close(handle: u64) -> io::Result<()> {
    let mut request = [0u8; TCP_CLOSE_REQUEST_LEN];
    encode_tcp_close(4, handle, TCP_EXCHANGE_TIMEOUT_MS, &mut request)
        .map_err(|_| io_errno(syscall::EINVAL))?;
    let mut reply = [0u8; TCP_IO_RESULT_LEN];
    let reply_length = call(&request, &mut reply)?;
    let (request_id, status, _) =
        decode_tcp_io_result(Opcode::TcpCloseResult, &reply[..reply_length])
            .map_err(|_| io_errno(syscall::EIO))?;
    if request_id != 4 {
        return Err(io_errno(syscall::EIO));
    }
    if status != 0 {
        return Err(io_errno(status.unsigned_abs() as u64));
    }
    Ok(())
}

fn tcp_connect_command(host: &str, port: u16) -> io::Result<()> {
    let (handle, _) = tcp_connect(host, port)?;
    tcp_close(handle)
}

fn tcp_send_command(host: &str, port: u16, data: &[u8]) -> io::Result<()> {
    let (handle, _) = tcp_connect(host, port)?;
    let sent = tcp_send(handle, data)?;
    let mut received = [0u8; MAX_TCP_IO_LEN];
    let mut length = 0usize;
    while length < data.len() {
        let (chunk, closed) = tcp_receive(handle, &mut received[length..data.len()])?;
        length += chunk;
        if closed || chunk == 0 {
            break;
        }
    }
    println!(
        "sent={} received={} data={}",
        sent,
        length,
        String::from_utf8_lossy(&received[..length])
    );
    let matches = &received[..length] == data;
    let close_result = tcp_close(handle);
    if !matches {
        return Err(io_errno(syscall::EIO));
    }
    close_result
}

struct TlsConnectionInfo {
    handle: u64,
    address: [u8; 4],
    port: u16,
    protocol_version: u16,
    cipher_suite: u16,
    hostname: String,
    certificate_subject: String,
    certificate_issuer: String,
    certificate_not_before: u64,
    certificate_not_after: u64,
}

fn tls_connect(host: &str, port: u16) -> io::Result<TlsConnectionInfo> {
    let mut request = [0u8; 40 + MAX_HOSTNAME_LEN];
    let request_length = encode_tls_connect(1, host, port, TCP_EXCHANGE_TIMEOUT_MS, &mut request)
        .map_err(|error| {
        eprintln!("TLS IPC request encode failed: {error:?}");
        io_errno(syscall::EINVAL)
    })?;
    let mut reply = vec![0u8; 80 + MAX_HOSTNAME_LEN + 1024];
    let reply_length = call(&request[..request_length], &mut reply).map_err(|error| {
        eprintln!("TLS IPC call failed: {error}");
        error
    })?;
    let result = decode_tls_connect_result(&reply[..reply_length]).map_err(|error| {
        eprintln!("TLS IPC reply decode failed: {error:?} length={reply_length}");
        io_errno(syscall::EIO)
    })?;
    if result.request_id != 1 || result.port != port {
        return Err(io_errno(syscall::EIO));
    }
    if result.status != 0 {
        eprintln!("TLS failure: {:?}", result.failure);
        return Err(io_errno(result.status.unsigned_abs() as u64));
    }
    Ok(TlsConnectionInfo {
        handle: result.handle,
        address: result.address,
        port: result.port,
        protocol_version: result.protocol_version,
        cipher_suite: result.cipher_suite,
        hostname: result.hostname.to_owned(),
        certificate_subject: result.certificate_subject.to_owned(),
        certificate_issuer: result.certificate_issuer.to_owned(),
        certificate_not_before: result.certificate_not_before,
        certificate_not_after: result.certificate_not_after,
    })
}

fn tls_close(handle: u64) -> io::Result<()> {
    let mut request = [0u8; 40];
    encode_tls_close(2, handle, TCP_EXCHANGE_TIMEOUT_MS, &mut request)
        .map_err(|_| io_errno(syscall::EINVAL))?;
    let mut reply = [0u8; TLS_IO_RESULT_LEN];
    let reply_length = call(&request, &mut reply)?;
    let (request_id, status, failure, reply_handle, _) =
        decode_tls_io_result(Opcode::TlsCloseResult, &reply[..reply_length])
            .map_err(|_| io_errno(syscall::EIO))?;
    if request_id != 2 || reply_handle != handle {
        return Err(io_errno(syscall::EIO));
    }
    if status != 0 {
        eprintln!("TLS close failure: {failure:?}");
        return Err(io_errno(status.unsigned_abs() as u64));
    }
    Ok(())
}

fn tls_connect_command(host: &str, port: u16) -> io::Result<()> {
    let connection = tls_connect(host, port)?;
    println!(
        "Connected to {}:{} ({}.{}.{}.{})",
        connection.hostname,
        connection.port,
        connection.address[0],
        connection.address[1],
        connection.address[2],
        connection.address[3]
    );
    println!(
        "TLS version: {}",
        tls_version_name(connection.protocol_version)
    );
    println!(
        "Cipher suite: {}",
        cipher_suite_name(connection.cipher_suite)
    );
    println!("Server hostname: {}", connection.hostname);
    println!("Certificate subject: {}", connection.certificate_subject);
    println!("Certificate issuer: {}", connection.certificate_issuer);
    println!(
        "Certificate validity: {}..{} (Unix UTC)",
        connection.certificate_not_before, connection.certificate_not_after
    );
    tls_close(connection.handle)
}

fn tls_version_name(version: u16) -> &'static str {
    match version {
        0x0304 => "TLS 1.3",
        _ => "unknown",
    }
}

fn cipher_suite_name(cipher_suite: u16) -> &'static str {
    match cipher_suite {
        0x1301 => "TLS_AES_128_GCM_SHA256",
        0x1303 => "TLS_CHACHA20_POLY1305_SHA256",
        _ => "unknown",
    }
}

struct HttpResponseInfo {
    handle: u64,
    status_code: u16,
    body_length: usize,
    content_type: String,
}

fn http_get(url: &str) -> io::Result<HttpResponseInfo> {
    let mut request = vec![0u8; 48 + MAX_HTTP_URL_LEN];
    let request_length = encode_http_request(
        10,
        HttpMethod::Get,
        TCP_EXCHANGE_TIMEOUT_MS,
        url,
        "",
        &[],
        &mut request,
    )
    .map_err(|_| io_errno(syscall::EINVAL))?;
    let mut reply = [0u8; 56 + 256];
    let reply_length = call(&request[..request_length], &mut reply)?;
    let result =
        decode_http_request_result(&reply[..reply_length]).map_err(|_| io_errno(syscall::EIO))?;
    if result.request_id != 10 {
        return Err(io_errno(syscall::EIO));
    }
    if result.status != 0 || result.failure != HttpFailure::None {
        eprintln!("HTTP failure: {:?}", result.failure);
        return Err(io_errno(result.status.unsigned_abs() as u64));
    }
    Ok(HttpResponseInfo {
        handle: result.handle,
        status_code: result.status_code,
        body_length: result.body_length as usize,
        content_type: result.content_type.to_owned(),
    })
}

fn http_read(handle: u64, stream: HttpStream, maximum: usize) -> io::Result<(Vec<u8>, bool)> {
    let maximum = maximum.min(MAX_HTTP_IPC_DATA_LEN);
    let mut request = [0u8; HTTP_READ_REQUEST_LEN];
    encode_http_read(11, handle, maximum as u32, stream, &mut request)
        .map_err(|_| io_errno(syscall::EINVAL))?;
    let mut reply = vec![0u8; 48 + maximum];
    let reply_length = call(&request, &mut reply)?;
    let (request_id, status, failure, reply_handle, complete, data) =
        decode_http_read_result(Opcode::HttpReadResult, &reply[..reply_length])
            .map_err(|_| io_errno(syscall::EIO))?;
    if request_id != 11 || reply_handle != handle {
        return Err(io_errno(syscall::EIO));
    }
    if status != 0 || failure != HttpFailure::None {
        eprintln!("HTTP read failure: {failure:?}");
        return Err(io_errno(status.unsigned_abs() as u64));
    }
    Ok((data.to_vec(), complete))
}

fn http_close(handle: u64) -> io::Result<()> {
    let mut request = [0u8; HTTP_CLOSE_REQUEST_LEN];
    encode_http_close(12, handle, &mut request).map_err(|_| io_errno(syscall::EINVAL))?;
    let mut reply = [0u8; 48];
    let reply_length = call(&request, &mut reply)?;
    let (request_id, status, failure, reply_handle, _, _) =
        decode_http_read_result(Opcode::HttpCloseResult, &reply[..reply_length])
            .map_err(|_| io_errno(syscall::EIO))?;
    if request_id != 12 || reply_handle != handle {
        return Err(io_errno(syscall::EIO));
    }
    if status != 0 || failure != HttpFailure::None {
        return Err(io_errno(status.unsigned_abs() as u64));
    }
    Ok(())
}

fn https_get_command(url: &str) -> io::Result<()> {
    let response = http_get(url)?;
    let display_length = response.body_length.min(MAX_BODY_DISPLAY);
    let mut body = Vec::with_capacity(display_length);
    while body.len() < display_length {
        let (chunk, complete) = http_read(
            response.handle,
            HttpStream::Body,
            display_length - body.len(),
        )?;
        if chunk.is_empty() {
            break;
        }
        body.extend_from_slice(&chunk);
        if complete {
            break;
        }
    }
    println!("Status: {}", response.status_code);
    println!("Content-Type: {}", response.content_type);
    println!("Content-Length: {}", response.body_length);
    println!("Body:");
    print!("{}", String::from_utf8_lossy(&body));
    if !body.ends_with(b"\n") {
        println!();
    }
    if response.body_length > body.len() {
        println!("[body display truncated at {} bytes]", body.len());
    }
    http_close(response.handle)
}

fn parse_port(value: &std::ffi::OsStr) -> io::Result<u16> {
    let port = value
        .to_string_lossy()
        .parse::<u16>()
        .map_err(|_| io_errno(syscall::EINVAL))?;
    if port == 0 {
        Err(io_errno(syscall::EINVAL))
    } else {
        Ok(port)
    }
}

fn main() -> io::Result<()> {
    let args = coreutils::args();
    match args.as_slice() {
        [command, address] if command == "ping" => {
            let address = address
                .to_string_lossy()
                .parse::<Ipv4Addr>()
                .map_err(|_| io_errno(syscall::EINVAL))?;
            ping(address)
        }
        [command] if command == "stats" => statistics(),
        [command, hostname] if command == "resolve" => {
            resolve(hostname.to_str().ok_or_else(|| io_errno(syscall::EINVAL))?).map(|_| ())
        }
        [command, host, port] if command == "tcp-connect" => tcp_connect_command(
            host.to_str().ok_or_else(|| io_errno(syscall::EINVAL))?,
            parse_port(port)?,
        ),
        [command, host, port, data] if command == "tcp-send" => tcp_send_command(
            host.to_str().ok_or_else(|| io_errno(syscall::EINVAL))?,
            parse_port(port)?,
            data.as_encoded_bytes(),
        ),
        [command, host, port] if command == "tls-connect" => tls_connect_command(
            host.to_str().ok_or_else(|| io_errno(syscall::EINVAL))?,
            parse_port(port)?,
        ),
        [command, url] if command == "https-get" => {
            https_get_command(url.to_str().ok_or_else(|| io_errno(syscall::EINVAL))?)
        }
        _ => coreutils::usage(
            "net",
            "ping <IPv4 address> | resolve <hostname> | tcp-connect <host-or-ip> <port> | tcp-send <host-or-ip> <port> <data> | tls-connect <hostname> <port> | https-get <https-url> | stats",
        ),
    }
}
