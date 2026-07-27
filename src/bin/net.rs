use std::io;
use std::net::Ipv4Addr;

use mochi_user_syscall as syscall;
use mochios_net_device_protocol::{
    HEADER_LEN, Opcode, PING_REQUEST_LEN, PING_RESULT_LEN, STACK_STATISTICS_LEN,
    decode_ping_result, decode_stack_statistics, encode_empty, encode_ping,
};

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
    Ok(())
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
        _ => coreutils::usage("net", "ping <IPv4 address> | stats"),
    }
}
