use std::arch::x86_64::__cpuid;
use std::io::{self, Write};

use mnu_abi::performance::{
    AllocationSubsystem, BootMilestone, CounterMetric, DistributionSnapshot,
    FrameAllocationFailure, GaugeMetric, HeapAllocationSizeClass, KernelPerformanceSnapshot,
    LatencyMetric, CLOCK_SOURCE_CPUID_CRYSTAL, CLOCK_SOURCE_HYPERVISOR,
};
use mochi_user_syscall::{self as syscall, SyscallNumber};

const COUNTER_NAMES: [&str; CounterMetric::COUNT] = [
    "heap_allocations",
    "heap_allocation_bytes",
    "heap_frees",
    "heap_freed_bytes",
    "heap_allocation_failures",
    "frame_allocations",
    "frame_frees",
    "ipc_bytes_copied",
    "ipc_send_allocations",
    "ipc_receive_allocations",
    "timer_interrupts",
    "page_faults",
    "executable_bytes_read",
];

const GAUGE_NAMES: [&str; GaugeMetric::COUNT] = [
    "heap_live_bytes",
    "heap_reserved_bytes",
    "heap_quarantined_bytes",
    "frames_in_use",
    "frames_quarantined",
];

const LATENCY_NAMES: [&str; LatencyMetric::COUNT] = [
    "ipc_small_one_way",
    "ipc_small_round_trip",
    "ipc_four_kibibytes",
    "ipc_lock_wait",
    "ipc_wakeup",
    "context_switch",
    "scheduler_run_queue",
    "scheduler_wakeup",
    "vfs_path_lookup",
    "vfs_open",
    "vfs_read",
    "vfs_write",
    "vfs_close",
    "vfs_stat",
    "exec_parse",
    "exec_load",
    "exec_relocate",
    "exec_entry",
];

const BOOT_NAMES: [&str; BootMilestone::COUNT] = [
    "mnu_entry",
    "early_memory_ready",
    "page_allocator_ready",
    "bsp_ready",
    "ap_ready",
    "scheduler_started",
    "filesystem_mounted",
    "system_services_started",
    "compositor_started",
    "binder_started",
    "binder_first_frame",
    "idle",
];

const HEAP_SIZE_CLASS_NAMES: [&str; HeapAllocationSizeClass::COUNT] = [
    "0_to_16",
    "17_to_64",
    "65_to_256",
    "257_to_1024",
    "1025_to_4096",
    "4097_to_16384",
    "16385_to_65536",
    "65537_to_262144",
    "larger",
];

const ALLOCATION_SUBSYSTEM_NAMES: [&str; AllocationSubsystem::COUNT] = [
    "other",
    "scheduler",
    "ipc",
    "vfs",
    "page_fault",
    "network_receive",
    "network_transmit",
    "block_io",
    "process_creation",
    "thread_creation",
    "syscall",
];

const FRAME_FAILURE_NAMES: [&str; FrameAllocationFailure::COUNT] = [
    "allocator_unavailable",
    "exhausted",
    "invalid_contiguous_request",
    "contiguous_unavailable",
];

fn main() -> io::Result<()> {
    if !coreutils::args().is_empty() {
        coreutils::usage("mperf", "");
    }

    let mut snapshot = KernelPerformanceSnapshot::default();
    syscall::call2(
        SyscallNumber::PerformanceSnapshot,
        (&mut snapshot as *mut KernelPerformanceSnapshot) as u64,
        size_of::<KernelPerformanceSnapshot>() as u64,
    )
    .map_err(|error| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("performance snapshot syscall failed: {}", error.raw()),
        )
    })?;

    let stdout = io::stdout();
    let mut output = io::BufWriter::new(stdout.lock());
    write_snapshot(&mut output, &snapshot)?;
    output.flush()
}

fn write_snapshot(output: &mut impl Write, snapshot: &KernelPerformanceSnapshot) -> io::Result<()> {
    let processor = processor_info();
    writeln!(output, "{{")?;
    writeln!(output, "  \"format\": \"mnu-performance-v7\",")?;
    write!(output, "  \"mnu_revision\": ")?;
    write_json_string(output, env!("MNU_GIT_REVISION"))?;
    writeln!(output, ",")?;
    write!(output, "  \"rustc\": ")?;
    write_json_string(output, env!("MNU_RUSTC_VERSION"))?;
    writeln!(output, ",")?;
    writeln!(
        output,
        "  \"build_profile\": \"{}\",",
        env!("MNU_BUILD_PROFILE")
    )?;
    writeln!(
        output,
        "  \"build_features\": \"{}\",",
        env!("MNU_BUILD_FEATURES")
    )?;
    write!(output, "  \"cpu\": ")?;
    write_json_string(output, &processor.model)?;
    writeln!(output, ",")?;
    writeln!(
        output,
        "  \"cpu_count\": {},",
        std::thread::available_parallelism().map_or(0, usize::from)
    )?;
    write!(output, "  \"environment\": ")?;
    write_json_string(output, &processor.environment)?;
    writeln!(output, ",")?;
    writeln!(output, "  \"snapshot_version\": {},", snapshot.version)?;
    writeln!(output, "  \"snapshot_size_bytes\": {},", snapshot.size)?;
    writeln!(output, "  \"flags\": {},", snapshot.flags)?;
    writeln!(
        output,
        "  \"clock_source\": \"{}\",",
        clock_source(snapshot.clock_source)
    )?;
    writeln!(
        output,
        "  \"tsc_frequency_khz\": {},",
        snapshot.tsc_frequency_khz
    )?;
    writeln!(output, "  \"memory\": {{")?;
    writeln!(output, "    \"usable_frames\": {},", snapshot.usable_frames)?;
    writeln!(output, "    \"free_frames\": {},", snapshot.free_frames)?;
    writeln!(
        output,
        "    \"kernel_stack_high_water_bytes\": {},",
        snapshot.kernel_stack_high_water_bytes
    )?;
    writeln!(
        output,
        "    \"heap_capacity_bytes\": {},",
        snapshot.heap_capacity_bytes
    )?;
    writeln!(
        output,
        "    \"heap_committed_bytes\": {},",
        snapshot.heap_committed_bytes
    )?;
    writeln!(
        output,
        "    \"heap_internal_fragmentation_bytes\": {{\"current\": {}, \"peak\": {}}}",
        snapshot.heap_internal_fragmentation.current, snapshot.heap_internal_fragmentation.peak
    )?;
    writeln!(output, "  }},")?;
    write_counters(output, snapshot)?;
    writeln!(output, ",")?;
    write_gauges(output, snapshot)?;
    writeln!(output, ",")?;
    write_heap_allocations(output, snapshot)?;
    writeln!(output, ",")?;
    write_frame_allocator(output, snapshot)?;
    writeln!(output, ",")?;
    write_timer_activity(output, snapshot)?;
    writeln!(output, ",")?;
    write_vfs_activity(output, snapshot)?;
    writeln!(output, ",")?;
    write_latencies(output, snapshot)?;
    writeln!(output, ",")?;
    write_boot_timestamps(output, snapshot)?;
    writeln!(output)?;
    writeln!(output, "}}")
}

fn write_vfs_activity(
    output: &mut impl Write,
    snapshot: &KernelPerformanceSnapshot,
) -> io::Result<()> {
    let activity = snapshot.vfs_activity;
    writeln!(output, "  \"vfs\": {{")?;
    writeln!(
        output,
        "    \"metadata_queries\": {},",
        activity.metadata_queries
    )?;
    writeln!(
        output,
        "    \"read_range_calls\": {},",
        activity.read_range_calls
    )?;
    writeln!(
        output,
        "    \"write_range_calls\": {},",
        activity.write_range_calls
    )?;
    writeln!(
        output,
        "    \"read_requested_bytes\": {},",
        activity.read_requested_bytes
    )?;
    writeln!(
        output,
        "    \"read_transferred_bytes\": {},",
        activity.read_transferred_bytes
    )?;
    writeln!(
        output,
        "    \"write_requested_bytes\": {},",
        activity.write_requested_bytes
    )?;
    writeln!(
        output,
        "    \"write_transferred_bytes\": {},",
        activity.write_transferred_bytes
    )?;
    writeln!(
        output,
        "    \"temporary_buffer_allocations\": {},",
        activity.temporary_buffer_allocations
    )?;
    writeln!(
        output,
        "    \"temporary_buffer_bytes\": {},",
        activity.temporary_buffer_bytes
    )?;
    writeln!(
        output,
        "    \"path_clone_allocations\": {},",
        activity.path_clone_allocations
    )?;
    writeln!(
        output,
        "    \"path_clone_bytes\": {}",
        activity.path_clone_bytes
    )?;
    write!(output, "  }}")
}

fn write_timer_activity(
    output: &mut impl Write,
    snapshot: &KernelPerformanceSnapshot,
) -> io::Result<()> {
    let sleep = snapshot.timer_activity.sleep_queue;
    let futex = snapshot.timer_activity.futex_timeout_queue;
    writeln!(output, "  \"timer\": {{")?;
    write_latency(
        output,
        "sleep_queue_housekeeping",
        sleep.housekeeping,
        snapshot.tsc_frequency_khz,
        true,
    )?;
    writeln!(output, "    \"sleep_queue_full_scans\": {},", sleep.full_scans)?;
    writeln!(
        output,
        "    \"sleep_queue_skipped_checks\": {},",
        sleep.skipped_checks
    )?;
    writeln!(output, "    \"sleep_queue_wakeups\": {},", sleep.wakeups)?;
    write_latency(
        output,
        "futex_timeout_housekeeping",
        futex.housekeeping,
        snapshot.tsc_frequency_khz,
        true,
    )?;
    writeln!(
        output,
        "    \"futex_timeout_full_scans\": {},",
        futex.full_scans
    )?;
    writeln!(
        output,
        "    \"futex_timeout_skipped_checks\": {},",
        futex.skipped_checks
    )?;
    writeln!(
        output,
        "    \"futex_timeout_wakeups\": {}",
        futex.wakeups
    )?;
    write!(output, "  }}")
}

fn write_frame_allocator(
    output: &mut impl Write,
    snapshot: &KernelPerformanceSnapshot,
) -> io::Result<()> {
    let frame = &snapshot.frame_allocator;
    writeln!(output, "  \"frame_allocator\": {{")?;
    writeln!(output, "    \"requests\": {},", frame.requests)?;
    writeln!(output, "    \"free_list_hits\": {},", frame.free_list_hits)?;
    writeln!(output, "    \"bump_hits\": {},", frame.bump_hits)?;
    writeln!(
        output,
        "    \"contiguous_requests\": {},",
        frame.contiguous_requests
    )?;
    writeln!(
        output,
        "    \"memory_map_regions_examined\": {},",
        frame.memory_map_regions_examined
    )?;
    writeln!(output, "    \"zero_calls\": {},", frame.zero_calls)?;
    writeln!(output, "    \"zero_bytes\": {},", frame.zero_bytes)?;
    writeln!(output, "    \"zero_cycles\": {},", frame.zero_cycles)?;
    writeln!(
        output,
        "    \"bump_free_pages\": {},",
        snapshot.frame_fragmentation.bump_free_pages
    )?;
    writeln!(
        output,
        "    \"recycled_pages\": {},",
        snapshot.frame_fragmentation.recycled_pages
    )?;
    writeln!(
        output,
        "    \"largest_contiguous_pages\": {},",
        snapshot.frame_fragmentation.largest_contiguous_pages
    )?;
    write_latency(
        output,
        "lock_wait",
        snapshot.frame_allocator_lock_wait,
        snapshot.tsc_frequency_khz,
        true,
    )?;
    write_named_counts(
        output,
        "failures",
        &FRAME_FAILURE_NAMES,
        &frame.failures,
        true,
    )?;
    write_cpu_counts(
        output,
        "allocated_pages_by_cpu",
        &snapshot.frame_activity.allocated_pages_by_cpu,
        true,
    )?;
    write_named_counts(
        output,
        "allocated_pages_by_subsystem",
        &ALLOCATION_SUBSYSTEM_NAMES,
        &snapshot.frame_activity.allocated_pages_by_subsystem,
        true,
    )?;
    write_named_counts(
        output,
        "zero_calls_by_subsystem",
        &ALLOCATION_SUBSYSTEM_NAMES,
        &snapshot.frame_activity.zero_calls_by_subsystem,
        true,
    )?;
    write_named_counts(
        output,
        "zero_cycles_by_subsystem",
        &ALLOCATION_SUBSYSTEM_NAMES,
        &snapshot.frame_activity.zero_cycles_by_subsystem,
        false,
    )?;
    write!(output, "  }}")
}

fn write_heap_allocations(
    output: &mut impl Write,
    snapshot: &KernelPerformanceSnapshot,
) -> io::Result<()> {
    writeln!(output, "  \"heap_allocations\": {{")?;
    write_named_counts(
        output,
        "by_size_bytes",
        &HEAP_SIZE_CLASS_NAMES,
        &snapshot.heap_allocations_by_size,
        true,
    )?;
    write_cpu_counts(output, "by_cpu", &snapshot.heap_allocations_by_cpu, true)?;
    write_named_counts(
        output,
        "by_subsystem",
        &ALLOCATION_SUBSYSTEM_NAMES,
        &snapshot.heap_allocations_by_subsystem,
        false,
    )?;
    write!(output, "  }}")
}

fn write_cpu_counts<const N: usize>(
    output: &mut impl Write,
    group: &str,
    counts: &[u64; N],
    trailing_comma: bool,
) -> io::Result<()> {
    write!(output, "    \"{group}\": [")?;
    for (index, count) in counts.iter().enumerate() {
        if index != 0 {
            write!(output, ", ")?;
        }
        write!(output, "{count}")?;
    }
    writeln!(output, "]{}", if trailing_comma { "," } else { "" })
}

fn write_named_counts<const N: usize>(
    output: &mut impl Write,
    group: &str,
    names: &[&str; N],
    counts: &[u64; N],
    trailing_comma: bool,
) -> io::Result<()> {
    writeln!(output, "    \"{group}\": {{")?;
    for (index, name) in names.iter().enumerate() {
        let suffix = if index + 1 == N { "" } else { "," };
        writeln!(output, "      \"{name}\": {}{suffix}", counts[index])?;
    }
    writeln!(output, "    }}{}", if trailing_comma { "," } else { "" })
}

fn write_counters(output: &mut impl Write, snapshot: &KernelPerformanceSnapshot) -> io::Result<()> {
    writeln!(output, "  \"counters\": {{")?;
    for (index, name) in COUNTER_NAMES.iter().enumerate() {
        let suffix = if index + 1 == COUNTER_NAMES.len() {
            ""
        } else {
            ","
        };
        writeln!(
            output,
            "    \"{name}\": {}{suffix}",
            snapshot.counters[index]
        )?;
    }
    write!(output, "  }}")
}

fn write_gauges(output: &mut impl Write, snapshot: &KernelPerformanceSnapshot) -> io::Result<()> {
    writeln!(output, "  \"gauges\": {{")?;
    for (index, name) in GAUGE_NAMES.iter().enumerate() {
        let gauge = snapshot.gauges[index];
        let suffix = if index + 1 == GAUGE_NAMES.len() {
            ""
        } else {
            ","
        };
        writeln!(
            output,
            "    \"{name}\": {{\"current\": {}, \"peak\": {}}}{suffix}",
            gauge.current, gauge.peak
        )?;
    }
    write!(output, "  }}")
}

fn write_latencies(
    output: &mut impl Write,
    snapshot: &KernelPerformanceSnapshot,
) -> io::Result<()> {
    writeln!(output, "  \"latencies\": {{")?;
    for (index, name) in LATENCY_NAMES.iter().enumerate() {
        write_latency(
            output,
            name,
            snapshot.latencies[index],
            snapshot.tsc_frequency_khz,
            index + 1 != LATENCY_NAMES.len(),
        )?;
    }
    write!(output, "  }}")
}

fn write_latency(
    output: &mut impl Write,
    name: &str,
    latency: DistributionSnapshot,
    tsc_frequency_khz: u64,
    trailing_comma: bool,
) -> io::Result<()> {
    let mean = latency.sum_cycles.checked_div(latency.count).unwrap_or(0);
    write!(
        output,
        "    \"{name}\": {{\"count\": {}, \"mean_cycles\": {mean}, \"p50_cycles\": {}, \"p95_cycles\": {}, \"p99_cycles\": {}, \"max_cycles\": {}, \"p50_ns\": ",
        latency.count,
        latency.p50_cycles,
        latency.p95_cycles,
        latency.p99_cycles,
        latency.max_cycles,
    )?;
    write_nanoseconds(output, latency.p50_cycles, tsc_frequency_khz)?;
    write!(output, ", \"p95_ns\": ")?;
    write_nanoseconds(output, latency.p95_cycles, tsc_frequency_khz)?;
    write!(output, ", \"p99_ns\": ")?;
    write_nanoseconds(output, latency.p99_cycles, tsc_frequency_khz)?;
    writeln!(output, "}}{}", if trailing_comma { "," } else { "" })
}

fn write_boot_timestamps(
    output: &mut impl Write,
    snapshot: &KernelPerformanceSnapshot,
) -> io::Result<()> {
    let origin = snapshot.boot_timestamps[BootMilestone::MnuEntry as usize];
    writeln!(output, "  \"boot\": {{")?;
    for (index, name) in BOOT_NAMES.iter().enumerate() {
        let timestamp = snapshot.boot_timestamps[index];
        let elapsed = timestamp.checked_sub(origin).filter(|_| timestamp != 0);
        let suffix = if index + 1 == BOOT_NAMES.len() {
            ""
        } else {
            ","
        };
        write!(
            output,
            "    \"{name}\": {{\"tsc\": {timestamp}, \"elapsed_ns\": "
        )?;
        match elapsed {
            Some(cycles) => write_nanoseconds(output, cycles, snapshot.tsc_frequency_khz)?,
            None => write!(output, "null")?,
        }
        writeln!(output, "}}{suffix}")?;
    }
    write!(output, "  }}")
}

fn write_nanoseconds(output: &mut impl Write, cycles: u64, frequency_khz: u64) -> io::Result<()> {
    if frequency_khz == 0 {
        return write!(output, "null");
    }
    let nanoseconds = u128::from(cycles)
        .saturating_mul(1_000_000)
        .checked_div(u128::from(frequency_khz))
        .unwrap_or(0);
    write!(output, "{nanoseconds}")
}

fn clock_source(source: u32) -> &'static str {
    match source {
        CLOCK_SOURCE_HYPERVISOR => "hypervisor",
        CLOCK_SOURCE_CPUID_CRYSTAL => "cpuid-crystal",
        _ => "unavailable",
    }
}

struct ProcessorInfo {
    model: String,
    environment: String,
}

fn processor_info() -> ProcessorInfo {
    let highest_extended = __cpuid(0x8000_0000).eax;
    let model = if highest_extended >= 0x8000_0004 {
        let mut bytes = [0u8; 48];
        for (index, leaf) in (0x8000_0002..=0x8000_0004).enumerate() {
            let registers = __cpuid(leaf);
            let offset = index * 16;
            bytes[offset..offset + 4].copy_from_slice(&registers.eax.to_le_bytes());
            bytes[offset + 4..offset + 8].copy_from_slice(&registers.ebx.to_le_bytes());
            bytes[offset + 8..offset + 12].copy_from_slice(&registers.ecx.to_le_bytes());
            bytes[offset + 12..offset + 16].copy_from_slice(&registers.edx.to_le_bytes());
        }
        String::from_utf8_lossy(&bytes)
            .trim_matches(char::from(0))
            .trim()
            .to_owned()
    } else {
        String::from("unknown")
    };

    let feature = __cpuid(1);
    let environment = if feature.ecx & (1 << 31) == 0 {
        String::from("physical-machine")
    } else {
        let vendor = __cpuid(0x4000_0000);
        let mut bytes = [0u8; 12];
        bytes[0..4].copy_from_slice(&vendor.ebx.to_le_bytes());
        bytes[4..8].copy_from_slice(&vendor.ecx.to_le_bytes());
        bytes[8..12].copy_from_slice(&vendor.edx.to_le_bytes());
        format!(
            "virtual-machine:{}",
            String::from_utf8_lossy(&bytes).trim_matches(char::from(0))
        )
    };

    ProcessorInfo { model, environment }
}

fn write_json_string(output: &mut impl Write, value: &str) -> io::Result<()> {
    write!(output, "\"")?;
    for character in value.chars() {
        match character {
            '\"' => write!(output, "\\\"")?,
            '\\' => write!(output, "\\\\")?,
            '\n' => write!(output, "\\n")?,
            '\r' => write!(output, "\\r")?,
            '\t' => write!(output, "\\t")?,
            character if character.is_control() => write!(output, "\\u{:04x}", character as u32)?,
            character => write!(output, "{character}")?,
        }
    }
    write!(output, "\"")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_output_contains_stable_metric_names() {
        let mut snapshot = KernelPerformanceSnapshot {
            version: 1,
            size: size_of::<KernelPerformanceSnapshot>() as u32,
            tsc_frequency_khz: 2_000_000,
            ..KernelPerformanceSnapshot::default()
        };
        snapshot.latencies[LatencyMetric::IpcSmallRoundTrip as usize].count = 4;
        snapshot.latencies[LatencyMetric::IpcSmallRoundTrip as usize].sum_cycles = 800;
        snapshot.latencies[LatencyMetric::IpcSmallRoundTrip as usize].p99_cycles = 400;

        let mut output = Vec::new();
        write_snapshot(&mut output, &snapshot).unwrap();
        let output = String::from_utf8(output).unwrap();

        assert!(output.starts_with("{\n"));
        assert!(output.ends_with("}\n"));
        assert!(output.contains("\"ipc_small_round_trip\""));
        assert!(output.contains("\"mean_cycles\": 200"));
        assert!(output.contains("\"p99_ns\": 200"));
        assert!(output.contains("\"heap_live_bytes\""));
        assert!(output.contains("\"by_subsystem\""));
        assert!(output.contains("\"heap_committed_bytes\""));
        assert!(output.contains("\"frame_allocator\""));
        assert!(output.contains("\"memory_map_regions_examined\""));
        assert!(output.contains("\"lock_wait\""));
        assert!(output.contains("\"largest_contiguous_pages\""));
        assert!(output.contains("\"allocated_pages_by_cpu\""));
        assert!(output.contains("\"zero_cycles_by_subsystem\""));
        assert!(output.contains("\"timer\""));
        assert!(output.contains("\"vfs\""));
        assert!(output.contains("\"temporary_buffer_allocations\""));
        assert!(output.contains("\"path_clone_bytes\""));
        assert!(output.contains("\"sleep_queue_housekeeping\""));
        assert!(output.contains("\"futex_timeout_full_scans\""));
        assert!(output.contains("\"contiguous_unavailable\""));
        assert!(output.contains("\"mnu_entry\""));
    }

    #[test]
    fn unavailable_clock_writes_null_nanoseconds() {
        let mut output = Vec::new();
        write_nanoseconds(&mut output, 123, 0).unwrap();
        assert_eq!(output, b"null");
    }

    #[test]
    fn json_strings_escape_control_characters() {
        let mut output = Vec::new();
        write_json_string(&mut output, "a\n\"b\\c").unwrap();
        assert_eq!(output, br#""a\n\"b\\c""#);
    }
}
