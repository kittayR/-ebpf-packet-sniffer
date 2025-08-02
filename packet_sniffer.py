from bcc import BPF
import socket
import struct
import sys

# Load eBPF program
b = BPF(src_file="packet_sniffer.c")

# Load function as SOCKET_FILTER
function_network = b.load_func("packet_monitor", BPF.SOCKET_FILTER)

# Attach to network interface (use eth0 for WSL2)
device = "eth0"
BPF.attach_raw_socket(function_network, device)

# Counters
stats = {"TCP": 0, "UDP": 0, "Other": 0, "Total": 0, "Bytes": 0}

# Output handler
def print_event(cpu, data, size):
    event = b["events"].event(data)
    src_ip = socket.inet_ntoa(struct.pack("I", event.saddr))
    dst_ip = socket.inet_ntoa(struct.pack("I", event.daddr))

    protocol = "TCP" if event.protocol == 6 else "UDP" if event.protocol == 17 else "Other"

    # Update counters
    stats[protocol] += 1
    stats["Total"] += 1
    stats["Bytes"] += event.size

    print(f"[+] {protocol} | {src_ip} → {dst_ip} | Size: {event.size} bytes")

    # Show stats every 10 packets
    if stats["Total"] % 10 == 0:
        print(f"\n--- Stats ---\nTotal Packets: {stats['Total']}\n"
              f"TCP: {stats['TCP']} | UDP: {stats['UDP']} | Other: {stats['Other']}\n"
              f"Total Bytes: {stats['Bytes']} bytes\n")

print(f"--- Packet Sniffer Started on {device} ---\nPress Ctrl+C to stop.\n")

try:
    b["events"].open_perf_buffer(print_event)
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("\n--- Final Stats ---")
    print(f"Total Packets: {stats['Total']}")
    print(f"TCP: {stats['TCP']} | UDP: {stats['UDP']} | Other: {stats['Other']}")
    print(f"Total Bytes: {stats['Bytes']} bytes")
    print("--- Stopped ---")
    sys.exit(0)

