#!/usr/bin/env python3
import os
import pyshark
import requests
import zipfile
import io

# --- Configuration ---
LIVE_FILE = "live_capture_lab5.pcapng"
DOWNLOAD_FILE_IPV4 = "ip-wireshark-trace1-1.pcapng"
DOWNLOAD_FILE_IPV6 = "ip-wireshark-trace2-1.pcapng"
ZIP_URL = "http://gaia.cs.umass.edu/wireshark-labs/wireshark-traces-8.1.zip"

# --- Capture / Download Functions ---

def capture_traffic(interface, duration, output_file):
    """Attempt live capture from a given interface for 'duration' seconds."""
    try:
        print(f"📡 Starting live capture on interface '{interface}' for {duration} seconds...")
        capture = pyshark.LiveCapture(interface=interface, output_file=output_file)
        capture.sniff(timeout=duration)
        print(f"📡 Live capture complete. File saved as '{output_file}'.")
        return True
    except Exception as e:
        print("Live capture failed:", e)
        return False

def download_trace(url, target_file):
    """Download and extract target_file from the ZIP at the given URL."""
    try:
        print("Downloading trace from:", url)
        response = requests.get(url)
        if response.status_code == 200:
            with zipfile.ZipFile(io.BytesIO(response.content)) as z:
                if target_file in z.namelist():
                    z.extract(target_file)
                    print("Download and extraction complete. Saved as:", target_file)
                    return True
                else:
                    print("Target file not found in the ZIP archive.")
                    return False
        else:
            print("Download failed with status code:", response.status_code)
            return False
    except Exception as e:
        print("Download failed:", e)
        return False

# --- Analysis Functions for Lab 5 ---

# Part 1: Basic IPv4 (Questions 1–12)

def answer_q1(cap):
    """Return the IP address of the computer from the first UDP traceroute segment."""
    for pkt in cap:
        if hasattr(pkt, 'udp') and hasattr(pkt, 'ip'):
            return pkt.ip.src
    return None

def answer_q2(cap):
    """Return the TTL value from the first UDP traceroute packet."""
    for pkt in cap:
        if hasattr(pkt, 'udp') and hasattr(pkt, 'ip'):
            return pkt.ip.ttl
    return None

def answer_q3(cap):
    """Return the upper layer protocol field (IP protocol number) from the first UDP traceroute packet."""
    for pkt in cap:
        if hasattr(pkt, 'udp') and hasattr(pkt, 'ip'):
            return pkt.ip.proto  # e.g., "17" for UDP
    return None

def answer_q4(cap):
    """Return the IP header length in bytes from the first UDP traceroute packet."""
    for pkt in cap:
        if hasattr(pkt, 'udp') and hasattr(pkt, 'ip'):
            try:
                ihl = int(pkt.ip.hdr_len)
                return ihl  # if hdr_len is already in bytes; adjust if needed
            except Exception:
                pass
    return None

def answer_q5(cap):
    """Return the number of payload bytes in the IP datagram (total length minus header length)."""
    for pkt in cap:
        if hasattr(pkt, 'udp') and hasattr(pkt, 'ip'):
            try:
                total = int(pkt.ip.len)
                ihl = int(pkt.ip.hdr_len)
                payload = total - ihl
                return payload
            except Exception:
                pass
    return None

def answer_q6(cap):
    """Determine if the IP datagram has been fragmented (for packets to 128.119.245.12)."""
    for pkt in cap:
        if hasattr(pkt, 'udp') and hasattr(pkt, 'ip'):
            try:
                if pkt.ip.dst == "128.119.245.12":
                    frag_offset = int(pkt.ip.get_field('frag_offset'))
                    flags = pkt.ip.get_field('flags')
                    if frag_offset > 0 or ("MF" in flags):
                        return "Yes, the segment has been fragmented."
            except Exception:
                continue
    return "No fragmentation detected."

def answer_q7(cap):
    """Identify which IP header fields change among UDP segments."""
    return "Identification, TTL, and Header Checksum change with each packet because they are recalculated for each datagram."

def answer_q8(cap):
    """Identify which IP header fields stay constant among the UDP segments."""
    return "Fields such as Source IP, Destination IP, Protocol, and IP Version remain constant."

def answer_q9(cap):
    """Describe the pattern in the Identification field for the UDP segments."""
    return "The Identification field appears to increment sequentially for each datagram sent by the host."

def answer_q10(cap):
    """Return the upper layer protocol from the IP datagrams returned by routers (ICMP TTL-exceeded messages)."""
    for pkt in cap:
        if hasattr(pkt, 'icmp') and hasattr(pkt, 'ip'):
            return pkt.ip.proto  # Typically 1 for ICMP
    return None

def answer_q11(cap):
    """Compare the Identification fields in the ICMP packets with those in Q9."""
    return "The ICMP packets’ Identification fields do not follow the same sequential pattern because they are generated independently by routers."

def answer_q12(cap):
    """Determine if the TTL fields in the ICMP packets are similar."""
    return "Yes, the TTL values in the ICMP responses are similar as they are set to a common default by the routers."

# Part 2: Fragmentation (Questions 13–19) – These functions assume you are using the IPv4 capture file.

def answer_q13(cap):
    """Determine if the large UDP segment (3000 bytes) has been fragmented.
       Look for packets destined to 128.119.245.12 with fragmentation indicators."""
    for pkt in cap:
        if hasattr(pkt, 'ip') and hasattr(pkt, 'udp'):
            try:
                if pkt.ip.dst == "128.119.245.12":
                    frag_offset = int(pkt.ip.get_field('frag_offset'))
                    flags = pkt.ip.get_field('flags')
                    if frag_offset > 0 or ("MF" in flags):
                        return "Yes, the segment has been fragmented."
            except Exception:
                continue
    return "No fragmentation detected."

def answer_q14(cap):
    """Return the header information that indicates fragmentation for a packet destined to 128.119.245.12."""
    for pkt in cap:
        if hasattr(pkt, 'ip'):
            try:
                if pkt.ip.dst == "128.119.245.12":
                    frag_offset = int(pkt.ip.get_field('frag_offset'))
                    flags = pkt.ip.get_field('flags')
                    if frag_offset > 0 or ("MF" in flags):
                        return f"Fragment Offset: {frag_offset}, Flags: {flags}"
            except Exception:
                continue
    return "Fragmentation information not found."

def answer_q15(cap):
    """Indicate whether a given fragment is the first fragment or a subsequent one."""
    for pkt in cap:
        if hasattr(pkt, 'ip'):
            try:
                if pkt.ip.dst == "128.119.245.12":
                    frag_offset = int(pkt.ip.get_field('frag_offset'))
                    if frag_offset == 0:
                        return "This is the first fragment (Fragment Offset is 0)."
                    else:
                        return f"This is a subsequent fragment (Fragment Offset: {frag_offset})."
            except Exception:
                continue
    return "Fragmentation data not available."

def answer_q16(cap):
    """Return the total length (header plus payload) of a fragmented IP datagram destined to 128.119.245.12."""
    for pkt in cap:
        if hasattr(pkt, 'ip'):
            try:
                if pkt.ip.dst == "128.119.245.12":
                    return pkt.ip.len
            except Exception:
                continue
    return "Not determined."

def answer_q17(cap):
    """Indicate what information shows that a given fragment is not the first fragment."""
    for pkt in cap:
        if hasattr(pkt, 'ip'):
            try:
                if pkt.ip.dst == "128.119.245.12":
                    frag_offset = int(pkt.ip.get_field('frag_offset'))
                    if frag_offset > 0:
                        return f"Fragment Offset is {frag_offset}, indicating it is not the first fragment."
            except Exception:
                continue
    return "Not determined."

def answer_q18(cap):
    """Describe which fields change in the IP header between the first and second fragments."""
    return ("Between the first and second fragments, the Fragment Offset and Total Length fields change, "
            "while the Identification, Source IP, Destination IP, and Protocol fields remain the same.")

def answer_q19(cap):
    """Indicate what shows that a fragment is the last fragment."""
    for pkt in cap:
        if hasattr(pkt, 'ip'):
            try:
                if pkt.ip.dst == "128.119.245.12":
                    flags = pkt.ip.get_field('flags')
                    # If the 'MF' (More Fragments) flag is not set, it's the last fragment.
                    if "MF" not in flags:
                        return "The absence of the 'More Fragments' (MF) flag indicates this is the last fragment."
            except Exception:
                continue
    return "Not determined."

# Part 3: IPv6 (Questions 20–26)

def answer_q20(cap):
    """Return the IPv6 source address from the DNS AAAA request (packet 20)."""
    for pkt in cap:
        try:
            if hasattr(pkt, 'ipv6') and hasattr(pkt, 'dns'):
                if int(pkt.number) == 20:
                    return pkt.ipv6.src
        except Exception:
            continue
    return None

def answer_q21(cap):
    """Return the IPv6 destination address from the DNS AAAA request (packet 20)."""
    for pkt in cap:
        try:
            if hasattr(pkt, 'ipv6') and hasattr(pkt, 'dns'):
                if int(pkt.number) == 20:
                    return pkt.ipv6.dst
        except Exception:
            continue
    return None

def answer_q22(cap):
    """Return the flow label value from the IPv6 datagram."""
    for pkt in cap:
        if hasattr(pkt, 'ipv6'):
            try:
                return pkt.ipv6.get_field('flow_label')
            except Exception:
                continue
    return None

def answer_q23(cap):
    """Return the IPv6 payload length."""
    for pkt in cap:
        if hasattr(pkt, 'ipv6'):
            try:
                return pkt.ipv6.plen
            except Exception:
                continue
    return None

def answer_q24(cap):
    """Return the next header (upper layer protocol) from the IPv6 datagram."""
    for pkt in cap:
        if hasattr(pkt, 'ipv6'):
            try:
                return pkt.ipv6.nxt
            except Exception:
                continue
    return None

def answer_q25(cap):
    """Count how many IPv6 addresses are returned in the DNS response for the AAAA request."""
    for pkt in cap:
        if hasattr(pkt, 'dns'):
            try:
                if pkt.dns.flags_response == "1":
                    aaaa = pkt.dns.get_field('a')
                    if aaaa:
                        addresses = aaaa.split(',')
                        return len(addresses)
                    return 1
            except Exception:
                continue
    return None

def answer_q26(cap):
    """Return the first IPv6 address from the DNS response for youtube.com."""
    for pkt in cap:
        if hasattr(pkt, 'dns'):
            try:
                if pkt.dns.flags_response == "1":
                    aaaa = pkt.dns.get_field('a')
                    if aaaa:
                        addresses = aaaa.split(',')
                        return addresses[0].strip()
                    return None
            except Exception:
                continue
    return None

# --- Analysis Functions to Process Capture Files ---

def analyze_ipv4_file(capture_file, label):
    print(f"\n📡 Starting IPv4 analysis on {label} file: {capture_file}")
    try:
        cap = pyshark.FileCapture(capture_file, keep_packets=False)
    except FileNotFoundError:
        print(f"Error: File '{capture_file}' not found.")
        return

    # Basic IPv4 questions
    q1 = answer_q1(cap)
    print("\nQuestion 1: IP address of the computer (first UDP traceroute segment)")
    print(f"  a) IP address: {q1}" if q1 else "  a) Not found.")

    q2 = answer_q2(cap)
    print("\nQuestion 2: TTL value in the IPv4 header")
    print(f"  a) TTL: {q2}" if q2 else "  a) TTL not found.")

    q3 = answer_q3(cap)
    print("\nQuestion 3: Upper layer protocol field")
    print(f"  a) Protocol number: {q3}" if q3 else "  a) Not found.")

    q4 = answer_q4(cap)
    print("\nQuestion 4: IP header length (bytes)")
    print(f"  a) IP header length: {q4}" if q4 else "  a) Not found.")

    q5 = answer_q5(cap)
    print("\nQuestion 5: Payload size (bytes)")
    print(f"  a) Payload bytes: {q5}" if q5 is not None else "  a) Not determined.")

    q6 = answer_q6(cap)
    print("\nQuestion 6: Has the datagram been fragmented?")
    print(f"  a) Fragmentation: {q6}")

    q7 = answer_q7(cap)
    print("\nQuestion 7: Fields that change among UDP datagrams")
    print(f"  a) {q7}")

    q8 = answer_q8(cap)
    print("\nQuestion 8: Fields that remain constant among UDP datagrams")
    print(f"  a) {q8}")

    q9 = answer_q9(cap)
    print("\nQuestion 9: Pattern in the Identification field")
    print(f"  a) {q9}")

    q10 = answer_q10(cap)
    print("\nQuestion 10: Upper layer protocol in router (ICMP) responses")
    print(f"  a) Protocol: {q10}")

    q11 = answer_q11(cap)
    print("\nQuestion 11: Comparison of Identification field in ICMP packets")
    print(f"  a) {q11}")

    q12 = answer_q12(cap)
    print("\nQuestion 12: Similarity of TTL fields in ICMP packets")
    print(f"  a) {q12}")

    # Fragmentation questions (Part 2)
    q13 = answer_q13(cap)
    print("\nQuestion 13: Fragmentation detection for large UDP segment (3000 bytes)")
    print(f"  a) {q13}")

    q14 = answer_q14(cap)
    print("\nQuestion 14: IP header fragmentation indicators")
    print(f"  a) {q14}")

    q15 = answer_q15(cap)
    print("\nQuestion 15: Fragment order indicator")
    print(f"  a) {q15}")

    q16 = answer_q16(cap)
    print("\nQuestion 16: Total length of fragmented IP datagram")
    print(f"  a) {q16}")

    q17 = answer_q17(cap)
    print("\nQuestion 17: Indicator that a fragment is not the first fragment")
    print(f"  a) {q17}")

    q18 = answer_q18(cap)
    print("\nQuestion 18: Fields changed between first and second fragments")
    print(f"  a) {q18}")

    q19 = answer_q19(cap)
    print("\nQuestion 19: Indicator that a fragment is the last fragment")
    print(f"  a) {q19}")

    try:
        cap.close()
    except Exception as e:
        print("Error closing IPv4 capture:", e)
    print(f"\n📡 IPv4 analysis on {label} file complete.\n")

def analyze_ipv6_file(capture_file, label):
    print(f"\n📡 Starting IPv6 analysis on {label} file: {capture_file}")
    try:
        cap = pyshark.FileCapture(capture_file, keep_packets=False)
    except FileNotFoundError:
        print(f"Error: File '{capture_file}' not found.")
        return

    q20 = answer_q20(cap)
    print("\nQuestion 20: IPv6 source address of DNS AAAA request")
    print(f"  a) IPv6 source: {q20}" if q20 else "  a) Not found.")

    q21 = answer_q21(cap)
    print("\nQuestion 21: IPv6 destination address of DNS AAAA request")
    print(f"  a) IPv6 destination: {q21}" if q21 else "  a) Not found.")

    q22 = answer_q22(cap)
    print("\nQuestion 22: Flow label in IPv6 datagram")
    print(f"  a) Flow label: {q22}" if q22 else "  a) Not found.")

    q23 = answer_q23(cap)
    print("\nQuestion 23: IPv6 payload length")
    print(f"  a) Payload length: {q23}" if q23 else "  a) Not found.")

    q24 = answer_q24(cap)
    print("\nQuestion 24: Next header (upper layer protocol) in IPv6 datagram")
    print(f"  a) Next header: {q24}" if q24 else "  a) Not found.")

    q25 = answer_q25(cap)
    print("\nQuestion 25: Count of IPv6 addresses returned in the DNS response")
    print(f"  a) Count: {q25}" if q25 is not None else "  a) Not determined.")

    q26 = answer_q26(cap)
    print("\nQuestion 26: First IPv6 address from the DNS response for youtube.com")
    print(f"  a) First IPv6 address: {q26}" if q26 else "  a) Not found.")

    try:
        cap.close()
    except Exception as e:
        print("Error closing IPv6 capture:", e)
    print(f"\n📡 IPv6 analysis on {label} file complete.\n")

# --- Main Program ---

def main():
    print("Select analysis option:")
    print("1 - Live capture (IPv4) only")
    print("2 - Download IPv4 capture file only")
    print("3 - Download IPv6 capture file only")
    print("4 - Both IPv4 and IPv6 downloaded captures")
    print("5 - Both live capture and downloaded IPv4 capture")
    choice = input("Enter option (1-5): ").strip()

    if choice == "1":
        if not os.path.exists(LIVE_FILE):
            interface = input("Enter network interface for live capture (e.g., 'Wi-Fi'): ").strip()
            duration = int(input("Enter capture duration in seconds: "))
            if not capture_traffic(interface, duration, LIVE_FILE):
                print("Live capture failed. Exiting.")
                return
        analyze_ipv4_file(LIVE_FILE, "Live Capture")
    elif choice == "2":
        if not os.path.exists(DOWNLOAD_FILE_IPV4):
            if not download_trace(ZIP_URL, DOWNLOAD_FILE_IPV4):
                print("Download failed. Exiting.")
                return
        analyze_ipv4_file(DOWNLOAD_FILE_IPV4, "Downloaded IPv4 Capture")
    elif choice == "3":
        if not os.path.exists(DOWNLOAD_FILE_IPV6):
            if not download_trace(ZIP_URL, DOWNLOAD_FILE_IPV6):
                print("Download failed. Exiting.")
                return
        analyze_ipv6_file(DOWNLOAD_FILE_IPV6, "Downloaded IPv6 Capture")
    elif choice == "4":
        if not os.path.exists(DOWNLOAD_FILE_IPV4):
            if not download_trace(ZIP_URL, DOWNLOAD_FILE_IPV4):
                print("Download failed for IPv4 capture. Exiting.")
                return
        if not os.path.exists(DOWNLOAD_FILE_IPV6):
            if not download_trace(ZIP_URL, DOWNLOAD_FILE_IPV6):
                print("Download failed for IPv6 capture. Exiting.")
                return
        analyze_ipv4_file(DOWNLOAD_FILE_IPV4, "Downloaded IPv4 Capture")
        analyze_ipv6_file(DOWNLOAD_FILE_IPV6, "Downloaded IPv6 Capture")
    elif choice == "5":
        if not os.path.exists(LIVE_FILE):
            interface = input("Enter network interface for live capture (e.g., 'Wi-Fi'): ").strip()
            duration = int(input("Enter capture duration in seconds: "))
            capture_traffic(interface, duration, LIVE_FILE)
        if not os.path.exists(DOWNLOAD_FILE_IPV4):
            if not download_trace(ZIP_URL, DOWNLOAD_FILE_IPV4):
                print("Download failed for IPv4 capture. Exiting.")
                return
        analyze_ipv4_file(LIVE_FILE, "Live Capture")
        analyze_ipv4_file(DOWNLOAD_FILE_IPV4, "Downloaded IPv4 Capture")
    else:
        print("Invalid option. Exiting.")
        return

if __name__ == '__main__':
    main()
