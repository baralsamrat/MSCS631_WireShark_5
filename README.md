# MSCS631_WireShark_5
Wireshark – Lab 4: IP

**Samrat Baral**

University of the Cumberlands  

2025 Spring – Advanced Computer Networks (MSCS-631-M40) – Full Term  

Dr. Yousef Nijim

March 14, 2025

---

# Lab Overview
In this lab, you will investigate the IPv4 and IPv6 protocols using packet traces. You will analyze:
- IPv4 datagrams captured during a traceroute session,
- The behavior of UDP and ICMP packets,
- IP fragmentation in large UDP segments,
- IPv6 DNS and traffic details.

The lab requires you to inspect packet headers in Wireshark, answer questions about header fields, fragmentation, and IPv6 addressing, and use display filters to focus on specific traffic.

---

## Output Screenshots

![1](./screenshots/Capture-1.PNG)  
![2](./screenshots/Capture-2.PNG)  
![3](./screenshots/Capture-3.PNG)  


## Prerequisites

- **Python 3.x**
- **Tshark:** Ensure that Tshark is installed and available in your system's PATH.  
  Download from [Wireshark](https://www.wireshark.org/download.html).
- **Pyshark:** Install via pip: 
```bash
pip install pyshark
python3 lab5.py
```

## Features

- Analysis of IPv4 header fields (TTL, Identification, etc.)
- Examination of UDP, ICMP, and fragmented datagrams
- IPv6 packet inspection and DNS AAAA request analysis

  
