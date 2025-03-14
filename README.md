# MSCS631_WireShark_5
Wireshark – Lab 5: IP

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

Below is the complete Markdown file content for your lab report. Save this text as lab5.md in your project directory.

# MSCS631_WireShark_5
Wireshark – Lab 5: IP Protocol, Fragmentation, and IPv6

**Your Name**

University Name

2025 Spring – Advanced Computer Networks (MSCS-631-M40) – Full Term

Dr. Yousef Nijim

March 2, 2025

---

# Lab Overview

In this lab, you will investigate the IPv4 and IPv6 protocols using packet traces. You will analyze:
- IPv4 datagrams captured during a traceroute session,
- The behavior of UDP and ICMP packets,
- IP fragmentation in large UDP segments,
- IPv6 DNS and traffic details.

The lab requires you to inspect packet headers in Wireshark, answer questions about header fields, fragmentation, and IPv6 addressing, and use display filters to focus on specific traffic.

  
```bash
  pip install pyshark
```

	•	Download the required trace files (e.g., ip-wireshark-trace1-1.pcapng and ip-wireshark-trace2-1.pcapng) from the Wireshark Labs repository:
Wireshark Labs Trace Files

# Lab Analysis and Answers


## Part 1: Basic IPv4

### Question 1: Select the first UDP segment sent by your computer via the traceroute command to gaia.cs.umass.edu. Expand the Internet Protocol part of the packet in the packet details window. What is the IP address of your computer?


### Question 2: What is the value in the time-to-live (TTL) field in this IPv4 datagram’s header?


### Question 3: What is the value in the upper layer protocol field in this IPv4 datagram’s header? [Note: the answers for Linux/MacOS differ from Windows here].


### Question 4:How many bytes are in the IP header?

### Question 5: How many bytes are in the payload of the IP datagram? Explain how you determined the number of payload bytes.

### Question 6: Has this IP datagram been fragmented? Explain how you determined whether or not the datagram has been fragmented.

### Question 7: Which fields in the IP datagram always change from one datagram to the next within this series of UDP segments sent by your computer destined to 128.119.245.12, via traceroute? Why?

### Question 8: Which fields in this sequence of IP datagrams (containing UDP segments) stay constant? Why?

### Question 9: Describe the pattern you see in the values in the Identification field of the IP datagrams being sent by your computer.

### Question 10: What is the upper layer protocol specified in the IP datagrams returned from the routers? [Note: the answers for Linux/MacOS differ from Windows here].

### Question 11: Are the values in the Identification fields (across the sequence of all of ICMP packets from all of the routers) similar in behavior to your answer to question 9 above?

### Question 12: Are the values of the TTL fields similar, across all of the ICMP packets from all of the routers?


## Part 2: Fragmentation


### Question 13: Find the first IP datagram containing the first part of the segment sent to 128.119.245.12 by your computer (using traceroute with a packet length of 3000 bytes). Has that segment been fragmented across more than one IP datagram?

### Question 14: What information in the IP header indicates that this datagram has been fragmented?


### Question 15: What information in the IP header for this packet indicates whether this is the first fragment versus a latter fragment?


### Question 16: How many bytes are there in this IP datagram (header plus payload)?


### Question 17: Inspect the datagram containing the second fragment of the fragmented UDP segment. What information in the IP header indicates that this is not the first datagram fragment?


### Question 18: What fields change in the IP header between the first and second fragment?


### Question 19: Find the IP datagram containing the third fragment of the original UDP segment. What information in the IP header indicates that this is the last fragment of that segment?



## Part 3: IPv6

### Question 20: What is the IPv6 address of the computer making the DNS AAAA request? Give the IPv6 source address for this datagram in the exact same form as displayed in the Wireshark window.

### Question 21: What is the IPv6 destination address for this datagram? Give this IPv6 address in the exact same form as displayed in the Wireshark window.

### Question 22:What is the value of the flow label for this datagram?


### Question 23: How much payload data is carried in this datagram?



### Question 24: What is the upper layer protocol to which this datagram’s payload will be delivered at the destination?



### Question 25: How many IPv6 addresses are returned in the response to the AAAA request?


### Question 26: What is the first of the IPv6 addresses returned by the DNS for youtube.com? Give this IPv6 address in the exact same shorthand form as displayed in the Wireshark window.


Conclusion

Summarize your findings and insights from the lab analysis here.
You now have a complete lab report template in Markdown that includes all questions and placeholders for your answers.
