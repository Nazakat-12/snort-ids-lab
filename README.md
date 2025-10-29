
# Network Intrusion Detection Lab — Snort IDS

## Overview
This repo documents a hands-on lab where I configured **Snort (open-source IDS)** in an isolated environment to detect common network-based attack patterns, analyze alerts, and recommend mitigation steps. The work demonstrates practical skills in IDS tuning, alert validation, packet analysis, and translating technical findings into business-focused remediation.

**Key skills demonstrated:** Snort configuration & tuning, rule writing, packet capture analysis (Wireshark), alert triage, mitigation planning, report writing.

## Table of Contents
- [Lab Goals](#lab-goals)  
- [Environment & Topology](#environment--topology)  
- [Tools Used](#tools-used)  
- [Setup & Configuration (high level)](#setup--configuration-high-level)  
- [Sample Snort Rules](#sample-snort-rules)  
- [Detection Scenarios & Test Steps](#detection-scenarios--test-steps)  
- [Alert Analysis & Evidence](#alert-analysis--evidence)  
- [Mitigations & Recommendations](#mitigations--recommendations)  
- [Deliverables & Files in Repo](#deliverables--files-in-repo)  
- [Next Steps & Learning Notes](#next-steps--learning-notes)

---

## Lab Goals
1. Deploy Snort in IDS mode to monitor a lab subnet.  
2. Create and tune custom rules for high-value detections (reconnaissance, ICMP flood, suspicious HTTP requests).  
3. Validate alerts using packet captures and map detections to MITRE ATT&CK techniques.  
4. Produce a short remediation plan and evidence package for stakeholders.



## Environment & Topology


[Router/Host VM] --- [Snort Sensor (Ubuntu VM)] --- [Lab Network: Target VMs (Windows/Linux)]

- All VMs run in an isolated host-only network.  
- Snort sensor uses `eth0` in promiscuous mode to monitor traffic.  
- Packet captures performed with `tcpdump` and validated in Wireshark.

---

## Tools Used
- Snort (IDS)  
- Suricata comparison notes (optional)  
- Wireshark / tcpdump  
- Kali Linux (for safe simulation/scripts in lab)  
- Ubuntu Server (Snort sensor)  
- Python (for simple alert parsing scripts)

---

## Setup & Configuration (high level)
1. Installed Snort on Ubuntu:
   ```bash
   sudo apt update && sudo apt install snort -y


Configured snort.conf with HOME_NET and external network variables.

Enabled unified2 output for alert logging and used Barnyard2/fast.log parsing for analysis (optional).

Created a dedicated rules file local.rules for custom detections and tuned thresholds to minimize false positives.

Captured traffic with tcpdump -i eth0 -w capture.pcap for offline validation.

Sample Snort Rules (safe, non-actionable examples)

Place these in local.rules. These are detection templates for learning and auditing only.

# Detect simple ICMP flood (educational threshold)
alert icmp any any -> $HOME_NET any (msg:"LAB - ICMP possible flood"; threshold:type both, track by_src, count 20, seconds 10; sid:1000001; rev:1;)

# Detect suspicious HTTP User-Agent (example)
alert tcp any any -> $HOME_NET 80 (msg:"LAB - Suspicious HTTP User-Agent"; content:"BadScanner"; http_header; sid:1000002; rev:1;)

# Detect FTP login attempts (example)
alert tcp any any -> $HOME_NET 21 (msg:"LAB - FTP login attempt"; flow:to_server,established; content:"USER "; sid:1000003; rev:1;)

Detection Scenarios & Test Steps

Reconnaissance (Nmap SYN scan)

Run nmap -sS -p- <target> from attacker VM.

Snort rule triggered for SYN scan (custom detection based on multiple SYN packets).

ICMP Storm Simulation (benign flood)

Use hping3 -1 --flood <target> in lab for controlled testing (only on lab VMs).

Snort alerts aggregated and threshold tuned to reduce noise.

HTTP Suspicious Header Detection

Use curl -A "BadScanner" http://<target> to trigger HTTP User-Agent based rule.

Each scenario includes packet capture for evidence and a short alert timeline.

Alert Analysis & Evidence

For each alert, the following artifacts were collected:

capture.pcap — packet-level evidence (openable in Wireshark).

alerts.log — Snort unified2 / fast.log entries.

timeline.txt — sequence of events mapped to timestamps.

Example analysis snippet (from alerts.log):

[**] [1:1000001:1] LAB - ICMP possible flood [**]
[Priority: 2] {ICMP} 192.168.56.101 -> 192.168.56.102


Mapped each detection to MITRE ATT&CK technique where applicable (e.g., T1046 - Network Service Discovery).

Mitigations & Recommendations

Short, actionable remediation steps provided to stakeholders:

Network Segmentation: Limit lateral movement by isolating critical services.

Egress Filtering: Block unnecessary outbound protocols and restrict to known IPs.

Rate-Limiting / ACLs: Apply rate limits for ICMP and SYN connections at firewall level.

Host Hardening: Remove unused services (Telnet/FTP), enforce secure alternatives (SSH), and patch OS/software.

Alert Tuning: Continue iterative tuning of Snort rules and create whitelist exceptions for known benign scanners.

These recommendations are tied to business risk (e.g., potential downtime, data confidentiality loss) and include owners & timelines for remediation.

##Ethics & Use

This lab is for educational use in isolated environments only. Do not use any of the techniques against systems you do not own or have permission to test.

Contact

GitHub: https://github.com/Nazakat-12

LinkedIn: https://www.linkedin.com/in/nazakat-ali-a808982a2/
