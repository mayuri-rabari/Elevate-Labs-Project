# Elevate-Labs-Project
# TASK-1

 Cyber Security Project Report Title: Port Scanning and Service Enumeration using Nmap

Internship: Elevate Labs - Cyber Security Internship

Date: 24th June 2025

Tool Used: Nmap v7.95 on Kali Linux

Target: 192.168.38.66 (Local IP)

 Objective To discover open ports, detect running services, and assess potential vulnerabilities on a local network host using different Nmap scanning techniques.

Tools & Commands Used Command Purpose nmap -sV 10.217.18.143 Version detection scan nmap -sS 192.168.38.66 SYN stealth scan (quick and less detectable) nmap -p- 192.168.38.66 Full port scan (1-65535 TCP ports)

 Results Summary

Service Version Detection (nmap -sV) Open Ports Detected:
135/tcp – Microsoft Windows RPC

139/tcp – NetBIOS Session Service

445/tcp – Microsoft-DS (SMB file sharing)

8000/tcp – Splunkd HTTP service

8009/tcp – Splunkd (remote login disabled)

OS Detected: Microsoft Windows

CPE Identifier: cpe:/o:microsoft:windows

SYN Stealth Scan (nmap -sS) Confirmed the same open ports:
135, 139, 445, 8000, 8009

Full Port Scan (nmap -p-) Total Open Ports Found:
135, 139, 445, 8000, 8009, 49665, 49666, 49667, 49673, 49674, 62391

Observation: Additional high-numbered ephemeral ports are open. These are usually used for dynamic client-server communication and can indicate active services or malware using open ports.

 Security Risk Analysis Port Service Potential Risk 135, 139, 445 RPC/NetBIOS/SMB High — Often targeted for Windows exploits (e.g., EternalBlue) 8000, 8009 Splunk HTTP Medium — Web-based services could be exposed without authentication 49665–49674, 62391 Unknown Medium — Dynamic ports, possibly used by internal services or malware

 Recommendations Disable unused services and ports to reduce the attack surface.

Implement firewalls to filter inbound traffic.

Patch vulnerabilities associated with RPC and SMB services (if exposed externally).

Run vulnerability scan tools like OpenVAS or Nessus on the open ports.

Use authentication and encryption for web-based services (Splunk).

Based on your Nmap scan results of the host 192.168.56.1, here’s a comprehensive evaluation of the security risks associated with the discovered open ports and services:

 Identified Open Ports & Security Risk Evaluation Port Service Description Risk Level Security Risks 135/tcp msrpc (Microsoft RPC) Handles DCOM and remote management  High - Used in remote attacks (e.g., MS03-026)

Vulnerable to DCOM buffer overflows
Often exploited in lateral movement
139/tcp netbios-ssn NetBIOS session for file/printer sharing  High - Used in SMB attacks

Can allow information disclosure or unauthenticated file access
445/tcp microsoft-ds (SMB over TCP) File sharing and Active Directory  High - Critical vulnerabilities (EternalBlue, WannaCry)

Enables pass-the-hash, SMB relay attacks
8000/tcp Splunkd httpd Web interface for Splunk (free license)  Medium - May expose internal data/logs if unauthenticated

May be vulnerable to web exploits (XSS, injection)
8009/tcp Splunkd (unknown) Possibly AJP or alternate Splunk port  Medium - Could expose unauthenticated or misconfigured services

If AJP (Apache JServ Protocol), may be vulnerable to Ghostcat
49665-49674/tcp 62391/tcp Unknown (Ephemeral ports) High ports used by Windows for dynamic service binding  Low-Medium - Could indicate active services

If bound by malware or backdoor, may permit remote access
Often used for RPC, WMI, or malware C2 traffic
 Summary of Potential Threats Remote Code Execution (RCE):

Ports 135, 139, and 445 are common vectors for RCE exploits.

Attackers can exploit these to gain remote shell or control.

Privilege Escalation & Lateral Movement:

Open SMB ports allow attackers to extract credentials or move laterally within a network.

Unsecured Web Services (Port 8000/8009):

If Splunk or HTTP services are not secured with auth or encryption, data leaks or command injection may occur.

Misconfigured Ephemeral Ports:

High-numbered ports could expose internal services not meant for public use.

Malware often hides in these dynamic ports.

Denial of Service (DoS):

Unpatched RPC/SMB services could be DoS’d by sending malformed packets.

 Recommended Mitigations Action Description  Disable SMB v1 Prevent exploits like EternalBlue by disabling SMBv1  Use Firewall Rules Block unused ports (especially 135–139, 445) from external access  Service Audits Audit Splunk/web interfaces for authentication & vulnerabilities  Patch Management Ensure Windows and Splunk are up-to-date with latest security patches  Malware Scan Scan host for malware that may be using high ephemeral ports  Network Segmentation Isolate vulnerable services in DMZ or behind VPNs/firewalls

Here is the attachment of this task 1:
![Screenshot 2025-06-24 141029](https://github.com/user-attachments/assets/30bfa6d8-7c9e-40d3-8918-60ab6e99dc27)
![Screenshot 2025-06-24 150938](https://github.com/user-attachments/assets/9068713b-c88a-464f-9b94-c114347bbc3c)


#  Task 2: Phishing Email Analysis Report

##  Sample Email Analyzed

**Subject:** Microsoft account password change  
**Sender:** support@msupdate.net  
**Time:** 4:09 PM  
**Recipient:** ethan@hooksecurity.co

###  Screenshot
Phising Email Screenshot
![Screenshot 2025-06-24 111812](https://github.com/user-attachments/assets/aeb943e1-6ff0-4d02-9c46-32a2f138ef3b)

## 🔍 Phishing Indicators Found

| Indicator                        | Description                                                                 |
|----------------------------------|-----------------------------------------------------------------------------|
| 1. **Suspicious sender domain** | The sender is `support@msupdate.net`, which is not an official Microsoft domain. Microsoft typically uses `@accountprotection.microsoft.com` or similar. |
| 2. **Sense of urgency**         | "If this wasn’t you, your account has been compromised" pressures the user to take action immediately. |
| 3. **Clickable links**          | The links such as “Reset your password” and “opt out” could lead to phishing pages (can't verify real destination without headers or hover preview). |
| 4. **Generic greeting**         | No personalized name used – a red flag for mass phishing emails.           |
| 5. **Spoofed branding**         | Mimics Microsoft’s layout and branding to trick the recipient.              |



#  Tools Used

- Manual analysis of email content
- Email header domain inspection
- URL hover checks (if tested in real client)
- (If available) header analysis tool like:  
  - [MXToolbox Header Analyzer](https://mxtoolbox.com/EmailHeaders.aspx)



# What I Learned

- How phishing emails spoof trusted brands
- Importance of inspecting the sender’s domain
- Common phishing techniques: urgency, spoofed domains, and generic greetings
- How attackers leverage social engineering


#  – Task 3-4 screenshots
![Screenshot 2025-06-29 201006](https://github.com/user-attachments/assets/61a47851-65c3-47a2-adaa-6f8efa485c50)
![Screenshot 2025-06-29 193827](https://github.com/user-attachments/assets/d514318c-fc85-4bf3-829c-a2de491bdf94)
![Screenshot 2025-06-29 193850](https://github.com/user-attachments/assets/a3174c3a-95f2-48fa-a427-26b8abb2d680)
![Screenshot 2025-06-29 194236](https://github.com/user-attachments/assets/b8b8a8bf-58b8-4eca-b893-6f29e20b71c9)
![Screenshot 2025-06-29 195007](https://github.com/user-attachments/assets/a17b6ebc-99d7-40f5-9d99-2a56e64c3eb6)
![Screenshot 2025-06-29 195604](https://github.com/user-attachments/assets/c106f0f4-5ca1-4f16-a088-681bde885bf8)



#  – Task 3
# Vulnerability Assessment Report Using OpenVAS

---

## Objective

The objective of this assessment is to identify and analyze security vulnerabilities in a local system using **OpenVAS** (Greenbone Community Edition), classify them based on severity (CVSS), and apply basic remediation steps.

---
## screenshots are provided in readme.md

## Tool Description

**OpenVAS** (Open Vulnerability Assessment System) is a free and open-source vulnerability scanner that performs full system scans using the Greenbone Security Feed. It detects misconfigurations, outdated packages, open ports, CVEs, and more.

### 1. System Update
```bash
sudo apt update && sudo apt upgrade -y

### 2. Install OpenVAS
sudo apt install openvas -y

3. Setup OpenVAS & Sync Feed
sudo gvm-setup

4. Start OpenVAS Services
sudo gvm-start


Target Configuration
Host IP: 127.0.0.1 (localhost)

Port Range: Default (1–65535)

Scan Config: Full and Fast

Scan Task Details
Name: Localhost Scan

Target: Localhost

Scanner: OpenVAS default

Scan Type: Full and Fast

### Execution Process
Logged into OpenVAS dashboard at https://127.0.0.1:9392

Created scan target for localhost

Created and launched scan task

Waited ~45 minutes for scan to complete

Analyzed the vulnerability report


# 🔥 Task 4: Setup and Use a Firewall on Windows 11
### 🛡️ Cybersecurity Internship Task Report

---

## 🎯 Objective

To configure and test basic Windows Firewall rules to allow or block traffic on specific ports and understand how firewalls filter network traffic.

---

## 🧰 Tools Used

- **Operating System**: Windows 11
- **Firewall Tool**: Windows Defender Firewall with Advanced Security
- **Command Line Utility**: Windows PowerShell / CMD
- **Testing Tool**: Telnet (enabled manually via optional features)

---

## 🧪 Task Steps on Windows 11

### ✅ Step 1: Open Windows Firewall Configuration
- Press `Win + R` → type `wf.msc` → press `Enter`
- This opens **Windows Defender Firewall with Advanced Security**

---

### ✅ Step 2: View Existing Rules
- Navigated to:
  - **Inbound Rules**: Rules controlling traffic entering the system
  - **Outbound Rules**: Rules controlling traffic leaving the system

---

### ✅ Step 3: Block Inbound Traffic on Port 23 (Telnet)
1. In the left panel, clicked on **Inbound Rules** → then **New Rule**
2. Selected **Port** → clicked **Next**
3. Selected **TCP** → specified port **23**
4. Selected **Block the connection**
5. Applied rule to all profiles: **Domain, Private, Public**
6. Named the rule: `Block Telnet Port 23`
7. Clicked **Finish**

---
Step 4:  Allow SSH (Port 22)
Created a new inbound rule:

Protocol: TCP, Port: 22

Action: Allow the connection


### ✅ Step 5: Test the Rule
- Enabled Telnet client:
  - Opened **Settings → Optional Features → Add a feature → Telnet Client → Install**
- Tested using CMD:
  ```bash
  telnet localhost 23


# Task 5 – Wireshark Packet Analysis

## Objective
Capture and analyze live network traffic to identify common protocols using Wireshark.

## Protocols Identified
1. **DNS** – Used for domain name resolution (e.g., google.com → IP)
2. **TCP** – Reliable transport layer protocol for HTTP, SSH, etc.
3. **ICMP** – to check ping (ICMP) traffic

## How Capture Was Performed
- Interface: Wi-Fi
- Visited: `https://example.com`
- Performed: `ping google.com`
- Duration: 1 minute

![Screenshot (218)](https://github.com/user-attachments/assets/ffb2880b-5d8a-4320-853d-c5fcd73032f5)
![Screenshot (219)](https://github.com/user-attachments/assets/660d09ad-e4e7-43f7-b190-cd42d5dae219)
![Screenshot (220)](https://github.com/user-attachments/assets/1271adbe-f3d1-4911-8830-6d3804c71db1)
