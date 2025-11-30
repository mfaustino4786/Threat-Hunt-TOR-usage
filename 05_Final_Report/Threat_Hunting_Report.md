# 🚨 Final Threat Hunting Report – TOR Usage

## 👤 Analyst Information
- **Name:**  Matthew Faustino-Page  
- **Email:**  mfaustino4786@gmail.com
- **Date Completed:**  11/27/2025

---

# 📌 Executive Summary
A threat-hunting investigation was conducted to determine whether TOR Browser was used on corporate systems to bypass security controls and access restricted websites. Network telemetry revealed unusual encrypted outbound traffic, including connections to known TOR guard/entry nodes. Endpoint telemetry confirmed the installation and execution of TOR Browser on the device **threathuntmatt**.

The investigation captured file artifacts, process executions, and network connections indicative of TOR usage. The activity aligned with multiple MITRE ATT&CK techniques, including Proxy Use (T1090) and Ingress Tool Transfer (T1105). Detection logic was effective across process, file, and network layers, with minor gaps in identifying TOR nodes dynamically.

---

# 📘 Scenario Description
Management suspected employees were using anonymizing tools to circumvent corporate policies. Firewall/proxy logs showed encrypted traffic to unfamiliar IPs, with patterns resembling TOR guard node communications. Anonymous internal reports also indicated attempts to access blocked websites using TOR.

To validate suspicions, a controlled adversary simulation was conducted. TOR Browser was downloaded, installed, executed, and used to access a `.onion` site. This activity produced endpoint and network telemetry used to evaluate detection coverage and identify gaps.

---

# 🔍 Activity Summary
The simulated adversary performed the following actions:

1. Downloaded TOR Browser from `torproject.org`.
2. Executed the TOR installer.
3. Launched `tor.exe` and TOR-bundled `firefox.exe`.
4. Allowed TOR to establish encrypted circuits to guard/entry nodes.
5. Accessed a `.onion` webpage for testing.
6. Closed the browser and deleted the installer to mimic evasive behavior.

These steps created identifiable Indicators of Compromise (IoCs) within Microsoft Defender for Endpoint (MDE) and network logs.

---

# 🧪 Detections & IoCs

## **IoCs Identified**

### **File Artifacts**
- `tor.exe`
- `firefox.exe` (TOR version)
- `TorBrowser\Data\Tor\torrc`
- `TorBrowser\Data\Tor\state`

### **Process Indicators**
- Execution of:
  - `tor.exe`
  - `firefox.exe`

### **Network Indicators**
- TOR-related ports:
  - TCP **9001**
  - TCP **443**
- Connections to known TOR guard/entry node IPs
- `RemoteUrl` values appearing blank

---

## **Queries Used to Detect IoCs**

### TOR Execution Detection
```kql
DeviceProcessEvents
| where FileName in ("tor.exe") 
    or FolderPath contains @"\Tor Browser\"
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, FolderPath
| order by Timestamp desc
