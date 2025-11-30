# Threat Event Template – TOR Usage Scenario

> **Purpose:** Document simulated malicious TOR activity and map related IoCs and detection logic.

## 👤 Analyst Information
- Name:  Matthew Faustino-Page
- Email:  mfaustino4786@gmail.com
- Date:  11/22/2025

---

# 1. Scenario Summary
Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks.

---

# 2. Environment
- Device Name:  threathuntmatt
- OS:  Windows 11 Pro 25H2 Gen 2
- MDE Onboard Status:  Onboarded

---

# 3. Activity Steps (Adversary Emulation)
1. Download TOR Browser from the official site.  
2. Execute the TOR Browser installer.  
3. Launch `tor.exe` and TOR’s embedded `firefox.exe`.  
4. Allow TOR Browser to connect to TOR guard/entry nodes.  
5. Visit a known `.onion` site for testing.  
6. Close TOR Browser.  
7. Delete the installer.
---

# 4. Generated IoCs
List:
- File artifacts
  `tor.exe`  
  `firefox.exe` (TOR bundled binary)    

- Network connections  
   Outbound traffic on:
  - TCP **9001**
  - TCP **443**

---

# 5. Detection Logic

### Tables Referenced:
- `DeviceProcessEvents`  
- `DeviceFileEvents`  
- `DeviceNetworkEvents`  
- `DeviceImageLoadEvents`  
- `DeviceRegistryEvents`  
- `DeviceInfo`

### Queries Used:
### **A. Detect TOR Browser Execution**

DeviceProcessEvents
| where DeviceName == "threathuntmatt"
| where FileName contains "tor.exe" 
      or FolderPath contains @"\Tor Browser\"
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, FolderPath
| order by Timestamp desc

### **B. Detect TOR Installation**

DeviceFileEvents
| where DeviceName == "threathuntmatt"
| where FileName contains "tor"
      or FolderPath contains @"\Tor Browser\"
| project Timestamp, DeviceName, FileName, FolderPath, ActionType
| order by Timestamp desc

### **B. Detect TOR Network Traffic**

DeviceNetworkEvents
| where DeviceName == "threathuntmatt"
| where Protocol == "Tcp" and RemotePort in (443, 9001, 9030)
| where isempty(RemoteUrl) or RemoteUrl == ""
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteIP, RemotePort
| order by Timestamp desc



---

# 6. Findings Summary

The hunt confirmed active TOR usage on the device threathuntmatt.

MDE telemetry logged execution of tor.exe and TOR’s embedded firefox.exe.

File activity showed TOR Browser extraction and configuration file creation.

Network logs captured outbound connections to recognized TOR guard nodes on ports 9001 and 9030.

Encrypted sessions with no SNI matched typical TOR traffic patterns.

The combined IoCs aligned strongly with TOR usage, and detection logic successfully surfaced all major artifacts of the activity.

---

# 7. MITRE ATT&CK Mapping
| Technique                      | ID         | Description                               |
|-------------------------------|------------|-------------------------------------------|
| Proxy Use                     | T1090      | TOR anonymizes and tunnels traffic.       |
| Application Layer Protocol    | T1071      | Encrypted traffic over common ports.      |
| Ingress Tool Transfer         | T1105      | Downloading TOR Browser installer.        |
| User Execution – Malicious File | T1204.002 | User manually executed TOR Browser.       |


---

# 8. Recommendations

To prevent unauthorized TOR usage and strengthen network security, implement the following defensive and hardening strategies:

## 🔒 Endpoint Hardening
- **Block TOR executables** (`tor.exe`, `obfs4proxy.exe`, TOR Firefox builds) using:
  - Microsoft Defender Attack Surface Reduction (ASR)
  - Application Control / AppLocker policies
  - Smart App Control (Windows 11)
- **Restrict portable applications** from running in user directories such as:
  - `%USERPROFILE%\Downloads`
  - `%USERPROFILE%\Desktop`
  - `%TEMP%`
- **Enable Controlled Folder Access** to prevent unauthorized extraction of TOR Browser components.

## 🌐 Network Controls
- **Block known TOR guard, relay, and exit node IP ranges** at the firewall.  
  (TOR publishes updated lists; automate ingestion where possible.)
- **Disable outbound traffic on TOR-related ports**, such as:
  - TCP **9001**, **9030**, **9050**, **9150**
- **Monitor TLS traffic with no SNI**, whi

