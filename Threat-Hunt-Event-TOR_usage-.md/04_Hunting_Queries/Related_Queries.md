# KQL Queries Used for Hunting TOR Traffic

## 🔍 Process Activity

```kusto
DeviceProcessEvents
| where FileName contains "tor" or FileName contains "firefox"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, FolderPath
```

---

## 🌐 Network Activity

```kusto
DeviceNetworkEvents
| where RemotePort in (9001, 9030, 9150)
| project TimeGenerated, DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName
```

---

## 📁 File Activity

```kusto
DeviceFileEvents
| where FolderPath contains "Tor Browser"
| project TimeGenerated, FileName, FolderPath, DeviceName
```

---

Add any additional queries discovered during hunting.
