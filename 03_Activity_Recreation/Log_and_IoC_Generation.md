# IoC & Log Generation Tracking

This file documents all observed IoCs and related logs.

## 📝 Expected IoCs
- `tor.exe` or `firefox.exe` child processes
- Network traffic on ports: 9001, 9030, 9150
- TOR installation directory file events
- DeviceProcessEvents entries for browser execution

---

## 📊 Observed IoCs
(Add actual values)

| IoC Type | Value | Source Table | Notes |
|---------|--------|--------------|-------|
| Process |        | DeviceProcessEvents | |
| File Path |      | DeviceFileEvents | |
| Network |        | DeviceNetworkEvents | |

---

## 🧪 Validation Queries

```kusto
DeviceProcessEvents
| where FileName has "tor"
| order by TimeGenerated desc
```

```kusto
DeviceNetworkEvents
| where RemotePort in (9001, 9030, 9150)
| order by TimeGenerated desc
```

---

## 🖼 Screenshots
Include screenshots of query results or logs.
