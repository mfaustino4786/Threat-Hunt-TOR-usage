# Verifying DeviceInfo Logs in MDE

After onboarding, the DeviceInfo table should contain events.

## ✔ Validation Checklist
- [ ] Device appears in Defender portal
- [ ] DeviceInfo table logs have populated
- [ ] Events show accurate OS and device metadata

## 🔍 Validation Query

KQL:
    DeviceInfo
    | where DeviceName contains "threathuntmatt"  

## 📌 Notes
Document timing, delays, or missing logs if applicable.
