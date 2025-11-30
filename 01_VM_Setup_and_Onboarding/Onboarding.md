# Microsoft Defender for Endpoint – Onboarding


## 📝 Onboarding Process
1. Download onboarding package from Microsoft 365 Defender Portal.
2. Extract or run the onboarding script based on OS type.
3. Confirm successful onboarding:

## ✔ Verification Steps

### KQL Query:

DeviceInfo
| where DeviceName == "threathuntmatt"
| project DeviceName, OnboardingStatus, OSPlatform

![Confirm VM Onboard](../screenshots/confirmvmonboard.png)

