# Sudden-Network-Slowdowns

## Preparation

### Scenario

The server team has noticed a significant network performance degradation on some of their older devices attached to the network in the **10.0.0.0/16** network. After ruling out external DDoS attacks, the security team suspects something might be going on internally.

**Description:**

- **All** internal traffic is permitted by default.
- PowerShell and other applications are **unrestricted** in the environment.

**Task:**

- Identify any instances of large file movements or port scanning behavior against internal hosts.

**Goal:**

- Determine whether unauthorized data transfer or port scanning (network reconnaissance) is occurring within the local environment.

---

### Components, Tools, and Technologies Employed

- **Cloud Environment:** Microsoft Azure (VM-Windows target machine)
- **Threat Detection Platform:** Microsoft Defender for Endpoint (MDE)
  

----

## Detection & Analysis

### **Connection Failure Review**

Identified a host **cyberclaw-vm** generating an anomalous volume of failed connection requests to itself and other systems on the same subnet.

Wrote a KQL query targeting **DeviceNetworkEvents** to filter for **ConnectionFailed** actions originating from the suspect host.

```kql
DeviceNetworkEvents
| where DeviceName == "cyberclaw-vm"
| where ActionType == "ConnectionFailed"
| summarize FailedConnectionAttempts = count() by DeviceName, ActionType, LocalIP, RemoteIP
| order by FailedConnectionAttempts desc 
```

<img alt="Image" src="https://github.com/user-attachments/assets/4799fb99-862f-4740-9c9d-57e562b1f78a" />
<br><br>

Findings: The query returned multiple failed connection attempts from **cyberclaw-vm** to both its own IP address and neighboring hosts, indicating potential self-scanning or internal reconnaissance behavior consistent with malware or misconfiguration.

---

### **Network Forensics**

Analyzed failed connection requests from suspected host **10.3.0.50** by querying network logs and ordering results by timestamp to reveal connection patterns.

```kql
let SuspiciousIP = "10.3.0.50";
DeviceNetworkEvents
| where DeviceName == "cyberclaw-vm"
| where ActionType == "ConnectionFailed"
| where LocalIP == "10.3.0.50"
| order by Timestamp
```
<img alt="Image" src="https://github.com/user-attachments/assets/7548d689-0e9b-4434-9c2d-3345ea427cc3" />
<br><br>

Findings: The sequential order of the ports confirmed that several port scans were being conducted.

---

### **Anomalous behavior**

I reviewed the DeviceProcessEvents table to identify any suspicious activity occurring around the time the port scan began.

```kql
let VMName = "cyberclaw-vm";
let specificTime = datetime(2026-04-22T00:06:57.8028463Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 10m) .. (specificTime + 10m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, FileName, InitiatingProcessCommandLine, AccountName
```

<img alt="Image" src="https://github.com/user-attachments/assets/68c7cf18-4234-4ba8-89a8-a3439880c789" />
<br><br>

Findings: A PowerShell script named `portscan.ps1` was launched by the **br00klyn** account at `2026-04-22T00:06:57.8028463Z.`

#### `Timestamp captured: 2026-04-22T00:06:57.8028463Z`
---

### **MITRE ATT&CK Mapping: Tactics, Techniques, and Procedures (TTPs)**

- [T1059.001 – Command and Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001/)

- [T1046 - Network Service Discovery](https://attack.mitre.org/techniques/T1046/)

- [T1018 - Remote System Discovery](https://attack.mitre.org/techniques/T1018/)

- [T1078 – Valid Accounts](https://attack.mitre.org/techniques/T1078/)


---

## Response

This activity was not anticipated or authorized by administrators. The device was therefore immediately isolated, and a malware scan was initiated.

---

## Documentation
Findings:

- PowerShell script execution
- `7zip` installation
- Employee data compressed to `.zip`
- Archive moved to hidden folder

## 5. Improvement

- Block unauthorized tools (e.g., `7-Zip` via App Control)
- Set alerts for suspicious PowerShell execution, Zip file activity, silent installs
- Define clear isolation criteria: isolate if exfiltration is confirmed or in progress
- Develop baseline of normal archiving behavior by department/role
---
## 🧾Summary                   
The user `cyberclaw-vm` installed `7-Zip` via PowerShell, compressed employee data into a ZIP archive, and moved it to a `backup` folder in ProgramData. No data exfiltration was detected. The behavior is consistent with data staging, so findings were escalated to management and monitoring remains active.

---
## References
- [NIST SP 800-61r3](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf)
