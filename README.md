# Sudden Network Slowdowns

<p align="center">
<img width="886" height="591" alt="Image" src="https://github.com/user-attachments/assets/aa3331ab-eb48-435f-8e41-008809627dc5" />
</p>

## 1. Preparation

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
- **Threat Detection Platform:** Microsoft Defender XDR Advanced Hunting with Microsoft Defender for Endpoint (MDE) telemetry
  

----

## 2. Detection & Analysis

### **Connection Failure Review**

Identified a host **cyberclaw-vm** generating an anomalous volume of failed connection requests to itself and other systems on the same subnet.

Wrote a KQL query targeting **DeviceNetworkEvents** to filter for **ConnectionFailed** actions originating from the suspect host.
<br><br>
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
<br><br>
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
<br><br>
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

## 3. Response

This activity was not anticipated or authorized by administrators. The device was therefore immediately isolated, and a malware scan was initiated.
<br><br>
<img alt="Image" src="https://github.com/user-attachments/assets/fec87d32-350f-4395-a52e-58dfd8e1f151" />
<br><br>
Findings: The malware scan returned no findings. However, as a precautionary measure, the affected device was isolated and a support ticket was raised to reimage and rebuild the system. The device remains in an isolated state.

---

## 4. Documentation
Findings:

- PowerShell script `portscan.ps1` executed by user `br00klyn`
- Internal port scanning activity detected
- Excessive failed internal connection attempts from **cyberclaw-vm**
- Consistent with port scanning/reconnaissance
  
---

## 5. Improvement

- Enable PowerShell script logging
- Block port scan tools via App Control
- Alert on sequential connection failures
- Detect port scans by tracking failed connection patterns
- Block outbound traffic from unauthorized hosts

---
## 🧾Summary                   
An investigation into `cyberclaw-vm` identified an abnormal volume of failed internal connection attempts to itself and neighboring hosts. The pattern of activity was consistent with internal port scanning behavior and systematic probing of multiple systems. A PowerShell script `(portscan.ps1)` was executed by user **br00klyn** during the same timeframe as the suspicious activity. No malware was detected, but the host was isolated and scheduled for rebuild as a precaution.

---
## References
- [NIST SP 800-61r3](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r3.pdf)
