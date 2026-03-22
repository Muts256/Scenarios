####  Alert: MYDFIR-ALRT-0002

####  Alert Name
**Internal Port Scan Detected**

####  Date / Time
`2025-08-20 06:18:35 UTC`

####  Affected Device
`Vuln-srv.internal.local`

####  User Account
`administrator`

#### File Detected
`netscan.exe`

#### Network Target
`192.168.1.0/24`

---

Question: How would you investigate to determine if this activity is adversary related or legitimate usage?
---
####  Investigation: Internal Port Scan (Legitimate vs Malicious)
#### Summary

The alert “Internal Port Scan Detected” was triggered after netscan.exe executed on Vuln-srv.internal.local. The process was observed scanning the internal network range of 192.168.1.0/24.


####  Objective
Determine whether the execution of `netscan.exe` targeting `192.168.1.0/24` by the `administrator` account is an authorised activity or adversary reconnaissance.

---

#### 1.  Validate Business Justification
- Check:
  - Change management / ticketing systems
  - Vulnerability scanning schedules
  - Security team activities

*Legitimate Indicators:*
- Approved scan window
- Known tool usage by the security team

*Potential Red Flags:*
- No record of planned scanning
- Activity outside maintenance window

#### 2. Account Behavior Analysis (`administrator`)

*Possible Query*
```
DeviceLogonEvents
| where AccountName == "administrator"
| where DeviceName == "Vuln-srv.internal.local"
| project Timestamp, LogonType, RemoteIP, InitiatingProcessFileName
| order by Timestamp desc
```
*What to Look For:*

  - Logon type (interactive vs remote)
  - Source IP address

*Potential Red Flags:*

  - Remote logon from an unknown host
  - Use of the admin account outside normal patterns
  - Log on at unusual hours

#### 3. Process Execution Context

*Possible Query*
```
DeviceProcessEvents
| where FileName =~ "netscan.exe"
| where DeviceName == "Vuln-srv.internal.local"
| project Timestamp, ProcessCommandLine, InitiatingProcessFileName, AccountName
```
*What to look for*
  - Parent process
  - Command-line arguments (scan intensity, ports)

*Potential Red Flags:*

  - Spawned by PowerShell.exe or scripts
  - Obfuscated or unusual command-line flags

#### 4. Network Scan Behavior Analysis

*Possible Query*
```
DeviceNetworkEvents
| where InitiatingProcessFileName == "netscan.exe"
| where DeviceName == "Vuln-srv.internal.local"
| summarize ConnectionCount = count() by RemoteIP, RemotePort
| order by ConnectionCount desc

```
*What to look for*
  - High volume of connections across many ports/hosts
  - Scan pattern (horizontal vs vertical) - Horizontal Pattern: A scan that is run to test one port across many hosts, e.g., port 22 across 10.0.0.2 - 10.0.0.15. This normally indicates a search for a particular vulnerability. A vertical scan is run on a single host, e.g., one host 10.0.0.5 ports 22, 80, 3389. This indicates trying to discover services that are running. A common tactic is to combine both scans

*Potential Red Flags:*

  - Rapid, high-frequency connections (automated scan)
  - Targeting critical infrastructure (DCs, servers)


#### 5. Timeline Correlation
*Possible Query*
```
union DeviceProcessEvents, DeviceNetworkEvents, DeviceLogonEvents
| where DeviceName == "Vuln-srv.internal.local"
| where Timestamp between (datetime(2025-08-20 05:30:00) .. datetime(2025-08-20 07:00:00))
| order by Timestamp asc
```
*What to look for:*

Identify:
  - Login → who initiated activity
  - Execution → when scan started
  - Follow-up → lateral movement or exploitation

#### 6. Lateral Movement Indicators
*Possible Query*
```
DeviceProcessEvents
| where DeviceName == "Vuln-srv.internal.local"
| where FileName in~ ("psexec.exe", "wmic.exe", "winrm.cmd", "mstsc.exe")
```
*What to look for*
- Process that may have been started after scanning

*Potential Red Flags*
- Remote execution tools used after scan
- Attempts to access discovered hosts

#### 7. File Reputation & Origin (netscan.exe)
*Possible Query*
```
DeviceFileEvents
| where FileName == "netscan.exe"
| project Timestamp, FolderPath, SHA256, InitiatingProcessFileName
```
*What to look for*
  - Verify hash reputation (trusted tool vs unknown binary)
  - Check file origin:
    - Downloaded?
    - Copied from another host?

*Potential Red Flags*
- Unknown or unsigned binary
- Recently dropped before execution


#### 8. Baseline Comparison
Has this host performed scans before?
Is netscan.exe commonly used in the environment?

*Potential Red Flags:*

First-time occurrence
Deviates from normal admin behavior

#### Immediate Response (if malicious)
- Isolate Vuln-srv.internal.local
- Disable or reset the administrator account
- Block scanning tool via EDR
- Hunt for lateral movement across the subnet
- Initiate incident response procedures

#### MITRE ATT&CK Mapping
- **T1046** – Network Service Scanning
- **T1087** – Account Discovery (potential follow-on)
- **T1021** – Remote Services (potential lateral movement)


#### Lessons Learned
This scenario highlights that effective detection relies on:
- Understanding **dual-use tools**
- Correlating **identity, endpoint, and network data**
- Validating activity against **business context**
