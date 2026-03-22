#### Alert: MYDFIR-ALRT-0001

A suspicious DLL was executed with regsvr32 under SYSTEM.

####  Alert Name
*Potential Privilege Escalation: regsvr32 DLL Execution (SYSTEM)*

#### Date / Time
`2025-08-15 04:25:81 UTC`

#### Affected Device
`conf-west02.internal.local`

#### User Context
`SYSTEM`

#### File Detected
`nbjlop.dll`

#### Command Line Execution
```bash
regsvr32 nbjlop.dll
```
---

*Question: What evidence would you look for to determine how SYSTEM-level execution was achieved?*
---

#### Investigation: SYSTEM-Level Execution Root Cause
Summary:

The Windows utility regsvr32 was used to execute or register a DLL under the SYSTEM account. This behavior is commonly associated with privilege escalation or execution of malicious code, as attackers may abuse trusted system binaries to evade detection.

#### Objective
Determine how the `regsvr32` execution of `nbjlop.dll` was performed under the **SYSTEM** account.

#### Steps to take 

#### 1. Parent Process Analysis
- Identify the parent of `regsvr32.exe` via EDR/Sysmon logs
- Trace the full process tree

*What to look for:*
- `services.exe` → Service-based execution
- `taskeng.exe` / `schtasks.exe` → Scheduled task abuse
- `wmiprvse.exe` → WMI execution
- `powershell.exe` / `cmd.exe` → Script-based execution

*Red Flags:*
- Unusual or unknown parent process
- Script interpreter spawning SYSTEM-level process

#### 2. Scheduled Task Abuse
- Check for newly created or modified tasks:
  - Review:
      - Run as: SYSTEM
      - Task creation time (correlate with alert)
    
Possible query to use
```
DeviceProcessEvents
| where DeviceName == "conf-west02.internal.local"
| where FileName in~ ("schtasks.exe", "taskeng.exe")
| project Timestamp, FileName, ProcessCommandLine, AccountName, InitiatingProcessFileName

```
*Potential Red Flags*
  - Tasks created shortly before execution
  - Tasks configured to run as SYSTEM
  - Task executing regsvr32

#### 3. Service Creation / Modification
- Check for:
  - New or modified services running as SYSTEM
  - Services pointing to suspicious binaries or scripts
 Possible Query to use
````
DeviceProcessEvents
| where FileName =~ "sc.exe"
| where ProcessCommandLine has_any ("create", "config")
| project Timestamp, ProcessCommandLine, AccountName, InitiatingProcessFileName

````
*Potential Red Flags:*
  - Service executing DLL via regsvr32
  - Random or non-standard service names


#### 4. Lateral Movement (WMI Execution)
 Reason: 
 - Windows Management Instrumentation (WMI) is one of the most common ways attackers execute commands remotely that end up running as SYSTEM.
 - Runs as SYSTEM by Design. WMI service (wmiprvse.exe) runs with high privileges
 - Stealth (LOLBIN Technique)

Possible Query
````
DeviceProcessEvents
| where FileName =~ "wmiprvse.exe"
| project Timestamp, ProcessCommandLine, InitiatingProcessFileName, AccountName

````
*Potential Red Flags*
  - Remote execution preceding SYSTEM activity
  - Execution from another host
  - 
Lateral Movement Indicators

Possible Query
````
DeviceNetworkEvents
| where DeviceName == "conf-west02.internal.local"
| where Timestamp between (datetime(2025-08-15 03:30:00) .. datetime(2025-08-15 04:30:00))
| project Timestamp, RemoteIP, RemotePort, InitiatingProcessFileName

````
*Potential Red Flags*
  - Connections from admin workstations or unknown hosts
  - SMB (445), WinRM (5985), RDP (3389)

#### 5. Privilege Escalation Events
Review logs for privilege escalation events:
  - Windows Event ID 4672 (Special privileges assigned)
  - Event ID 4688 (Process creation)

What to look for:
  - Account gaining elevated privileges before execution
  - Token impersonation or duplication patterns

Possible Query
````
SecurityEvent
| where EventID in (4672, 4688)
| where Computer == "conf-west02.internal.local"
| project TimeGenerated, EventID, Account, Process
| order by TimeGenerated desc

````

#### 6. DLL Investigation
Possible Query

````
DeviceFileEvents
| where FileName == "nbjlop.dll"
| project Timestamp, FolderPath, SHA256, InitiatingProcessFileName

````
Reason: 
  - Check the hash reputation using VirusTotal 
  - Verify digital signature

#### 7. Timeline Correlation
Possible Query
````
union DeviceProcessEvents, DeviceFileEvents, DeviceNetworkEvents
| where DeviceName == "conf-west02.internal.local"
| where Timestamp between (datetime(2025-08-15 03:30:00) .. datetime(2025-08-15 04:30:00))
| order by Timestamp asc

````
Reason:

Reconstruct:
  - Initial access
  - Privilege escalation
  - SYSTEM execution

#### MITRE ATT&CK Mapping
  - T1218.010 – Signed Binary Proxy Execution: regsvr32
  - T1068 – Exploitation for Privilege Escalation
  - T1055 – Process Injection (potential)

#### Immediate Actions (if malicious)
  - Isolate device via MDE
  - Run live response investigation
  - Remove persistence (tasks/services)
  - Reset credentials
  - Hunt for similar activity across the environment

Lessons Learned

This scenario reinforces that effective detection and response depend on:
- Understanding *how attackers use native tools*
- Tracing *execution paths, not just events*
- Leveraging *EDR + SIEM together for full visibility*

