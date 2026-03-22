#### Alert: MYDFIR-ALRT-0000

#### Alert Name
*Unauthorized Remote Tool Installation*

####  Affected Device
`app-east01.internal.local`

#### User Account
`svc-confluence`

###  File Detected
`AnyDesk.exe`

#### Command Line Execution
```bash
AnyDesk.exe --install --silent --password P@ssword1
```

---

*Question: How would you investigate whether this was deployed by an attacker for remote access?*
---

### Investigation: Unauthorized Remote Tool Installation

#### Objective
Determine whether the installation of **AnyDesk** was a legitimate administrative activity or a malicious deployment for unauthorized remote access.

#### Steps I would take:

#### 1. Validate Change Legitimacy
- Check IT change management / ticketing systems.
- Confirm with system owners or the DevOps team.
- Investigate if `svc-confluence` is authorized to install software

*Key Question to answer:*  
Was there an approved reason for installing remote access software on this host?

#### 2. Analyze User Account (`svc-confluence`)
- Identify account type (service account vs interactive user)
- Review:
  - Recent logins (interactive vs service usage)
  - Source IP addresses
  - Authentication anomalies (impossible travel, unusual times)

  *Concerns/ Potential Red Flags*
  - Service account used for interactive login
  - Logins from unknown or external IPs

#### 3. Process Execution & Timeline Analysis
- Review EDR/SIEM telemetry:
  - Parent process of `AnyDesk.exe`
  - Execution timestamp
  - Correlate with other processes
  
*Objective/Key Question:*
- Was it launched via?
  - `powershell.exe`
  - `cmd.exe`
  - `winrm` / remote execution tools?
    
 *Potential Red Flags:*
- Spawned by scripting engines
- Executed shortly after login from an unusual source

#### 4. Network Activity Analysis
- Check outbound connections from the host:
  - AnyDesk-related domains/IPs
  - Unknown external IPs
- Look for:
  - Persistent connections: A long-lasting, continuous network session between the host and a remote device
  - Beaconing behavior: A network communication pattern where a device repeatedly reaches out to the same external host at regular or semi-regular intervals.

*Potential Red Flags:*
- Connections to rare or geo-anomalous locations
- Traffic outside normal business hours

#### 5. Persistence Mechanisms
- Check if AnyDesk was configured for persistence:
  - Registry Run keys
  - Scheduled tasks
  - Services

*Potential Red Flags:*
- Auto-start enabled without business justification
- Hidden or renamed services

#### 6. Credential Exposure Risk
- The command includes:
  ```
  --password P@ssword1
  ```
- Investigate:
  - If this password is reused elsewhere
  - If credentials were logged or exposed in scripts

*Potential Red Flag*
- Hardcoded credentials may allow an attacker re-entry

#### 7. Lateral Movement Indicators
- Check if the host:
  - Initiated connections to other internal systems
  - Used SMB, RDP, or WinRM post-installation

*Potential Red Flags:*
- New connections to critical infrastructure
- Access attempts using `svc-confluence`

#### 8. Baseline Comparison
- Has AnyDesk ever been used in the environment before?
- Is this normal for this server role?

*Potential Red Flags:*
- First-time appearance of remote tool on device/host

#### 9. Threat Intelligence Correlation
- Check if:
    - AnyDesk usage aligns with known attacker TTPs
    - Associated IPs/domains are malicious

Possible follow-up actions depending on the findings of the investigation

A) *Legitimate*
- Approved change request exists
- Activity matches admin behavior
- Known IT tooling pattern
Actions: Document what was investigated and the outcomes, and communicate to teammates

B) *Suspicious / Malicious*
- No approval or documentation
- Service account misuse
- External connections + persistence
- Evidence of lateral movement

Actions: 
#### Immediate Containment (if suspicious)
- Isolate the host from the network
- Disable or reset `svc-confluence`
- Remove AnyDesk
- Block remote access tools via EDR
- Initiate full incident response. Escalate for further investigation
- Follow up through the entire investigation, observing the NIST 800-61 guidelines


#### 10. Aftermath
- Lessons Learned. Document what was done. Fill in the gaps, if any, for a better response in the future.

#### MITRE ATT&CK Mapping
- T1219 – Remote Access Software
- T1059 – Command and Scripting Interpreter
- T1105 – Ingress Tool Transfer
