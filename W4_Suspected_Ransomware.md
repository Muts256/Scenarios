### Alerts during late shift

03:14. Three alerts land in your queue within 90 seconds, all from the same file server:

Alert 1 - vssadmin.exe executed: delete shadows /all /quiet

Alert 2 - Mass file modification: 4,000+ files renamed in 2 minutes, all gaining the extension .lkd

Alert 3 - CPU pinned at 98% on the same host

You've never seen the .lkd extension before. A quick search brings up nothing solid.
Before you do anything, you remember the email IT sent yesterday. They're rolling out a new archiving tool across the file servers this week, "expect elevated disk activity during off-peak hours." The rollout schedule attached shows this server listed for tonight.
Your isolation button disconnects the server from the network instantly. Finance opens in 5 hours, and that server holds their shared drives. Isolating it wrongly means a morning of downtime, an angry client, and an incident report with your name on it.

---

#### Explain how you would investigate and why?

Isolate the server immediately, then investigate.

The rapid change of the file extension is very suspicious. This is a high-confidence ransomware-style attack pattern, despite the legitimate archiving rollout.

The key is not to let the unfamiliar .lkd extension or yesterday's change notice outweigh the actual telemetry.

#### Why I Would Isolate

The decision to isolate the server is based on **three correlated indicators occurring within 90 seconds**:

1. **`vssadmin.exe delete shadows /all /quiet`**

   * This is a major red flag.
   * Deleting Volume Shadow Copies is commonly associated with ransomware because it removes an important recovery mechanism.

2. **4,000+ files renamed within two minutes**

   * This is highly abnormal for a normal archiving operation.
   * The fact that thousands of files are being renamed and assigned a previously unknown extension strongly suggests mass encryption or another malicious file-transformation process.

3. **CPU utilization at 98%**

   * Sustained CPU usage at this level is consistent with an intensive encryption, compression, or file-transformation process.

#### Escalate

With strong evidence of potentially destructive malicious activity on a critical file server. At this point, notify the response team and SOC lead.

Since Finance opens in five hours, management needs to know that there is a potential impact to critical business services before 08:00.

#### Contextual Consideration

The scheduled archiving rollout is relevant context and should be investigated. However, it should **not override the security telemetry**.

The combination of:

> **Shadow-copy deletion + mass file modification + unknown file extension + extremely high CPU utilization**

provides sufficient evidence to treat the activity as a potential ransomware incident and **contain the host immediately**.

Given that the server holds Finance share folders, the appropriate approach is to **isolate first, then investigate**, while simultaneously verifying whether the observed activity is associated with the authorised archiving deployment. Contact the change management team and the administrators to confirm that this behaviour is expected.

---

#### MITRE ATT&CK Mapping

| Evidence | Technique | ATT&CK ID | Rationale |
|---|---|---|---|
| `vssadmin.exe delete shadows /all /quiet` | Inhibit System Recovery | [T1490](https://attack.mitre.org/techniques/T1490/) | Deletes Volume Shadow Copies to prevent recovery. |
| 4,000+ files renamed within two minutes | Data Encrypted for Impact | [T1486](https://attack.mitre.org/techniques/T1486/) | Mass file modification is consistent with ransomware encryption. |
| Files receiving an unknown `.lkd` extension | Data Encrypted for Impact | [T1486](https://attack.mitre.org/techniques/T1486/) | A new extension across thousands of files may indicate encrypted or transformed data. |
| CPU utilization reaching 98% | Supporting evidence for T1486 | [T1486](https://attack.mitre.org/techniques/T1486/) | High CPU utilization may indicate an active encryption/transformation process, but CPU usage alone is not sufficient to establish the technique. |

---

#### Attack Scoping

After isolating the affected file server, the next priority is to determine whether the incident is isolated to that host or part of a wider compromise.

#### 1. Identify the Initial Affected Host

Establish:

* Hostname and IP address
* Logged-in users
* Processes running at the time of the incident
* Parent/child process relationships
* Executable paths and hashes
* Command-line arguments
* First observed malicious activity
* Timeline of file modifications

The objective is to establish **when the activity started, what initiated it, and which account or process was responsible**.

#### 2. Determine the Scope of File Impact

Examine:

* Number of affected files
* File extensions before and after modification
* Directories affected
* Network shares affected
* Whether files outside the expected archive location were modified
* Whether files are encrypted, renamed, deleted, or corrupted

Compare affected directories against known legitimate activity from the archiving deployment.

#### 3. Search for the Same Indicators Across the Environment

Use the SIEM/EDR to search for:

* The unknown `.lkd` extension
* `vssadmin.exe`
* `delete shadows`
* The suspicious executable/process
* File hashes
* Command-line arguments
* Associated IP addresses
* Domains
* User accounts
* Parent processes
* Similar file-modification activity

For example, search for other hosts executing:

```text
vssadmin.exe delete shadows
```

or exhibiting large numbers of file modifications within a short period.

#### 4. Investigate Authentication Activity

Determine whether the compromised host or account accessed other systems.

Review relevant authentication telemetry, including:

* Windows Event ID `4624` — successful logon
* Windows Event ID `4625` — failed logon
* Windows Event ID `4672` — special privileges assigned
* Kerberos Event ID `4768` — TGT requested
* Kerberos Event ID `4769` — service ticket requested

Look for unusual authentication patterns, particularly:

* The affected account authenticating to multiple systems
* Administrative logons
* Authentication from unusual hosts
* Authentication outside normal working patterns
* Sudden access to multiple file servers

#### 5. Investigate Lateral Movement

Determine whether the attacker moved from the affected server to other systems.

Look for evidence involving:

* SMB
* RDP
* WinRM
* PsExec
* Remote PowerShell
* Administrative shares
* Remote service creation

Correlate network connections with authentication and process telemetry.

#### 6. Search for Additional Compromised Hosts

Use the identified indicators to determine whether other endpoints or servers show similar behaviour.

Particular attention should be given to:

* Other file servers
* Domain controllers
* Backup servers
* Management servers
* Systems accessed by the compromised account

#### 7. Establish the Blast Radius

The final objective is to determine:

**Affected host → Affected accounts → Affected files → Affected shares → Other compromised hosts → Potentially compromised credentials → Potential business impact**

Only after establishing the scope should the incident be considered sufficiently understood for full eradication and recovery planning.

#### MITRE ATT&CK Consideration

The scoping activity itself should not automatically be mapped to an attacker technique. However, evidence discovered during the investigation may identify additional ATT&CK techniques, such as:

* **T1021 – Remote Services**
* **T1135 – Network Share Discovery**
* **T1078 – Valid Accounts**
* **T1059 – Command and Scripting Interpreter**

These should only be mapped when there is **actual evidence supporting them**, rather than inferred simply because the incident occurred on a file server.
