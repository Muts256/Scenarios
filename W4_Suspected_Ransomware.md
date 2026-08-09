### Alerts during late shift

03:14. Three alerts land in your queue within 90 seconds, all from the same file server:

Alert 1 - vssadmin.exe executed: delete shadows /all /quiet

Alert 2 - Mass file modification: 4,000+ files renamed in 2 minutes, all gaining the extension .lkd

Alert 3 - CPU pinned at 98% on the same host

You've never seen the .lkd extension before. A quick search brings up nothing solid.
Before you do anything, you remember the email IT sent yesterday. They're rolling out a new archiving tool across the file servers this week, "expect elevated disk activity during off-peak hours." The rollout schedule attached shows this server listed for tonight.
Your isolation button disconnects the server from the network instantly. Finance opens in 5 hours, and that server holds their shared drives. Isolating it wrongly means a morning of downtime, an angry client, and an incident report with your name on it.

#### Explain how you would investigate and why?

Isolate the server now, then investigate.

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

#### Contextual Consideration

The scheduled archiving rollout is relevant context and should be investigated. However, it should **not override the security telemetry**.

The combination of:

> **Shadow-copy deletion + mass file modification + unknown file extension + extremely high CPU utilization**

provides sufficient evidence to treat the activity as a potential ransomware incident and **contain the host immediately**.

Given that the server holds Finance share folders, the appropriate approach is to **isolate first, then investigate**, while simultaneously verifying whether the observed activity is associated with the authorised archiving deployment. Contact the change management team and the administrators to confirm that this behaviour is expected.


#### MITRE ATT&CK Mapping

| Evidence | Technique | ATT&CK ID | Rationale |
|---|---|---|---|
| `vssadmin.exe delete shadows /all /quiet` | Inhibit System Recovery | [T1490](https://attack.mitre.org/techniques/T1490/) | Deletes Volume Shadow Copies to prevent recovery. |
| 4,000+ files renamed within two minutes | Data Encrypted for Impact | [T1486](https://attack.mitre.org/techniques/T1486/) | Mass file modification is consistent with ransomware encryption. |
| Files receiving an unknown `.lkd` extension | Data Encrypted for Impact | [T1486](https://attack.mitre.org/techniques/T1486/) | A new extension across thousands of files may indicate encrypted or transformed data. |
| CPU utilization reaching 98% | Supporting evidence for T1486 | [T1486](https://attack.mitre.org/techniques/T1486/) | High CPU utilization may indicate an active encryption/transformation process, but CPU usage alone is not sufficient to establish the technique. |
