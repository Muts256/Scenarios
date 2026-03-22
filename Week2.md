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
