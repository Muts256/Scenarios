#### Alert: MYDFIR-ALRT-0003

##### Alert Name:

*Impossible Travel Sign-In Detected*

#### User Account
`George.Matthews@fakecompany.ca`

#### IP Address Activity
`197.228.6.18` → `142.113.48.49`

#### Time Detected
`2025-08-29 15:24 UTC`

---

#### Investigation: Impossible Travel (Compromise vs False Positive)

Within a 15-minute window, the user account George.Matthews signed into Microsoft 365 from two geographically distant locations that are not physically possible to travel between. Conditional Access flagged the session, but authentication was still successful.

####  Objective
Determine whether the impossible travel sign-in for `George.Matthews@fakecompany.ca` represents a true account compromise or a benign anomaly.

---


#### 1. Observed Activity
- **Source IP 1:** `197.228.6.18`
- **Source IP 2:** `142.113.48.49`
- **Time Window:** 15 minutes


#### 2.  Conditional Access Outcome
- **Policy Triggered:** Impossible Travel Detection
- **Result:**  *Flagged but NOT blocked*
- **Authentication Status:**  Successful


#### 3. Security Implications
- Successful authentication despite the Conditional Access trigger indicates:
  - Policy configured in **report-only mode**, OR
  - Policy allows access with **conditions satisfied** (e.g., MFA), OR
  - Gap in enforcement logic


#### 4. Risk Assessment
This behavior may indicate:

-  **Credential compromise**
-  **Session/token hijacking**
-  Use of **VPN or anonymization services**
-  Misconfigured Conditional Access policies


#### Key Concern
The authentication was **not blocked**, meaning a potentially unauthorized user may have gained access to corporate resources.



#### Initial Hypothesis
- If both logins originated from:
  - Different devices + different locations → **High likelihood of compromise**
  - Same device + VPN/proxy → **Possible false positive**


#### Next Steps
- Investigate sign-in logs for device and client consistency
- Validate MFA enforcement and results
- Analyze post-login activity
- Confirm activity directly with the user
- Review Conditional Access policy configuration
- Check both IPs against:
  - Threat intelligence feeds
  - Known VPN / proxy providers
  - Block or monitor suspicious IP addresses

#### MITRE ATT&CK Mapping
- **T1078** – Valid Accounts
- **T1556** – Modify Authentication Process (potential)
- **T1539** – Steal Web Session Cookie (potential)
