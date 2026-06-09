# Incident Response Report
## [Lab Name] — [Short Description of Incident Type]

<!--
TITLE: Replace with the lab name and a one-line description of the attack.
Example: "Web Investigation — SQL Injection to Web Shell Deployment"
-->

---

| Field              | Details                          |
|--------------------|----------------------------------|
| **Severity**       | Critical / High / Medium / Low   |
| **Status**         | Open / In Progress / Closed      |
| **Analyst**        | Murillo H. W. G.                 |
| **Date**           | YYYY-MM-DD                       |
| **Platform**       | CyberDefenders / HTB / LetsDefend / TryHackMe / Other |
| **Classification** | TLP:WHITE                        |

<!--
SEVERITY GUIDE:
- Critical → RCE, full system compromise, data exfiltration confirmed
- High     → Significant access gained, lateral movement, credential theft
- Medium   → Partial access, reconnaissance only, no confirmed exfiltration
- Low      → Failed attempts, no confirmed impact
-->

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Scope & Methodology](#2-scope--methodology)
3. [Attack Timeline](#3-attack-timeline)
4. [Technical Findings](#4-technical-findings)
5. [Indicators of Compromise (IOCs)](#5-indicators-of-compromise-iocs)
6. [Impact Assessment](#6-impact-assessment)
7. [Appendix](#7-appendix)
8. [Lessons Learned & Recommendations](#8-lessons-learned--recommendations)

---

## 1. Executive Summary

<!--
2-4 sentences covering:
- What happened (attack type)
- Who was affected (target system/application)
- What was the outcome (what the attacker achieved)
- Overall risk level

Keep it non-technical — this section should be readable by a non-security audience.
-->

> **Risk Level: [CRITICAL / HIGH / MEDIUM / LOW]** — [One sentence justifying the risk level.]

---

## 2. Scope & Methodology

### Scope

| Item             | Value                              |
|------------------|------------------------------------|
| Evidence File    | <!-- e.g. capture.pcap, auth.log, memory.dmp --> |
| Analysis Tool(s) | <!-- e.g. Wireshark, Splunk, Volatility, CyberChef --> |
| Target           | <!-- e.g. Web application, Windows host, Linux server --> |
| Analysis Type    | <!-- Post-incident forensic / Live response / Threat hunt --> |

### Methodology

<!--
List the steps taken during the investigation in order.
Examples:
1. Loaded PCAP into Wireshark and filtered HTTP traffic
2. Extracted IOCs from log file using grep/Splunk queries
3. Decoded obfuscated payloads with CyberChef
4. Correlated events across multiple log sources
-->

1. 
2. 
3. 

---

## 3. Attack Timeline

<!--
Map out the attack phases in order. Use the tree format below.
Common phases: Reconnaissance → Initial Access → Execution → Persistence → Exfiltration

Adjust phases to match the actual attack — not every incident has all phases.
-->

```
[Phase 1] 
    └── 

[Phase 2] 
    └── 

[Phase 3] 
    └── 

[Phase 4] 
    └── 
```

---

## 4. Technical Findings

<!--
One subsection per attack phase or major finding.
Each subsection should have:
- A brief explanation of what happened
- A table with key technical details
- The supporting evidence (screenshot reference)

Number the subsections to match the timeline phases.
-->

### 4.1 [Finding Name]

<!--
Example: "Attacker Identification", "Initial Access", "Payload Analysis"
-->

[Description of what was found and how.]

| Field  | Value |
|--------|-------|
|        |       |

**Evidence:**

> `screenshot-name.png` — [One sentence describing what the screenshot shows.]

![Alt text](screenshots/screenshot-name.png)

---

### 4.2 [Finding Name]

[Description of what was found and how.]

| Field  | Value |
|--------|-------|
|        |       |

**Evidence:**

> `screenshot-name.png` — [One sentence describing what the screenshot shows.]

![Alt text](screenshots/screenshot-name.png)

---

<!--
Add as many 4.X subsections as needed.
One subsection per distinct phase or finding.
-->

---

## 5. Indicators of Compromise (IOCs)

<!--
Consolidate ALL IOCs found during the investigation here.
Every IOC mentioned in Section 4 should appear in this table.

Common IOC types:
- IP Address
- Domain
- URL / URI
- File Hash (MD5/SHA1/SHA256)
- Filename
- Registry Key
- User Agent
- Email Address
- Credential
-->

| Type       | Value | Context |
|------------|-------|---------|
|            |       |         |
|            |       |         |

---

## 6. Impact Assessment

<!--
Assess the impact per area. Be objective — base severity on what was actually observed,
not on what could theoretically happen.

Common areas: Data Confidentiality, Data Integrity, System Availability,
Remote Code Execution, Lateral Movement, Reputational Damage
-->

| Impact Area           | Severity                        | Description |
|-----------------------|---------------------------------|-------------|
|                       | Critical / High / Medium / Low  |             |
|                       | Critical / High / Medium / Low  |             |

---

## 7. Appendix

<!--
Use this section for supporting material that doesn't fit in the main findings:
- Scripts or tools used during the investigation
- Raw log excerpts
- Full payload strings
- External references

If you wrote a script for the lab, document it here with usage context.
-->

### 7.1 [Tool / Script Name]

[Brief description of the tool and why it was used.]

**Usage context:** Applied to findings [X.X] and [X.X].

---

## 8. Concepts & Recommendations

<!--
Two parts:
1. Root Causes — what made the attack possible
2. Recommendations — concrete actions to prevent recurrence

Be specific. "Patch the system" is not a recommendation.
"Apply parameterized queries to all SQL-touching endpoints" is.
-->

### Vulnerability Root Causes

| Root Cause | Related Finding |
|------------|-----------------|
|            |                 |
|            |                 |

### Remediation Recommendations

<!--
Group by category. For each recommendation, specify:
- Priority: Immediate / Short-term / Long-term
- What exactly should be done
-->

**1. [Category] — [Priority]**
- 
- 

**2. [Category] — [Priority]**
- 
- 

---

*Report generated as part of Blue Team / DFIR lab exercise.*
*All findings are based on analysis performed in a controlled lab environment.*
