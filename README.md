# Lab — Detection & Response: RDP Brute-Force (Microsoft Sentinel / Microsoft Defender)

**Goal:** Deploy an Azure Windows VM, onboard it to Microsoft Defender for Endpoint (MDE) and Azure Monitor Agent (AMA), ingest authentication logs to Microsoft Sentinel / Defender, simulate an RDP brute-force, create a custom detection, validate incidents, and apply mitigation.

---

## Table of contents
- [Overview](#1-overview)  
- [Architecture](#2-architecture)  
- [Prerequisites](#3-prerequisites)  
- [Quick summary](#4-quick-summary)  
- [Full step-by-step lab (A → H)](#5-full-step-by-step-lab)  
- [KQL queries (copy/paste ready)](#6-kql-queries)  
- [Commands & samples (Azure CLI / PowerShell)](#7-commands--samples)  
- [Troubleshooting & FAQ](#8-troubleshooting--faq)  
- [Cleanup & cost control](#10-cleanup--cost-control)  
- [Improvements & next steps](#11-improvements--next-steps)
- [Short lab report](#12-short-lab-report)   
- [License & contact](#13-license--contact)  

---

## 1. Overview
This lab demonstrates a complete SOC-style detection workflow for RDP brute-force attempts:

- Deploy VM (victim) in Azure.  
- Ensure logs are collected (AMA / DCR → Log Analytics).  
- Onboard VM to Microsoft Defender for Endpoint (MDE) for EDR telemetry (DeviceLogonEvents).  
- Simulate failed RDP logons (attacker).  
- Build a robust KQL detection and create a Custom Detection Rule in Defender / Sentinel.  
- Validate generated incidents and perform mitigation (block IP in NSG or isolate VM).  

---

## 2. Architecture 
                  ┌───────────────────────────────┐
                  │   Attacker (Client / Laptop)  │
                  │   or another Azure VM         │
                  └───────────────┬───────────────┘
                                  │
                                  │  RDP (TCP 3389) attempts
                                  ▼
         ┌──────────────────────────────────────────────────────┐
         │                 Azure Network Layer                  │
         │                                                      │
         │   ┌──────────────┐     ┌──────────────────────────┐  │
         │   │   NSG        │     │ Public IP (VM-Victim-ip) │  │
         │   │  (Inbound:   │◀────┤   ↔ maps to VM NIC       │  │
         │   │  Allow RDP   │     └──────────────────────────┘  │
         │   │  only from   │                                 │
         │   │  attacker IP │                                 │
         │   └───────┬──────┘                                 │
         │           │                                        │
         │    ┌──────▼─────────────────────────────────┐      │
         │    │         VM-Victim (Windows Server)     │      │
         │    │                                        │      │
         │    │  - Windows Security Log (4625)         │      │
         │    │  - Defender MDE Agent ("Sense")        │      │
         │    │  - Azure Monitor Agent (AMA)           │      │
         │    └─────────┬───────────────┬──────────────┘      │
         │              │               │                     │
         └──────────────┼───────────────┼─────────────────────┘
                        │               │
            SecurityEvent (4625)   DeviceLogonEvents (LogonFailed)
         (via AMA → DCR → Log      (via Defender for Endpoint EDR
          Analytics Workspace)      → Advanced Hunting / XDR)
                        │               │
                        ▼               ▼
              ┌───────────────────┐  ┌──────────────────────┐
              │ Log Analytics WS  │  │ Microsoft Defender    │
              │ (LA-Workspace)    │  │ (security.microsoft)  │
              └─────────┬─────────┘  └─────────┬────────────┘
                        │                     │
                        ▼                     ▼
              ┌───────────────────┐  ┌──────────────────────┐
              │ Microsoft Sentinel│  │  Defender Incidents  │
              │ (KQL Detections)  │  │ + Advanced Hunting   │
              └─────────┬─────────┘  └──────────────────────┘
                        │
                        ▼
              ┌──────────────────────────────┐
              │ Custom Detection Rule         │
              │ - Detect ≥10 RDP failures     │
              │   from same IP in 15m window  │
              └──────────────────────────────┘
                        │
                        ▼
              ┌──────────────────────────────┐
              │ Incident / Alert created      │
              │ - Entities: Account, IP, Host │
              │ - Analyst can Investigate     │
              │   & Respond                   │
              └──────────────────────────────┘

---

## 3. Prerequisites
- Azure subscription with permission to create resources (VM, NSG, Log Analytics, Defender settings).  
- Microsoft 365 Defender tenant (for onboarding MDE).  
- Microsoft Remote Desktop (Mac/Windows) to reach the VM (or Azure Bastion).  
- Basic familiarity with KQL and Azure Portal.  
- (Optional) Azure CLI and PowerShell for automation.  


## 4. Quick summary
Create an Azure VM, onboard it to AMA & MDE, generate failed RDP logins, and detect them with a custom KQL-based rule that creates incidents in Defender/Sentinel.

---

## 5. Full step-by-step lab

### A. Prepare Azure resources
**Objective:** create resource group, Log Analytics workspace, virtual network, NSG and VM.

**Steps (Portal recommended):**
1. Create Resource Group `Lab-SC200` in chosen region (e.g., `canadacentral`).  
2. Create Log Analytics workspace `LA-Workspace-SC200`.  
3. Create Virtual Network `vnet-lab` + Subnet `snet-lab`.  
4. Create Network Security Group `nsg-victim`:
   - Add inbound rule to allow RDP (TCP 3389) only from your public IP (or your attacker test IP).  
   - Example rule name: `Allow-RDP-MyIP` (priority e.g., 300).
5. Deploy a Windows Server VM `VM-Victim` (Windows Server 2019/2022) in that subnet, attach Public IP, assign `nsg-victim` to its NIC, and associate the Log Analytics workspace (or plan to install AMA extension).

**Validation**
- RDP access from your workstation.  
- NSG rules present.  
- Workspace exists.


**VM overview (VM-Victim running)**
<img width="1632" height="37" alt="vm_overview" src="https://github.com/user-attachments/assets/3f80f100-111a-412f-aa73-d54355a04425" />  
**NSG inbound rules**
<img width="1015" height="168" alt="nsg_inbound_rules" src="https://github.com/user-attachments/assets/65131875-83fe-4558-b72f-2724cd6e1159" />

---

### B. Install Azure Monitor Agent (AMA) & Data Collection Rule (DCR)
**Objective:** forward Windows Event Logs (Security) to Log Analytics.

**Approach**
- Portal: Virtual Machine → Extensions + applications → Add → **Azure Monitor Agent**.  
- Create Data Collection Rule (DCR) to collect Windows Event Log channel `Security` and send it to `LA-Workspace-SC200`. Alternatively enable auto-provisioning through Defender for Cloud.

**Validation (inside VM)**
```powershell
# Verify Microsoft Monitoring Agent:
Get-Service | Where-Object { $_.Name -match "HealthService|AzureMonitor|MMA" } | Format-Table Status, Name, DisplayName
# Query in Log Analytics:
# SecurityEvent | where TimeGenerated > ago(1h) | take 10
```

**C. Onboard VM to Microsoft Defender for Endpoint (MDE)**

Objective: ensure EDR telemetry (DeviceLogonEvents) is available in Defender Advanced Hunting.

Auto-provision (recommended)
	•	Defender for Cloud → Environment settings → Defender plans → enable Endpoint protection and set auto-provisioning for MDE agent.

Manual onboarding (if needed)
	1.	security.microsoft.com → Settings → Endpoints → Onboarding.
	2.	Choose the onboarding package for Windows Server, download ZIP.
	3.	Copy ZIP to your VM (via RDP redirected folder or download inside VM).
	4.	Run WindowsDefenderATPOnboardingScript.cmd as Administrator.

Validate (inside VM)
```powershell
Get-Service | Where-Object { $_.Name -match "Sense|WdNis|WdFilter" } | Format-Table Status, Name, DisplayName
# Expect: Sense => Running
```

**Validate (portal)**

	•	security.microsoft.com → Devices → Device inventory → VM appears as Onboarded.
	•	Advanced Hunting: DeviceLogonEvents | where Timestamp > ago(1h) | take 20

<img width="911" height="560" alt="MDE" src="https://github.com/user-attachments/assets/b081269c-b47c-4a73-bd79-a2deab3cd86e" />

⸻

**D. Validate ingestion & mapping**

Objective: confirm both Sentinel (SecurityEvent) and Defender (DeviceLogonEvents) get data.

Queries to run
	•	Sentinel (Log Analytics)
```powershell
SecurityEvent
| where TimeGenerated > ago(1h) and EventID == 4625
| take 20
```

•	Defender Advanced Hunting
```powershell
DeviceLogonEvents
| where Timestamp > ago(1h)
| take 20
```
Validation
	•	See EventID 4625 in SecurityEvent.
	•	See LogonFailed entries in DeviceLogonEvents.

**E. Simulate brute-force RDP**

Objective: generate failed logon attempts from a controlled IP.

Manual safe method
	•	Use mstsc (or RDP client) and attempt to login to VM-Victim with the labuser username but wrong password, repeat quickly (10+ times) from your attacker machine or another VM.

Scripted (lab-only)
	•	You can script repeated failures, but be careful with lockout policies. Only perform in your lab.

Validation
	•	DeviceLogonEvents shows ActionType == "LogonFailed" for attacker IP.
	•	SecurityEvent shows EventID 4625.
 
<img width="870" height="329" alt="sentinel_query_results" src="https://github.com/user-attachments/assets/c870b78e-d140-4863-8b12-7d7560c7fa9b" />

⸻

**F. Create the detection (Custom detection rule)**

Objective: turn KQL into an actionable detection rule that creates incidents.

Recommended KQL (Max-in-bin approach):
```powershell
DeviceLogonEvents
| where Timestamp > ago(24h) and ActionType == "LogonFailed"
| extend SourceIP = tostring(RemoteIP),
         Account  = tostring(AccountName),
         Device   = tostring(DeviceName)
| summarize Attempts = count(), 
            ReportId = any(ReportId),          
            Timestamp = any(Timestamp)         
  by DeviceId, SourceIP, Account, Device
| where Attempts >= 10
| project Timestamp, DeviceId, ReportId, SourceIP, Account, Device, Attempts
| order by Attempts desc
```

**Create rule settings (Defender portal → Advanced hunting → Create detection rule)**

	•	Name: Detect_BruteForce_RDP_Lab
	•	Description: Detects 10 or more failed RDP logon attempts (LogonFailed) from the same source IP within a 15-minute window.
	•	Run query every: 5 minutes
	•	Lookup data from last: 30 minutes (or 24 hours if query uses ago(24h))
	•	Severity: Medium
	•	Category: Credential Access → Brute Force
	•	MITRE: T1110 (Brute Force)
	•	Alert title: Brute Force RDP Detected from {{SourceIP}}
	•	Alert description: This alert was triggered when {{Attempts}} failed RDP logon attempts were detected from {{SourceIP}} against account {{Account}} on device {{Device}} within a 15-minute window.
	•	Custom details: SourceIP, TargetAccount, TargetDevice, FailedAttempts
	•	Entity mapping: Account → Account, Host → Device, IP → SourceIP
	•	Automated actions: leave empty for lab (do not isolate automatically).

Validation
	•	Simulate the attack and confirm a new incident in Defender → Incidents & alerts.

<img width="1179" height="500" alt="KQL" src="https://github.com/user-attachments/assets/62c9c273-9a90-417b-bb2b-e149613cd22f" />

<img width="1600" height="345" alt="Incident" src="https://github.com/user-attachments/assets/671da599-1c6a-49ac-9fa2-6932cb5f1db8" />

⸻

## G — Investigation & Mitigation

**Important note:**  
No automated actions (playbooks, automatic isolation, automated blocking, etc.) were executed in this lab — all responses were performed manually or documented. This lets you validate the detection → investigation chain without risking accidental isolation of the VM or loss of access while working.

---

### 1) Investigation — quick checklist
- **Review the alert / incident:** open the incident, examine entities (SourceIP, Account, Device), timeline and evidence (logs).  
- **Useful queries:**  
  - `DeviceLogonEvents` for authentication attempts (`ActionType == "LogonFailed"`)  
  - `DeviceNetworkEvents` to inspect network traffic to/from the IP  
  - `DeviceProcessEvents` to check for suspicious processes on the endpoint  
- **Preserve evidence:** export relevant logs, screenshots and timestamps for the report and post-mortem.

---

### 2) Possible mitigations (enumerated with short explanations)

**A. Block the source IP (NSG / firewall)**  
- **What:** Add a rule to the NSG or firewall to deny traffic from the attacker IP (e.g., block TCP/3389).  
- **Why:** Fast, effective immediate stop for attack traffic.  
- **Limitations:** Attackers can switch IPs (proxies, botnets). Use as a temporary measure and document it.

**B. Isolate the device (EDR isolation)**  
- **What:** Use Microsoft Defender for Endpoint’s isolation action to remove the machine from the network (except Defender communication).  
- **Why:** Prevents exfiltration and lateral movement while you investigate.  
- **Limitations / precautions:** Admin access is impacted — ensure you have recovery options (Azure Serial Console, Bastion) and use only when necessary.

**C. Collect an investigation package / forensic snapshot**  
- **What:** Capture detailed logs and artifacts (memory, files, registry, timelines) via Defender/Sentinel.  
- **Why:** Provides a forensics bundle for deep analysis and evidence preservation.  
- **Limitations:** Storage/processing cost and possible privacy/legal approvals in production.

**D. Force password reset & verify compromise scope**  
- **What:** Reset the targeted user’s password and check for signs of compromise across other accounts.  
- **Why:** Prevents continued use of credentials that may have been discovered or brute-forced.  
- **Limitations:** Communicate to users and ensure password policy strength.

**E. Enforce MFA (require MFA for remote access)**  
- **What:** Require multi-factor authentication for accounts used to access RDP or cloud resources (Azure AD Conditional Access).  
- **Why:** Greatly reduces the effectiveness of password-only brute-force attacks.  
- **Limitations:** May require configuration effort and user onboarding.

**F. Temporarily disable public RDP / reduce attack surface**  
- **What:** Close port 3389 to the public, use Azure Bastion, a jump box, or VPN for admin access.  
- **Why:** Eliminates an exposed RDP target and forces attackers to find a different vector.  
- **Limitations:** Might impact legitimate admin workflows; plan for admin access alternatives.

**G. Increase logging & detection granularity**  
- **What:** Collect more telemetry (process, network, command-line details) and refine detection rules and enrichment (threat intel).  
- **Why:** Improves correlation capabilities and detection of complex attack behaviors.  
- **Limitations:** Increased ingestion costs and storage.

**H. Create an automated playbook (Logic App) to respond**  
- **What:** Build a playbook that, on alert, blocks the attacker IP in the NSG, creates a ticket, and notifies the team.  
- **Why:** Reduces time-to-respond (MTTR) and automates repeatable tasks.  
- **Limitations / precautions:** Test thoroughly to avoid false-positive automated blocking; include safeties (admin whitelist, approvals).

**I. Apply host-based mitigations**  
- **What:** Configure account lockout policies, enable RDP throttling, deploy OS hardening and exploit mitigations.  
- **Why:** Makes brute-force attempts much harder to succeed.  
- **Limitations:** Misconfiguration can impact legitimate users — tune carefully.

**J. Threat hunting & enrichment (threat intel)**  
- **What:** Enrich the alert with IP reputation, ASN, geolocation and search for other hosts contacting the same IP.  
- **Why:** Helps determine if this is an opportunistic scan or part of a broader campaign.

---

### 3) Recommended order of actions (practical playbook)
1. **Triage quickly** — confirm the alert: identify attacking IP(s), affected account(s) and host(s).  
2. **Temporary IP block** (NSG) to immediately stop visible activity.  
3. **Collect evidence** — capture investigation package and export relevant logs.  
4. **Analyze** — look for signs of compromise (persistence, new accounts, lateral movement).  
5. **Host-level actions** — reset passwords, check for credential reuse, enable MFA where possible.  
6. **Isolate** the host if you find evidence of compromise or ongoing suspicious activity.  
7. **Automate** the safe parts of the playbook (e.g., block IP + ticket creation) only after validation, and include safeguards.  
8. **Post-mortem** — document findings, update detection rules and hardening guidance.

---

### 4) Tips & best practices
- **Don’t automate isolation without safeguards.** Isolation is powerful but can stop remediation and investigation workflows — implement whitelists (trusted admin IPs) and approval gates.  
- **Always document actions.** Record who blocked what, why, for how long, and attach evidence. This is crucial for incident reports and audits.  
- **Test playbooks in a controlled environment** before deploying to production.  
- **Use defense-in-depth.** Combine network blocks, MFA, account policies, EDR telemetry, and hunting to reduce risk.  

---

**H. Cleanup & cost control**

•	Stop / deallocate VM

•	Delete the resource group when finished

Notes

•	Deallocating stops compute charges; managed disks still cost unless deleted.

•	Non-static public IP may change on stop/start.


## 6. KQL queries

Debug: failed logons (quick)
```powershell
DeviceLogonEvents
| where Timestamp > ago(1h) and ActionType == "LogonFailed"
| project Timestamp, DeviceId, ReportId, RemoteIP, AccountName, DeviceName
| order by Timestamp desc
| take 50
```
**Final detection (Max-in-bin)**
```powershell
DeviceLogonEvents
| where Timestamp > ago(24h) and ActionType == "LogonFailed"
| extend SourceIP = tostring(RemoteIP),
         Account  = tostring(AccountName),
         Device   = tostring(DeviceName)
| summarize Attempts = count(), 
            ReportId = any(ReportId),          
            Timestamp = any(Timestamp)         
  by DeviceId, SourceIP, Account, Device
| where Attempts >= 10
| project Timestamp, DeviceId, ReportId, SourceIP, Account, Device, Attempts
| order by Attempts desc
```
## 7. Commands & samples

Check services on Windows VM (PowerShell admin)
```powershell
Get-Service | Where-Object { $_.Name -match "Sense|WdNis|HealthService|AzureMonitor" } | Format-Table Status, Name, DisplayName
```
## 8. Troubleshooting & FAQ

	•	No DeviceLogonEvents?
	•	Ensure Sense service is Running. Wait 10–30 minutes after onboarding. Check security.microsoft.com device inventory.
	•	Create detection rule fails?
	•	Your final query must return DeviceId, Timestamp, and ReportId in the projection. Do not destructively rename or remove them.
	•	Rule not firing?
	•	Verify ago(...) in query vs rule Lookback. Lower threshold for testing (≥3) then raise to production (≥10).
	•	Agent auto-provision failed?
	•	Manually download onboarding package from security.microsoft.com and run script on VM.
	•	Lost RDP access after NSG change?
	•	Use Azure Serial Console or Azure Bastion or ensure your admin IP is allowed.

## 10. Cleanup & cost control

	•	Deallocate VM when idle.
	•	Delete resource group when finished to remove disks/public IPs.
	•	Use small VM sizes for labs (B1s or similar).
	•	Keep track of Log Analytics ingestion / Defender costs if you scale tests.

## 11. Improvements & next steps

	•	Create a Logic App playbook to automatically block attacker IP and create a ticket.
	•	Enrich detections by correlating DeviceLogonEvents with DeviceNetworkEvents and SecurityEvent.
	•	Add process-level detections (DeviceProcessEvents) and lateral movement rules.
	•	Automate lab deployment via ARM template / Bicep / Terraform.

## 12. Short lab report

This lab successfully demonstrated the end-to-end workflow for detecting and responding to RDP brute-force attempts using Microsoft Sentinel and Microsoft Defender for Endpoint.  

**Highlights:**  
- Built an Azure VM and configured secure NSG rules.  
- Enabled log ingestion through AMA + DCR and onboarded the VM to MDE.  
- Simulated brute-force attacks (failed RDP logons).  
- Authored a custom KQL detection to identify repeated failed logins.  
- Created a detection rule that raised incidents in Microsoft Defender.  
- Investigated incidents using Advanced Hunting queries.  
- Documented possible mitigations (IP block, isolation, MFA, RDP hardening, etc.).  

This lab demonstrates SOC skills across **deployment, detection engineering, incident investigation, and remediation planning**, making it suitable for inclusion in a security portfolio or CV.

## 13. License & contact

License: MIT — free to reuse for educational and portfolio purposes.
Contact: Add your GitHub profile or email if publishing publicly.
