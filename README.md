# CYBER RANGE BREACH - **CASE ID:** `SIR21183209`

# **Incident Trigger**

- **Subscription Affected:** `(Disabled) LOG(N) Pacific - Cyber Range 2`
- **Case ID:** `SIR21183209` (Microsoft Security Investigation)
    
![image](https://github.com/user-attachments/assets/221ebf0f-1508-4a05-a4e4-3ff756583efd)

    
- **Reported By:** cert@microsoft[.]com
- **Cause:** Violation of Azure Acceptable Use Policy
    
![image](https://github.com/user-attachments/assets/f14088bc-e0a9-437d-9c9a-43169a528bbf)

    
- **Action Taken:** Subscription disabled by Microsoft

![image](https://github.com/user-attachments/assets/e1dd4407-f56f-4f8d-9c83-a2eb3bada0b0)
 

---

# **Key Findings & Assumptions**

- **RDP & SSH were exposed** by design for simulation purposes.
- **Weak passwords** were likely in use across student-deployed systems.
- Some **vulnerable boxes had root access intentionally** for lab use.
- Students may have **left VMs running**, which could be exploited by bots.
- Prior history of **guest account abuse**, but no successful compromise logged.
- No direct evidence of **tunneling tools**, but **can’t be ruled out.**
- NSG requires hardening as Cyber Range 1 was not effected.

---

# Summary Hypothesis

> One or more student-deployed VMs were left exposed (SSH/RDP) with weak or default credentials, allowing external threat actors (likely bots or miners) to gain access. These compromised VMs may have launched outbound brute-force attacks, crypto-mining, or C2 traffic, triggering Microsoft’s abuse detection systems. The result was an automated shutdown of the subscription.

---

# Azure Brute Force Termination (Confirmed C2 & Miner Behaviour)

![image](https://github.com/user-attachments/assets/e68a2cfa-ff0a-4019-b885-7515c4764259)

![image](https://github.com/user-attachments/assets/f7d79c73-f396-4ef9-96cd-32a93c97a996)


## Recap of Findings

- **IOC(s):**
    - Top contacted IPs:
        - `172[.]202[.]65[.]10`, `125[.]87[.]89[.]229`, `168[.]63[.]129[.]16`, `101[.]91[.]114[.]194`
    - Process names used:
        - `systemd-worker`, `gc_linux_service`, `snapd`, `python3.10`
    - Executables dropped:
        - `xkbpvnlkrl`, `cftndlwyyn`, `anfcjteyug`, `spbsjctuog` in `/usr/bin/`
- **Affected VM:** `programmatic-remediation-linux-andre`
- **Earliest Activity:** April 25, 2025 03:13:59 AM (UTC)
- **Latest Activity:** May 5, 2025 10:47:09 AM UTC
- **Actions Observed:**
    - Obfuscated binaries launched in Bash
    - Beaconing to 50+ unique IPs across ports 443, 80, and 1919
    - Outbound brute-force activity on port 22 (SSH) to **120,653** unique public IPs

---

# Investigation Summary

> On May 5, 2025, Microsoft Defender telemetry flagged VM programmatic-remediation-linux-andre for behavior consistent with crypto-mining and outbound brute-force attacks.
> 
> 
> The system executed binaries from `/usr/bin/` with random names calling Bash (e.g., `xkbpvnlkrl bash 645`). These processes were often disguised as `systemd-worker`, and beaconed to external IPs over ports 80, 443, and 1919.
> 
> A total of **120,653 outbound connections** were made to unique public IPs, many via SSH on port 22, strongly suggesting use as a brute-force bot. This is the likely cause of the subscription being suspended and disabled,
> 

---

# Recommendations

- Block communication with the following confirmed IOC IPs:
    - `hxxp://172[.]202[.]65[.]10`, `hxxp://125[.]124[.]106[.]113`, `hxxp://188[.]166[.]211[.]175`
- Apply the following hardening controls before redeployment:
    - Disable direct public IP access; require Bastion or jump host
    - Enforce SSH key authentication or 16+ character complex passwords
    - Deploy outbound NSG egress deny rules by default; allow only whitelisted ports
    - Enable Defender for Endpoint tamper protection and audit log retention
    - Implement custom Sentinel alerts for:
        - High-volume outbound traffic
        - Execution from uncommon paths (`/usr/bin/` + random names)
        - Beaconing to >50 public IPs in 24h

---

# Appendix

- **Evidence 1:** [Top 50 Contacted IPs – systemd-worker]
- **Evidence 2:** [Outbound Beaconing over Port 1919]
- **Evidence 3:** [Malicious Executables Logged in `/usr/bin`]
- **Evidence 4:** [Total Unique IPs Targeted – 120,653]

---

![image](https://github.com/user-attachments/assets/563bd974-ef98-4c99-8a30-e856c05743b1)


![image](https://github.com/user-attachments/assets/bf687339-451e-47d4-9319-113e62fd8862)


![image](https://github.com/user-attachments/assets/82d5c10a-efb9-4956-b39e-ce041c2583b8)


![image](https://github.com/user-attachments/assets/5a52f861-8f09-4abf-952b-71b4ea584742)


![image](https://github.com/user-attachments/assets/fe0f9a8b-01aa-4d09-87ce-2ca1d7db6374)


References:

[**DoS:Linux/Xorddos.A**](https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?name=DoS:Linux/Xorddos.A)

# **Case ID:** `SIR21183209` (Microsoft Security Investigation) Summary

## 1. Recap of Findings

- **Earliest Activity:** April 25, 2025 03:13:59 AM (UTC)
- **Last Activity:** May 7, 2025 03:47:02 PM (UTC)
- **Affected Hosts:**
    - `linux-vm-360.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net`
    - `ljp-linux-vr.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net`
    - `linux-programmatic-fixcalvin.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net`
    - `linux-programmatic-zedd.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net`
    - `programmatic-remediation-linux-andre.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net`
    - `nab-linux-vuln.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net`
- **Affected Users:** `root`, `eforestal55`, `cheeki`, `testlabs`
- **Source IPs / URLs:**
    - `172[.]82[.]91[.]6` (Malware download server)
    - `172[.]82[.]91[.]19` (Additional curl fetch target)
- **Malicious Domains:** `dinpasiune[.]com`
- **Method of Access:** Direct execution of malicious shell scripts (e.g., `./retea`, `gcc.sh`) with SSH persistence via `authorized_keys`
- **Malware Observed:**
    - `/var/tmp/kbwvfuepukdbaztz`
    - `/var/tmp/keqneqzlvyhrfeyw`
    - `/etc/cron.hourly/gcc.sh`
    - `/lib/libudev.so.6`
- **Telemetry Limitations:** Network payload inspection is unavailable; no packet capture; possible gaps in prior login telemetry (before malware execution)

---

## 2. Investigation Summary

During the investigation, multiple Linux VMs were found to be compromised through the use of malicious shell scripts (`retea`, `gcc.sh`) and credential abuse involving the SSH `authorized_keys` file. The attacker used elevated root permissions in several cases to install persistent cron jobs and overwrite system libraries (e.g., `libudev.so`).

The infections span at least six VMs between April 25 and May 7, 2025. All compromised systems executed either `./retea` or variants that performed staged downloads from `172[.]82[.]91[.]6` and planted persistence mechanisms. Some systems also showed tampering with legitimate cron binaries and `/lib/` shared objects.

All observed activity is consistent with the known tactics of the XorDDoS and related Linux malware families, which involve credential theft, system tampering, and stealthy persistence.

---

## **3. Recommendations**

- Block communication with the following confirmed IOC IPs:
    - `hxxp://172[.]202[.]65[.]10`, `hxxp://125[.]124[.]106[.]113`, `hxxp://188[.]166[.]211[.]175`
- Apply the following hardening controls before redeployment:
    - Disable direct public IP access; require Bastion or jump host
    - Enforce SSH key authentication or 16+ character complex passwords
    - Deploy outbound NSG egress deny rules by default; allow only whitelisted ports
    - Enable Defender for Endpoint tamper protection and audit log retention
    - Implement custom Sentinel alerts for:
        - High-volume outbound traffic
        - Execution from uncommon paths (`/usr/bin/` + random names)
        - Beaconing to >50 public IPs in 24h

---

# **Case ID:** `SIR21183209` (Microsoft Security Investigation) Main Report

## Executive Summary

Between April 25**th and May 7th, 2025 (UTC)**, multiple Linux VMs in the student cyber range were compromised by persistent crypto-mining malware. Attackers used **SSH authorised key injection** to gain access and maintain persistence. The malware executed from common paths like `/dev/shm`, `/tmp`, and `/var/tmp`, leveraging files such as `libudev.so.6`, `gcc.sh`, and ELF binaries (`ygljglkjgfg0`, `retea`, etc.).

The initial infection occurred on **linux-vm-360** at **2025-05-04 01:09:30 UTC**, and the most recent compromise was recorded on **nab-linux-vuln** at **2025-05-07 14:47:02 UTC**.

**Affected users include:** `root`, `eforestal55`, `cheeki`, and `testlabs`. The primary attacker infrastructure resolved to **IP 172[.]82[.]91[.]6** and domain dinpasiune[.]com.

---

## 5W + 1H

- **Who:** Attacker(s) leveraging SSH key injection and cron persistence under `root`, `testlabs`, `eforestal55`, and `cheeki`.
- **What:** Remote access via modified `authorized_keys`, download and execution of miner payloads (`libudev.so.6`, `retea`, `gcc.sh`).
- **When:** First activity: **2025-05-04 01:09:30 UTC**
    
    Last activity: **2025-05-07 14:47:02 UTC**
    
- **Where:** Affected VMs include:
    - `linux-vm-360`
    - `ljp-linux-vr`
    - `linux-programmatic-zedd`
    - `linux-programmatic-fixcalvin`
    - `programmatic-remediation-linux-andre`
    - `nab-linux-vuln`
- **Why:** Cryptocurrency mining, the attacker used public tools and renamed binaries to maintain stealth and evade detection.
- **How:** SSH persistence via injected public keys, use of systemd services and cron jobs to restart miners.

---

## Threat Intelligence: Confirmed IOC Infrastructure

**Indicators of Compromise (IOCs):**

- **IPs:**
    - `172[.]82[.]91[.]6` (confirmed C2)
    - `172[.]82[.]91[.]19`
    - `85[.]31[.]47[.]99`
- **Domain:**
    - `dinpasiune[.]com` (malware host)
- **Files:**
    - `/dev/shm/ygljglkjgfg0`
    - `/usr/bin/retea`
    - `/etc/cron.hourly/gcc.sh`
    - `/usr/lib/libudev.so.6`

### 1. **IP: 172[.]82[.]91[.]6**

- **ASN**: AS212396, FyfeWeb Ltd
- **Provider**: Host Mayo LTD
- **Country**: 🇬🇧 United Kingdom (Newcastle upon Tyne)
- **Abuse Contact**: abuse@enginyring[.]com
- **Notes**:
    - No VirusTotal detections
    - Hosting infrastructure with privacy masking
    - Linked to domain `enginyring[.]com`
    - Appears in multiple infection chains, confirmed C2 address

---

### 2. **Domain: enginyring[.]com**

- **Registrar**: NETIM (France)
- **Created**: 2022-12-27
- **Expires**: 2025-12-27
- **ASN**: ENGINYRING EUROPE SRL (Romania)
- **Name Servers**: Cloudflare (obfuscated backend)
- **Status**: Registered, no website
- **Notes**:
    - Associated with malware campaigns
    - Privacy-shielded infrastructure
    - Likely operated by the bulletproof hosting provider

---

### 3. **IP: 85[.]31[.]47[.]99**

- **ASN**: AS151612, HOSTPERL
- **Provider**: HOSTPERL
- **Country**: 🇳🇿 New Zealand (Auckland)
- **Abuse Contact**: abuse@hostperl[.]com
- **VT Detections**: 1/94 (flagged by Forcepoint)
- **Notes**:
    - Passive DNS links to miner domains
    - Appears in live payload scripts (e.g., `retea`, `gcc.sh`)

---

### 4. **Observed Malicious Domains**

| Domain | Detection (VT) | Linked IP | Notes |
| --- | --- | --- | --- |
| `digitaldatainsights[.]org` | 13/94 | 85[.]31[.]47[.]99 | Staging domain for miners |
| `30640bd[.]icu` | 0/94 | 85[.]31[.]47[.]99 | Obscure, linked in scripts |
| `dinpasiune[.]com` | Manual block | — | Used in `curl`/`wget` download chains |

---

## IOC Summary Table

| Type | IOC | Status | Notes |
| --- | --- | --- | --- |
| IP | 172[.]82[.]91[.]6 | Active, No VT Hits | Main C2 server |
| Domain | enginyring[.]com | Active | C2 domain hosted via privacy registrar |
| IP | 85[.]31[.]47[.]99 | Low detection | Linked to payload staging |
| Domain | digitaldatainsights[.]org | Malicious (13/94) | Known miner staging domain |
| Domain | dinpasiune[.]com | Blocked via hosts | Used for initial infection scripts |

---

## **MITRE ATT&CK Mapping**

| Tactic | Technique ID | Technique Name | Evidence / Notes |
| --- | --- | --- | --- |
| **Initial Access** | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) | Brute Force: Password Guessing | SSH brute force access confirmed from logs |
| **Persistence** | [T1098.004](https://attack.mitre.org/techniques/T1098/004/) | Account Manipulation: SSH Authorized Keys | Attacker modified `authorized_keys` for root, `testlabs`, `eforestal55`, etc. |
| **Execution** | [T1059.004](https://attack.mitre.org/techniques/T1059/004/) | Command and Scripting Interpreter: Bash | Executed `.sh` payloads like `retea` |
| **Persistence** | [T1053.003](https://attack.mitre.org/techniques/T1053/003/) | Scheduled Task/Job: Cron | `/etc/cron.hourly/gcc.sh` used for recurring execution |
| **Persistence** | [T1546.006](https://attack.mitre.org/techniques/T1546/006/) | Event Triggered Execution: systemd service | systemd unit file tied to ELF malware |
| **Defense Evasion** | [T1036.004](https://attack.mitre.org/techniques/T1036/004/) | Masquerading: Masquerade Task or Service | Fake `libudev.so.6`, renamed `wget` to `good` |
| **Credential Access** | [T1556.004](https://attack.mitre.org/techniques/T1556/004/) | Credential Stuffing | Same SSH keys used across multiple VMs |
| **Command & Control** | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | Application Layer Protocol: Web Protocols | Used `curl`/`wget` to download payloads |
| **Impact** | [T1496](https://attack.mitre.org/techniques/T1496/) | Resource Hijacking | Observed crypto-mining behavior (XorDDoS variant) |

---

## Threat Intel Notes

- **Hosting** used across the UK, Romania, and New Zealand, likely bulletproof-style infra
- Use of **Cloudflare** to hide the backend infrastructure
- **Minimal detection** on some IPs/domains suggests use of fresh infra or short TTLs
- Scripts (`gcc.sh`, `libudev.so.6`, `retea`) confirm connections to these IOCs

---

## Recommendations

### **JIT VM Access**

- **NSG rules to block inbound SSH**
- **Blocking outbound connections to** `172[.]82[.]91[.]6`, `85[.]31[.]47[.]99`
- **Null-routing** `dinpasiune[.]com`
- **Use of Defender for Cloud workflow automation** to **auto-shutdown infected VMs**
- **Reference to compromised VMs**

### **Containment and Short-Term Actions**

- **Isolate the following compromised VMs immediately** or delete them.:
    - `linux-vm-360`, `ljp-linux-vr`, `linux-programmatic-fixcalvin`,
        
        `linux-programmatic-zedd`, `programmatic-remediation-linux-andre`, `nab-linux-vuln`
        
- **Block outbound traffic to known C2 infrastructure**, **if possible**:
    - IPs: `172[.]82[.]91[.]6`, `172[.]82[.]91[.]19`, `85[.]31[.]47[.]99`
    - Domains: `dinpasiune[.]com`
    - Optional: Add domains to `/etc/hosts` as `127.0.0.1` to null-route
- **Enable Just-In-Time (JIT) VM Access**:
    - Restrict SSH/RDP (ports 22/3389) to timed windows
    - Auto-expire access after 1 hour
    - [🔗 Microsoft Docs – JIT Access](https://learn.microsoft.com/en-us/azure/security-center/security-center-just-in-time)
- **Apply NSG (Network Security Group) Rules**:
    - Deny all inbound SSH from the internet
    - Whitelist Cyber Range IPs or VPN ranges only
- **Auto-Shutdown Infected VMs Using Defender for Cloud**:
    - Create a workflow automation triggered by “Crypto mining behaviour detected”
    - Action: Auto shutdown VM or alert the assigned mentor

---

# Appendix

## Crypto Miner Infection Evidence

### Cron Job Infections

![image](https://github.com/user-attachments/assets/f82faf99-0c7f-4541-ab77-90cb66048336)


### Cron Script

![image](https://github.com/user-attachments/assets/eb8371cf-ed8f-4aef-9484-844d296a28de)


### Malware Setting up Auth Keys for Persistence

![image](https://github.com/user-attachments/assets/541ded98-85d0-43a8-ae9c-149950c82f0f)


![image](https://github.com/user-attachments/assets/b9295f5b-94e8-4fb2-bb58-f9adac85a71d)


### Infected VMs (15-Day Period)

![image](https://github.com/user-attachments/assets/e4753180-6118-4dec-96e3-66c4156a0e9a)


![image](https://github.com/user-attachments/assets/823aa66f-19a9-4987-a410-78e044aeb383)


---

# Threat Intel

![image](https://github.com/user-attachments/assets/93ccf81f-4646-46da-9ea8-01d85fcd6387)


![image](https://github.com/user-attachments/assets/8742f6e9-1674-4afc-880f-ee3e62982200)


![image](https://github.com/user-attachments/assets/c46ea2c4-1f6e-41b3-ba56-57ba9c0ebc1e)


![image](https://github.com/user-attachments/assets/57557f72-366d-444e-86e9-539150cb8196)


![image](https://github.com/user-attachments/assets/870bf686-97ac-4d55-81ab-325317a79233)


# Payloads Commands Used

![image](https://github.com/user-attachments/assets/5bc90991-fed4-4039-acac-96ce2b7ed5c7)


![image](https://github.com/user-attachments/assets/7849795e-c5fe-4e01-b5a9-52336371161e)


![image](https://github.com/user-attachments/assets/efc50d7e-825b-49c3-bcb6-0de85806d206)


![image](https://github.com/user-attachments/assets/4936db3b-3075-4292-a965-5b000b7f1436)


---
## Created By:
- **Author Name**: Winston Hibbert
- **Author Contact**: www.linkedin.com/in/winston-hibbert-262a44271/
- **Date**: May 12, 2025

---

## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | `May 12, 2025`  | `Winston Hibbert`   

