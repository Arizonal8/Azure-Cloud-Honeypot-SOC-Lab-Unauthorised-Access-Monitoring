# 🛡️ Azure Cloud Honeypot & SOC Lab — Unauthorised Access Monitoring

> A hands-on Security Operations Centre (SOC) simulation built on Microsoft Azure. A deliberately exposed Windows VM honeypot was deployed to attract real-world brute-force attacks, with all activity captured and analysed through Microsoft Sentinel (SIEM), Log Analytics, and a geo-mapped attack dashboard.

---

## 📐 Architecture

([Azure Honeypot Architecture Diagram](https://github.com/Arizonal8/Azure-Cloud-Honeypot-SOC-Lab-Unauthorised-Access-Monitoring/raw/main/diagram-export-4-6-2026-3_41_44-PM.png))

The diagram above illustrates the full data flow: attackers from the public internet attempt to breach the exposed VM through a permissive NSG, the VM forwards security events to a Log Analytics Workspace, and Microsoft Sentinel enriches and visualises the data via a GeoIP watchlist and KQL-powered attack map.

---

## 🗂️ Table of Contents

- [Project Overview](#project-overview)
- [Tools & Services Used](#tools--services-used)
- [Infrastructure Setup](#infrastructure-setup)
- [Key Findings](#key-findings)
- [Attack Data Analysis](#attack-data-analysis)
- [Sentinel & Watchlist Configuration](#sentinel--watchlist-configuration)
- [Attack Map](#attack-map)
- [Architectural Diagram Prompt](#architectural-diagram-prompt)
- [Lessons Learned](#lessons-learned)

---

## 📌 Project Overview

This project simulates a real-world SOC analyst workflow by:

1. Deploying a Windows 11 VM on Azure with all firewall protections intentionally disabled
2. Configuring a Network Security Group (NSG) rule (`Danger_All_access`, Priority 100) to allow inbound traffic from any source on any port
3. Disabling Windows Defender Firewall on Domain, Private, and Public profiles
4. Installing the **AzureMonitorWindowsAgent** to forward security events to a Log Analytics Workspace
5. Ingesting a GeoIP database (55K entries) into Microsoft Sentinel as a Watchlist
6. Writing KQL queries to join failed login events with geolocation data
7. Rendering an interactive attack map showing attacker origins worldwide

The honeypot was live on **6 April 2026** and attracted real brute-force attacks within minutes of the firewall being disabled.

---

## 🧰 Tools & Services Used

### Cloud Platform

| Service | Purpose |
|---|---|
| **Microsoft Azure** | Cloud infrastructure provider |
| **Azure Virtual Machine** (Windows 11) | Honeypot target — `SOC-LabTest-RG` |
| **Azure Virtual Network** (`VN_SOC_Lab`) | Network isolation container |
| **Azure Network Security Group (NSG)** | Deliberately misconfigured to allow all inbound traffic |
| **Azure Public IP** (`SOC-LabTest-RG-ip`) | Exposed public endpoint (`20.108.28.87`) |
| **Azure Log Analytics Workspace** (`LogAnalyticsWorkspaceSOC`) | Central log aggregation |
| **Azure Data Collection Rule** (`DCR_Win_SOC`) | Routes VM security events to the workspace |
| **AzureMonitorWindowsAgent** v1.41.0.0 | VM extension that ships Windows Security events to Log Analytics |
| **Microsoft Sentinel** (SIEM) | Threat detection, watchlist management, and attack visualisation |
| **Azure Workbook** | Hosts the interactive Windows VM Attack Map |
| **Microsoft Defender for Cloud** | Asset inventory and posture monitoring |

### Query & Analysis

| Tool | Purpose |
|---|---|
| **KQL (Kusto Query Language)** | Querying `SecurityEvent` table for Event ID 4625 (failed logins) |
| **Sentinel Watchlist** (`geoip`) | 54,803-row GeoIP database for IP-to-location enrichment |
| **Advanced Hunting** | Validating watchlist ingestion via `_GetWatchlist('geoip')` |

### Local / Client Tools

| Tool | Purpose |
|---|---|
| **Linux (Ubuntu — `arinze-Latitude-5420`)** | Local workstation used to manage the lab, run terminal commands, and ping the VM |
| **Remmina Remote Desktop Client** | Used to connect to the Windows VM via RDP from the Linux workstation |
| **Windows Event Viewer** | Inspected raw Security logs directly on the VM (Event ID 4625, 4624, 4672) |
| **Windows Defender Firewall (Advanced Security)** | Deliberately disabled on all profiles to expose the VM |

---

## 🏗️ Infrastructure Setup

### Resource Group: `RG-SOC-LAB-APRIL` (UK South)

| Resource | Type |
|---|---|
| `SOC-LabTest-RG` | Virtual Machine (Windows 11) |
| `SOC-LabTest-RG-ip` | Public IP Address |
| `SOC-LabTest-RG-nsg` | Network Security Group |
| `soc-labtest-rg282_z1` | Network Interface |
| `SOC-LabTest-RG_OsDisk_1_...` | Managed Disk |
| `VN_SOC_Lab` | Virtual Network |
| `LogAnalyticsWorkspaceSOC` | Log Analytics Workspace |
| `DCR_Win_SOC` | Data Collection Rule |
| `SecurityInsights(loganalyticsworkspacesoc)` | Sentinel Solution |
| `88c296e6-... (Virtual M attack Map)` | Azure Workbook |

### NSG Inbound Rules

| Priority | Rule Name | Port | Protocol | Source | Action |
|---|---|---|---|---|---|
| **100** | `Danger_All_access` ⚠️ | Any | Any | Any | **Allow** |
| 65000 | AllowVnetInBound | Any | Any | VirtualNetwork | Allow |
| 65001 | AllowAzureLoadBalancerInBound | Any | Any | AzureLoadBalancer | Allow |
| 65500 | DenyAllInBound | Any | Any | Any | Deny |

> ⚠️ Priority 100 `Danger_All_access` overrides the default deny rule, exposing the VM to the entire internet.

---

## 🔑 Key Findings

### Brute-Force Attack Volume

From the **1,000 security events** captured in the query export (window: 6 April 2026, ~07:00–09:00 UTC):

- **969 out of 1,000 events (96.9%) were failed login attempts** (Event ID 4625)
- Only **31 events** were legitimate system logons or privilege assignments
- Attacks began within **minutes** of the firewall being disabled

### Attacker IPs

| IP Address | Failed Attempts | Notes |
|---|---|---|
| `185.156.73.74` | **491** | Primary attacker |
| `185.156.73.169` | **478** | Secondary attacker — adjacent IP, likely same threat actor |
| `5.151.212.211` | Simulated | Lab-controlled test from local Linux workstation |

Both primary IPs are closely adjacent, suggesting an automated credential-stuffing campaign from the same infrastructure.

### Top Usernames Targeted (Credential Stuffing)

| Username | Attempts |
|---|---|
| `administrator` | 58 |
| `admin` | 21 |
| `user` | 13 |
| `test` | 12 |
| `administrador` | 8 |
| `user1` | 8 |
| `user2` | 7 |
| `backup` | 4 |
| `testuser` | 4 |
| `teste` | 4 |

> This pattern is characteristic of automated credential-stuffing tools that cycle through common default username dictionaries.

### Geographic Origin (from Sentinel Attack Map)

| Location | Failed Logins |
|---|---|
| **Jordanow, Poland** | ~47,700 (dominant red cluster) |
| Mumbai, India | 1 |

Attacks were overwhelmingly concentrated from a single Eastern European source.

### Authentication Method

All brute-force attempts used **NTLM authentication** over **Logon Type 3 (Network)**, via `NtLmSsp` — consistent with automated RDP/SMB credential-stuffing tools.

### Simulated Attack (Lab-Controlled)

A manual unauthorised login attempt was also simulated from the local Linux workstation (`arinze-Latitude-5420`, IP `5.151.212.211`) using Remmina, generating Event ID 4625 with account name `Arizay`. This was visible in Windows Event Viewer and confirmed in Sentinel logs.

---

## 📊 Attack Data Analysis

The `query_data.csv` contains 1,000 rows exported from the `SecurityEvent` table in Log Analytics. Key event IDs observed:

| Event ID | Description | Count |
|---|---|---|
| **4625** | An account failed to log on | **969** |
| 4624 | An account was successfully logged on | ~15 |
| 4672 | Special privileges assigned to new logon | ~10 |
| 5379 | Credential Manager credentials were read | ~6 |

The overwhelming dominance of Event ID 4625 confirms the VM was under active, sustained brute-force attack throughout the monitoring window.

---

## 🗺️ Sentinel & Watchlist Configuration

### Watchlist: `geoip`

- **Source file:** `geoip-summarized.csv`
- **Total rows:** 54,803
- **SearchKey:** `network` (CIDR block)
- **Fields:** `network`, `latitude`, `longitude`, `cityname`, `countryname`
- **Status:** Succeeded ✅
- **Ingested:** 6 April 2026, 10:34 AM

### KQL Query (Attack Map)

```kql
let GeoIPDB_FULL = _GetWatchlist("geoip");
let WindowsEvents = SecurityEvent;
WindowsEvents | where EventID == 4625
| order by TimeGenerated desc
| evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network)
| summarize FailureCount = count() by IpAddress, latitude, longitude, cityname, countryname
| project FailureCount, AttackerIp = IpAddress, latitude, longitude,
  city = cityname, country = countryname,
  friendly_location = strcat(cityname, " (", countryname, ")");
```

This query:
1. Loads the full GeoIP watchlist
2. Filters Security Events for failed logins (Event ID 4625)
3. Performs an IPv4 lookup to match attacker IPs to geographic locations
4. Summarises by IP and location
5. Outputs to the Azure Workbook map visualisation (heatmap: green → red)

---

## 🌍 Attack Map

The attack map was built as an **Azure Workbook** using a `Map` visualisation with heatmap colouring (green → red by `FailureCount`). The large red bubble over Poland represents the dominant attack cluster (~47,700 failed login attempts from Jordanow).

---

## 📚 Lessons Learned

- Exposed RDP/SMB services on public IPs are discovered and attacked **within minutes**, not hours — internet-facing honeypots receive real traffic almost immediately
- Attackers use fully automated credential-stuffing with standard username dictionaries (`administrator`, `admin`, `user`, `test`) — default credentials remain the most targeted attack vector
- Two closely adjacent IPs (`185.156.73.74` and `185.156.73.169`) generating nearly equal volumes of attacks suggests a coordinated, scripted campaign from the same threat actor
- Microsoft Sentinel's GeoIP watchlist + KQL `ipv4_lookup` function provides powerful, scalable threat geolocation with no third-party tooling
- NTLM over Network Logon (Type 3) is the dominant protocol used in RDP brute-force attacks against exposed Windows targets
- The **AzureMonitorWindowsAgent** provides seamless telemetry forwarding from a VM to a SIEM with minimal configuration overhead
- NSG rules must always follow a deny-by-default model — a single high-priority allow-all rule completely negates all downstream deny rules

---

## ⚠️ Disclaimer

This lab was conducted in a controlled, sandboxed Azure environment for educational and research purposes only. The VM was intentionally misconfigured to attract attacks. **This configuration should never be replicated in production environments.** All resources were created in an isolated subscription and resource group and should be torn down after the lab.

---

*Lab conducted: 6 April 2026 | Azure Region: UK South | Author: Arinze Ihekweme*
