# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/cgmondejar/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

# Platforms and Languages Leveraged
- Windows 11 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

#  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

# High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

# Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched the DeviceFileEvents table for ANY file that had the string “tor” in it and discovered what looks like the user “cgm-admin” downloaded a tor installer, did something that resulted in many tor-related files being copied to the desktop and the creation of a file called “tor-shopping-list.txt” on the desktop at 2026-03-16T07:42:25.5841065Z. These events began at: 2026-03-16T07:30:24.8635504Z

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "cgm-threat-hunt"
| where InitiatingProcessAccountName == "cgm-admin"
| where FileName contains "tor"
| where Timestamp >= datetime(2026-03-16T07:30:24.8635504Z)
| order by Timestamp desc 
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1159" height="526" alt="image" src="https://github.com/user-attachments/assets/919ff476-e53d-4eb9-afbe-2f6b68082f71" />


---

### 2. Searched the `DeviceProcessEvents` Table

Searched the DeviceProcessEvents table for any ProcessCommandLine that contained the string “tor-browser-windows-x86_64-portable-15.0.7.exe
“. Based on the logs returned, at 2026-03-16T07:32:44.2883845Z, the administrator account cgm-admin on the computer cgm-threat-hunt launched a file named tor-browser-windows-x86_64-portable-15.0.7.exe from the Downloads folder, creating a new process on the system. The program was executed with the /S command-line switch, which typically indicates a silent installation, meaning the Tor Browser portable package was likely installed or extracted without showing installation prompts or user interaction.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "cgm-threat-hunt"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.7.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1450" height="176" alt="image" src="https://github.com/user-attachments/assets/1e1975fa-ebde-47ce-aac7-518b500f490d" />

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the DeviceProcessEvents table for any indication that user “cgm-admin” actually opened the tor browser. There was evidence that they did opened it at 2026-03-16T07:17:13.3312312Z. There were several other instances of firefox.exe (Tor) as well as tor.exe spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "cgm-threat-hunt"
| where FileName has_any ("tor.exe","firefox.exe","tor-browser-windows-x86_64-portable.exe","torbrowser-install-win64.exe","start-tor-browser.exe","identity_helper.exe","lyrebird.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```
<img width="1417" height="795" alt="image" src="https://github.com/user-attachments/assets/5d14a72d-2b38-4ee9-94f8-3ec0831662a5" />

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched the DeviceNetworkEvents table for any indication the tor browser was used to establish a connection using any of the known tor ports. At 2026-03-16T07:33:54.8555711Z, the administrator account (cgm-admin) on the computer cgm-threat-hunt successfully made an outbound network connection to the external IP address 145.239.1.9 on port 9001. The connection was initiated by tor.exe, running from the Tor Browser directory on the user’s desktop, and was associated with the URL https://www.m7ijj.com, indicating that the Tor client was continuing to communicate with nodes on the Tor network as part of establishing or maintaining its encrypted routing circuit. There were a couple other connections to sites over port 443.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "cgm-threat-hunt"
| where InitiatingProcessAccountName != "system"
| where InitiatingProcessFileName in ("tor.exe","firefox")
| where RemotePort in ("8443","9001","9030","9040","9050","9051","9150","9151","8118","80","443")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc
```
<img width="1587" height="332" alt="image" src="https://github.com/user-attachments/assets/3173a6de-9335-4de0-bfd8-7a4ec7911b95" />

---

# Chronological Events

## 1. Installer File Renamed
**Date/Time:** 16 Mar 2026 07:30:24  
**Description:** The Tor Browser installer file was renamed (likely from a temporary or download name to its final name).

| Field | Value |
|------|------|
| ActionType | FileRenamed |
| FileName | `tor-browser-windows-x86_64-portable-15.0.7.exe` |
| FolderPath | `C:\Users\CGM-admin\Downloads\tor-browser-windows-x86_64-portable-15.0.7.exe` |
| SHA256 | `958626901dbe17fc003ed671b61b3656375e6f0bc06c9dff60bd2f80d4ace21b` |

---

## 2. Installer File Created
**Date/Time:** 16 Mar 2026 07:30:27  
**Description:** The official Tor Browser portable installer (version 15.0.7) finished downloading and was saved to the **Downloads** folder.

| Field | Value |
|------|------|
| ActionType | FileCreated |
| FileName | `tor-browser-windows-x86_64-portable-15.0.7.exe` |
| FolderPath | `C:\Users\CGM-admin\Downloads\tor-browser-windows-x86_64-portable-15.0.7.exe` |
| SHA256 | `958626901dbe17fc003ed671b61b3656375e6f0bc06c9dff60bd2f80d4ace21b` |

---

## 3. Silent Installer Executed
**Date/Time:** 16 Mar 2026 07:32:44  
**Description:** The user executed the Tor Browser portable installer silently using the `/S` switch (no GUI prompts, automatic extraction to Desktop).

| Field | Value |
|------|------|
| ActionType | ProcessCreated |
| FileName | `tor-browser-windows-x86_64-portable-15.0.7.exe` |
| FolderPath | `C:\Users\CGM-admin\Downloads\tor-browser-windows-x86_64-portable-15.0.7.exe` |
| SHA256 | `958626901dbe17fc003ed671b61b3656375e6f0bc06c9dff60bd2f80d4ace21b` |
| CommandLine | `tor-browser-windows-x86_64-portable-15.0.7.exe /S` |

---

## 4. License Files Extracted
**Date/Time:** 16 Mar 2026 07:32:59  
**Description:** During extraction, three license text files for Tor components were created in the **Docs\Licenses** folder.

| File | Path |
|-----|------|
| tor.txt | `C:\Users\CGM-admin\Desktop\Tor Browser\Browser\TorBrowser\Docs\Licenses\tor.txt` |
| Torbutton.txt | `C:\Users\CGM-admin\Desktop\Tor Browser\Browser\TorBrowser\Docs\Licenses\Torbutton.txt` |
| Tor-Launcher.txt | `C:\Users\CGM-admin\Desktop\Tor Browser\Browser\TorBrowser\Docs\Licenses\Tor-Launcher.txt` |

---

## 5. Tor Executable Created
**Date/Time:** 16 Mar 2026 07:33:00  
**Description:** The core Tor executable was extracted and placed in the Tor Browser folder structure on the Desktop.

| Field | Value |
|------|------|
| ActionType | FileCreated |
| FileName | `tor.exe` |
| FolderPath | `C:\Users\CGM-admin\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe` |
| SHA256 | `5d7797c72d7eae405d6b2054d94c53494861eb1169d8a1b276775aa48dc94fd7` |

---

## 6. Desktop Shortcut Created
**Date/Time:** 16 Mar 2026 07:33:11  
**Description:** A shortcut to launch Tor Browser was created on the Desktop.

| Field | Value |
|------|------|
| ActionType | FileCreated |
| FileName | `Tor Browser.lnk` |
| FolderPath | `C:\Users\CGM-admin\Desktop\Tor Browser\Tor Browser.lnk` |

---

## 7. Profile Storage Files Created
**Date/Time:**  
- 16 Mar 2026 07:33:40  
- 16 Mar 2026 07:33:44  

**Description:** Tor Browser created its initial profile storage database files used for bookmarks, history, and settings.

| File | Path |
|-----|------|
| storage.sqlite | `...\profile.default\storage.sqlite` |
| storage-sync-v2.sqlite | `...\profile.default\storage-sync-v2.sqlite` |

---

## 8. First Tor Network Connection
**Date/Time:** 16 Mar 2026 07:33:50  
**Description:** Tor client began bootstrapping by connecting to a Tor relay on directory port **9001**.

| Field | Value |
|------|------|
| ActionType | ConnectionSuccess |
| Initiating Process | `tor.exe` |
| Remote Address | `89.191.217.1:9001` |
| URL | None |

---

## 9. Second Tor Network Connection
**Date/Time:** 16 Mar 2026 07:33:51  
**Description:** Tor continued bootstrapping and contacted another relay, associated with a `.com` domain (likely a bridge or directory mirror).

| Field | Value |
|------|------|
| ActionType | ConnectionSuccess |
| Initiating Process | `tor.exe` |
| Remote Address | `89.191.217.1:9001` |
| Associated URL | `https://www.hzi5b3mfrdnmo2u2o4flgorq.com` |

---

## 10. Multiple Tor Network Connections
**Date/Time:** 16 Mar 2026 07:33:54  
**Description:** Tor successfully established several connections to directory authorities and relays (including HTTPS and ORPort), indicating the Tor circuit was built and the browser became usable.

| Connection | Remote | URL |
|-----------|--------|-----|
| 1 | `145.239.1.9:9001` | None |
| 2 | `145.239.1.9:9001` | `https://www.m7ijj.com` |
| 3 | `212.132.125.165:443` | `https://www.h2bj7aj7.com` |
| 4 | `212.132.125.165:443` | None |

---

## 11. Shopping List File Created
**Date/Time:** 16 Mar 2026 07:42:25  
**Description:** A text file named **tor-shopping-list.txt** was created in the Documents folder and a shortcut was added to the **Recent items** folder.

| File | Path |
|-----|------|
| tor-shopping-list.txt | `C:\Users\CGM-admin\Documents\tor-shopping-list.txt` |
| tor-shopping-list.lnk | `...\Recent\tor-shopping-list.lnk` |

---

## 12. Shopping List File Renamed / Moved
**Date/Time:** 16 Mar 2026 07:43:10  
**Description:** The **tor-shopping-list.txt** file was moved or renamed to the Desktop.

| Field | Value |
|------|------|
| ActionType | FileRenamed |
| FileName | `tor-shopping-list.txt` |
| FolderPath | `C:\Users\CGM-admin\Desktop\tor-shopping-list.txt` |

---

# Summary

Between 07:30:24 and 07:43:10 on 16 March 2026, cgm-admin downloaded the official Tor Browser portable installer (v15.0.7), ran it silently (/S), which extracted the full package (tor.exe, profile files, licenses) to the Desktop. Tor.exe immediately launched and established multiple outbound Tor network connections on ports 9001 and 443. A “tor-shopping-list.txt” file was then created in Documents and moved to the Desktop. All activity was limited to this single account and directly related to Tor Browser download, installation, launch, and network use.

---

# Response Taken

TOR usage was confirmed on the endpoint `cgm-admin` by the user `cgm-threat-hunt`. The device was isolated, and the user's direct manager was notified.

---
