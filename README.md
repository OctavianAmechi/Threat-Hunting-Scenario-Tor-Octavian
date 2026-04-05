# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/OctavianAmechi/Threat-Hunting-Scenario-Tor-Octavian/blob/main/Create%20Threat-Hunting-Scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Seached the DeviceFileEvents for Any file that had the string “tor” in it and discovered what looks like the user “OctaviamAmechi” downloaded a tor installer, did something that resulted in many tor-related files being copied to the desktop and the creation of a file called tor-shopping-list.txt on the desktop. These events began at:
(Apr 3, 2026 11:07:14 PM)


**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "threat-hunt-lab"
| where FileName contains "tor"
| where InitiatingProcessAccountName == "octaviamamechi"
| where Timestamp >= datetime(Apr 3, 2026 11:07:14 PM)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account =InitiatingProcessAccountName

```

<img width="1672" height="728" alt="image" src="https://github.com/user-attachments/assets/7552750f-8c8e-456b-a931-e4c108b41096" />

---

### 2. Searched the `DeviceProcessEvents` Table

Searched the DeviceProcessEvents table for any ProcessCommandLine that contained the string “
tor-browser-windows-x86_64-portable-15.0.8.exe”. Based on the logs returned, at 11:11:00 PM on April 3, 2026, an employee on the “threat-hunt-lab” device ran the file 
tor-browser-windows-x86_64-portable-15.0.8.exe from their Downloads folder, using a command that triggered a silent installation


**Query used to locate event:**

```kql

DeviceProcessEvents  
| where DeviceName == "threat-hunt-lab"  
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.0.1.exe"  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1680" height="463" alt="image" src="https://github.com/user-attachments/assets/128a4dbe-47db-4e00-8967-0606037ad0b9" />

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the DeviceProcessEvents table for any indication that user “OctaviamAmechi” actually opened the tor browser. There was evidence that they did open it at Apr 3, 2026 11:29:54. There were several other instances of firefox.exe (Tor) as well as tor.exe spawned afterwards

**Query used to locate events:**

```kql
DeviceProcessEvents  
| where DeviceName == "threat-hunt-lab"  
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine  
| order by Timestamp desc
```
<img width="1605" height="981" alt="image" src="https://github.com/user-attachments/assets/3514404f-688a-4089-b5c9-3be4495a236e" />

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched the DeviceNetworkEvents table for any indication the tor browser was to establish a connection using any of the known tor ports. On April 3, 2026 at 11:12:57 PM, the device threat-hunt-lab successfully made a network connection to the external IP address 148.251.85.195 over port 9030. The connection was initiated by the Tor executable (tor.exe) running under the user account octaviamamechi.There were a few other connections to sites over port 443

**Query used to locate events:**

```kql
DeviceNetworkEvents  
| where DeviceName == "threat-hunt-lab"  
| where InitiatingProcessAccountName != "system"  
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")  
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")  
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath  
| order by Timestamp desc
```
<img width="1681" height="805" alt="image" src="https://github.com/user-attachments/assets/748b4da8-86a3-4aa3-b657-43bafe0e4ed3" />

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `Apr 3, 2026 11:07:14 PM`
- **Event:** The user "octaviamamechi" downloaded a file named `tor-browser-windows-x86_64-portable-14.0.1.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\octaviamamechi\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `April 3, 2026 11:11:00 PM  `
- **Event:** The user "octaviamamechi" executed the file `tor-browser-windows-x86_64-portable-14.0.1.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.1.exe /S`
- **File Path:** `C:\Users\octaviamamechi\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `Apr 3, 2026 11:29:54`
- **Event:** User "employee" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\octaviamamechi\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `April 3, 2026 11:12:57 PM`
- **Event:** A network connection to IP `176.198.159.33` on port `9001` by user "octaviamamechi" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\octaviamamechi\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `April 3, 2026 11:11:50 PM` - Connected to `194.164.169.85` on port `443`.
  - `April 3, 2026 11:11:50 PM` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "octaviamamechi" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `April 3, 2026 11:38:30 PM`
- **Event:** The user "octaviamamechi" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\octaviamamechi\Desktop\tor-shopping-list.txt`

---

## Summary

The user "octaviamamechi" on the "threat-hunt-lab" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `threat-hunt-lab` by the user `employee`. The device was isolated, and the user's direct manager was notified.

---
