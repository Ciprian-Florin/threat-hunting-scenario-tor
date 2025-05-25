<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/Ciprian-Florin/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

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

Searched for any file containing the string "tor" and discovered that the user "florinn" appears to have downloaded a TOR installer, performed actions that resulted in numerous TOR-related files being copied to the desktop, and created a file named tor-shopping-list.txt on the desktop. These events began at May 22, 2025 9:58:33 AM.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "threat-hunt-cip" 
| where InitiatingProcessAccountName == "florinn"
| where FileName contains "tor"
| where Timestamp >= datetime(May 22, 2025 9:58:33 AM)
| order by Timestamp desc 
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessAccountName
```
![1](https://github.com/user-attachments/assets/07f1656b-4403-4f06-9d4f-2bfd26d3d751)

---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any ProcessCommandLine entries containing the string "tor-browser-windows-x86_64-portable-14.5.2.exe". Based on the returned logs, at 2025-05-22T07:02:06.6128719Z, an employee on the "threat-hunt-cip" device executed the file from their Downloads folder using a command that initiated a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "threat-hunt-cip"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.2.exe"
| order by Timestamp desc 
```
![1](https://github.com/user-attachments/assets/14e5b690-ed9e-427e-82f7-5188ec81c3ef)

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "florinn" had opened the TOR browser. Evidence indicates that they did so at 2025-05-22T07:03:29.3647979Z. Several other instances of firefox.exe (TOR) and tor.exe were spawned afterward.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "threat-hunt-cip"
| where FileName in ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessAccountName, ProcessCommandLine
| order by Timestamp desc 
```
![222](https://github.com/user-attachments/assets/fa78e853-4294-409b-854f-97458171abfc)

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication that the TOR browser was used to establish a connection via any of the known TOR ports. On 2025-05-22T07:07:37.6796854Z, an employee using the device "threat-hunt-cip" successfully established a connection to the remote IP address 88.80.26.2 on port 9001. The connection was initiated by the process tor.exe, located at C:\Users\florinn\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe. There were also a few other connections to websites over port 443.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "threat-hunt-cip"
| where InitiatingProcessAccountName == "florinn"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| where RemotePort in ("9001", "9030","9040","9050", "9051", "9150", "80", "443")
| project Timestamp, DeviceName, InitiatingProcessAccountName,ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc 
```
![222](https://github.com/user-attachments/assets/bc16baf6-efa1-41af-a4d3-9115fe92df44)

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2025-05-22T06:58:33.6551133Z`
- **Event:** The user "florinn" downloaded a file named `tor-browser-windows-x86_64-portable-14.5.2.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** C:\Users\florinn\Downloads\tor-browser-windows-x86_64-portable-14.5.2.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2025-05-22T07:02:06.6128719Z`
- **Event:** The user "florinn" executed the file `tor-browser-windows-x86_64-portable-14.5.2.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.5.2.exe  /S`
- **File Path:** `C:\Users\florinn\Downloads\tor-browser-windows-x86_64-portable-14.5.2.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-05-22T07:03:29.3647979Z`
- **Event:** User "florinn" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\florinn\Downloads\tor-browser-windows-x86_64-portable-14.5.2.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2025-05-22T07:07:37.6796854Z`
- **Event:** A network connection to IP `88.80.26.2`on port `9001` by user "florinn" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\florinn\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `May 22, 2025 10:08:07 AM` - Connected to `185.177.126.118` on port `443`.
  - May 22, 2025 10:04:09 AM` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "florinn" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `May 22, 2025 10:31:37 AM`
- **Event:** The user "florinn" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\florinn\Desktop\tor-shopping-list.txt`

---

## Summary

The user "florinn" on the "threat-hunt-cip" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `threat-hunt-cip` by the user `florinn`. The device was isolated, and the user's direct manager was notified.

---
