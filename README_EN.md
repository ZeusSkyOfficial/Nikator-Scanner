# Nikator Scanner

[فارسی](README.md) | **English**

**SNI Finder • IP Finder • IP Scanner • IP Config**

A desktop toolkit for SNI, DNS, TCP, TLS, HTTP, IP reachability, and network configuration compatibility diagnostics.

Developed by **Nikator Team**  
Creator and support: [@Zeusskyofficial](https://t.me/Zeusskyofficial)

---

## Table of Contents

- [About](#about)
- [Features](#features)
- [Core Concepts](#core-concepts)
- [Running the Application](#running-the-application)
- [Usage Guide](#usage-guide)
- [Understanding Results](#understanding-results)
- [Settings and Data Storage](#settings-and-data-storage)
- [Exporting Results](#exporting-results)
- [Keyboard Shortcuts](#keyboard-shortcuts)
- [Building the Windows Executable](#building-the-windows-executable)
- [Troubleshooting](#troubleshooting)
- [Privacy and Responsible Use](#privacy-and-responsible-use)

---

## About

**Nikator Scanner** is a graphical toolkit for diagnosing network connections step by step. It helps identify the exact stage at which a connection fails:

1. Resolving a domain to an IP address through DNS
2. Establishing a TCP connection to the destination port
3. Performing a TLS handshake and inspecting the security certificate
4. Receiving an HTTP or HTTPS response

The application is intended for network administrators, developers, security researchers, and users who need detailed information about the status of a domain, SNI, IP address, or service.

The interface is built with **PySide6**, while scanning operations run in background workers so the UI remains responsive when multiple targets are being checked.

---

## Features

### SNI Scanning and Subdomain Discovery

- Accepts a root domain and builds a list of SNI candidates
- Uses a built-in subdomain dataset
- Supports custom user-provided wordlists
- Collects public names from Certificate Transparency through `crt.sh`
- Tests DNS, TCP, TLS, and HTTP independently
- Displays live statistics, success rate, and average latency
- Shows X.509 certificate details, issuer, SAN entries, validity dates, and cipher information

### Network Configuration Testing

- Safely identifies destinations in formats such as `vless://`, `vmess://`, `trojan://`, `ss://`, and `https://`
- Supports plain text and common JSON or YAML structures
- Extracts the host, port, and SNI without executing configuration content
- Checks DNS, TCP, and TLS for extracted destinations
- Generates a configuration using a verified IP when the format is supported

### IP Reachability Testing

- Supports IPv4 and IPv6
- Accepts multiple IP addresses directly or imports TXT/CSV files
- Tests ports, TLS, and response time
- Helps distinguish local network failures from remote service failures

### SNI Compatibility Testing

- Tests multiple SNI values against a selected IP address or front
- Verifies whether the certificate matches the requested SNI
- Supports SAN and wildcard certificate matching
- Compares different cases for compatibility research

### History and Reports

- Saves scan sessions in SQLite
- Searches and displays detailed results from previous sessions
- Deletes selected sessions or clears the complete history
- Exports results as JSON, CSV, or TXT

---

## Core Concepts

| Stage | What is tested? | Example failure |
|---|---|---|
| DNS | Can the domain be resolved to an IP address? | The domain does not exist or the resolver does not respond |
| TCP | Can a connection be established to the IP and port? | Closed port, timeout, or firewall restriction |
| TLS | Can an encrypted connection be established? | Incorrect SNI, invalid certificate, or incompatible TLS version |
| HTTP | Does the web service return a response? | 4xx/5xx status, redirect, or no response |

### What Is SNI?

SNI, or **Server Name Indication**, is the domain name sent to a server when a TLS handshake begins. When several domains share one IP address, the server uses SNI to select the correct service and certificate.

### Successful Connection vs. Matching Certificate

A TLS handshake can succeed even when the returned certificate was not issued for the requested SNI. In that case, the technical connection is available, but the domain identity is not verified. Nikator Scanner displays these two conditions separately.

---

## Running the Application

**Nikator Scanner is portable and does not require installation.**

1. Download the application file.
2. If it is inside a ZIP archive, extract the archive completely.
3. Double-click `NikatorScanner.exe`.
4. The application opens directly. No setup process, Python installation, or separate library installation is required.

---

## Usage Guide

### 1. Domain and SNI Scan

1. Open the SNI Scanner page from the sidebar.
2. Enter the domain without `https://` or an additional path; for example, `example.com`.
3. Select the candidate source: the built-in dataset, CT Logs, or a custom wordlist.
4. Adjust the timeout, retry count, and concurrency for your network conditions.
5. Start the scan and follow the live statistics.
6. Select a row to inspect its DNS, TCP, TLS, certificate, and HTTP details.

Start with moderate concurrency. A very high value can trigger rate limits, increase resource usage, or produce unstable results.

### 2. Configuration Test

1. Open the Configuration Tester page.
2. Paste configurations into the input field or import a file.
3. Review the destinations extracted by the parser.
4. Run the test to check DNS, TCP, and TLS for each destination.
5. When supported, copy a generated version of the configuration using a selected IP address.

> A real configuration may contain a UUID, password, or access credentials. Never publish it in an issue, screenshot, public file, or shared export.

### 3. IP Test

1. On the IP Tester page, enter one IP address per line.
2. Select the required port. HTTPS services commonly use port `443`.
3. Provide an appropriate SNI value when testing TLS.
4. Review or export the connection and latency results.

Example input:

```text
1.1.1.1
8.8.8.8
```

### 4. SNI Compatibility Test

1. Enter the target IP address or front.
2. Select SNI values from user input or the public dataset.
3. Start the scan.
4. Check the certificate-match column. A successful handshake alone does not guarantee that the certificate matches the requested domain.

### 5. Viewing History

The History page displays previous scan sessions. You can:

- Review the results of a session
- Search for or delete sessions
- Export the selected results to a file

---

## Understanding Results

| Status | Meaning |
|---|---|
| Success | The required stages for the selected test completed successfully |
| Failed | One or more stages failed; open the row details for more information |
| Timeout | The destination did not respond within the configured time |
| DNS Error | The domain could not be resolved or the resolver was unavailable |
| TCP Error | A connection to the IP address and port could not be established |
| TLS Error | The TLS handshake, certificate, or SNI is invalid or incompatible |

Test results depend on current network conditions. For a more reliable diagnosis, repeat the test at different times and, when appropriate, use another DNS resolver.

---

## Settings and Data Storage

User settings are stored locally at:

```text
~/.nikator_scanner/config.json
```

Scan history is stored at:

```text
~/.nikator_scanner/history.db
```

When logging is enabled, log files are stored at:

```text
~/.nikator_scanner/logs/nikator_scanner.log
```

The Settings page provides controls for:

- DNS, TCP, TLS, and HTTP timeouts
- Custom DNS resolvers
- Worker count and retry count
- Delay between requests
- Font size and compact table mode
- Logging level and history retention period
- Default export directory

---

## Exporting Results

### JSON

Best suited for programmatic processing, structured archives, and integration with other tools.

### CSV

Best suited for Excel, Google Sheets, and table-based analysis.

### TXT

Best suited for direct reading, simple reports, and text archives.

Before sharing an export, review its host, IP address, SNI, certificate, and other infrastructure information.

---

## Keyboard Shortcuts

| Shortcut | Action |
|---|---|
| `Ctrl + C` | Copy selected rows |
| `Ctrl + A` | Select all rows |
| `Ctrl + F` | Focus the search field |
| `Ctrl + S` | Quickly export results |
| `F5` | Retry failed targets |
| `Escape` | Close the active window or dialog |

---

## Building the Windows Executable

Install PyInstaller:

```bash
python -m pip install pyinstaller
```

Build the project with the provided spec file:

```bash
pyinstaller pyinstaller.spec
```

The executable is generated at:

```text
dist/NikatorScanner.exe
```

---

## Troubleshooting

### The Application Does Not Open

- Do not run the application directly from inside the ZIP archive. Extract all files first.
- Check whether your antivirus has quarantined the file.
- Download the latest official release again.
- Try running the application once with **Run as administrator**.

### Windows SmartScreen Warning

If you downloaded the file from the official project page, select **More info** and then **Run anyway**. Never run a file obtained from an unknown source.

### Frequent Timeouts or Unstable Results

- Reduce concurrency.
- Increase the timeout slightly.
- Select another DNS resolver.
- Check your internet connection and firewall restrictions.

### TLS Error or Certificate Mismatch

- Verify the SNI value.
- Check the system date and time.
- Make sure the destination port actually provides TLS.
- Inspect the Subject and SAN fields in the certificate details.

---

## Privacy and Responsible Use

- Nikator Scanner is designed for network diagnostics, DNS inspection, and TLS compatibility evaluation.
- Only test systems that you own or have explicit permission to assess.
- The application is not designed for exploitation, unauthorized access, or bypassing access controls.
- Configurations, scan history, and exports may contain sensitive infrastructure details. Review them before sharing.
- Local databases, logs, exports, virtual environments, and keys are excluded from the repository through `.gitignore`.
- A local pre-commit guard also checks for common token and key patterns.

---

## Project Structure

```text
nikator-scanner/
├── data/          # Public datasets
├── database/      # SQLite history management
├── models/        # Data and result models
├── network/       # DNS, TCP, TLS, and HTTP modules
├── parsers/       # Safe configuration parsing
├── scanners/      # Scanning engines
├── ui/            # PySide6 graphical interface
├── utils/         # Settings, exports, and helper utilities
├── main.py        # Application entry point
└── requirements.txt
```

---

## Support

When reporting a problem, include an error description, your operating system, the application version, and the steps required to reproduce the issue. Never include sensitive information, tokens, or real configurations in a public report.

Creator and support on Telegram: [@Zeusskyofficial](https://t.me/Zeusskyofficial)

---

## Usage Rights

All rights to this project are reserved by **Nikator Team**. The repository currently has no separate license file; therefore, reuse, redistribution, or derivative works require permission from the project owner.
