# VulnHunter

An automated vulnerability scanner built with Python, integrating Nmap, Nikto, and WhatWeb to perform reconnaissance and vulnerability assessment on authorized targets.

---

## Overview

VulnHunter is a command-line tool designed to automate the reconnaissance phase of penetration testing. It combines multiple industry-standard tools into a single workflow, providing clean, colorized output with structured results.

Built and tested on **Kali Linux**, this tool follows the standard pentesting methodology: port scanning → service detection → web vulnerability scanning → reporting.

---

## Features

- **Port Scanning** — Detects open ports and running services using Nmap
- **Service Version Detection** — Identifies exact software versions
- **Web Vulnerability Scanning** — Runs Nikto against discovered HTTP/HTTPS services
- **Technology Fingerprinting** — Uses WhatWeb to identify web technologies
- **FTP Enumeration** — Checks for anonymous FTP access and vsftpd backdoors
- **Colorized Output** — Clean, readable results using the `rich` library
- **Modular Design** — Each scanner runs independently; easy to extend

---

## Tech Stack

| Component | Purpose |
|-----------|---------|
| Python 3 | Core language |
| python-nmap | Nmap integration |
| rich | Terminal formatting & colors |
| subprocess | Wrapper for Nikto & WhatWeb |
| Nmap | Port scanning & service detection |
| Nikto | Web server vulnerability scanner |
| WhatWeb | Web technology fingerprinting |
