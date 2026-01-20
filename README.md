# Vulners Offline NSE Database Builder

This repository provides a way to build and use an **offline version of the popular Nmap NSE script `vulners`**.  
It allows vulnerability and exploit correlation **without any Internet access** by pre-downloading CVE data from NVD, enriching it with exploit availability, and packaging everything into a local Lua database that Nmap can query.

The project consists of two files:

- `build_nvd_bundle.py` – Downloads, normalizes, enriches, and packages CVE data.
- `vulners-offline.nse` – Offline-compatible replacement for the original `vulners.nse` script.

The final output is a password-protected ZIP bundle containing:
- `cve_data.lua` – Offline vulnerability database
- `vulners-offline.nse` – NSE script that consumes the offline database

---

## Features

- Full offline CVE database from NVD (2002 → present)
- CVSS v2 / v3.x parsing
- CPE 2.3 → CPE 2.2 conversion for Nmap compatibility
- Product & version normalization
- Exploit availability detection (Exploit-DB, Metasploit)
- Deduplication and performance-optimized Lua tables
- Password-protected portable bundle for field use

---

## Requirements

```bash
apt install python3-requests python3-tqdm
```

## Instructions

1. You must also obtain an NVD API key: https://nvd.nist.gov/developers/request-an-api-key

2. Edit the python script and replace with yout own API Key:
```python
API_KEY = "FAKE_API_KEY_REPLACE_ME"
```

3. Then build the bundle, this will create a password protected zip file. Default password is "infected", update as necessary. 
```bash
./build_nvd_bundle.py
```

4. Extract the zip file with 7-zip on the offline remote host.
```bash
7z x offline_vulners_bundle.zip
```

5. Run Nmap with the vulners-offline.nse
```bash
nmap -sV --script=vulners-offline.nse <target>
```

## Author
shr1mps
https://tottix.com
