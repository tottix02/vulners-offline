#!/usr/bin/env python3
import os
import json
import zipfile
import argparse
import requests
from datetime import datetime, timedelta
try:
    from tqdm import tqdm
except Exception:
    # Fallback when tqdm isn't installed; iterate without progress bar
    def tqdm(iterable, **kwargs):
        return iterable

## MAKE SURE TO PROVIDE YOUR API KEY here!!!!!!
API_KEY = "FAKE_API_KEY_REPLACE_ME"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
START_YEAR = 2002
CURRENT_YEAR = datetime.now().year
CACHE_FILE = "nvd_cves.json"

LUA_FILE = "cve_data.lua"
NSE_FILE = "vulners-offline.nse"
ZIP_FILE = "offline_vulners_bundle.zip"
ZIP_PASSWORD = b"infected"

DAYS_PER_REQUEST = 120

###############################################################################
# UTILITIES
###############################################################################

def cpe23_to_cpe22(cpe):
    """
    Convert a 2.3 CPE to the format Nmap expects.
    Example:
       cpe:2.3:a:microsoft:sql_server_2022:*:*:*:*:*:*:x64:*
    becomes:
       cpe:/a:microsoft:sql_server_2022:*
    """
    parts = cpe.split(":")
    if len(parts) < 6:
        return None
    return f"cpe:/{parts[2]}:{parts[3]}:{parts[4]}:{parts[5]}"


def extract_product_version_from_cpe23(cpe):
    """
    Normalize SQL Server's weird naming:
       sql_server_2022, sql_server_2019

    Returns (product, version)
    """
    parts = cpe.split(":")
    if len(parts) < 6:
        return None, None

    raw_product = parts[4].lower()
    raw_version = parts[5].lower()

    # SQL Server special case:
    #      sql_server_2022:*:*:*    → product "sql_server", version "2022"
    if raw_product.startswith("sql_server_"):
        return "sql_server", raw_product.replace("sql_server_", "")

    return raw_product, raw_version


def fetch_cves(start, end):
    headers = {"apiKey": API_KEY, "Accept": "application/json"}
    params = {
        "pubStartDate": start.strftime("%Y-%m-%dT00:00:00.000Z"),
        "pubEndDate": end.strftime("%Y-%m-%dT23:59:59.999Z"),
        "resultsPerPage": 2000,
    }

    all_items = []
    idx = 0

    while True:
        params["startIndex"] = idx
        r = requests.get(NVD_URL, headers=headers, params=params)

        if r.status_code != 200:
            print(f"[-] Error HTTP {r.status_code}")
            break

        data = r.json()
        items = data.get("vulnerabilities", [])
        all_items.extend(items)

        if len(items) < 2000:
            break

        idx += 2000

    return all_items


def generate_date_ranges(year):
    start = datetime(year, 1, 1)
    end = datetime(year, 12, 31)

    while start <= end:
        slice_end = min(start + timedelta(days=DAYS_PER_REQUEST - 1), end)
        yield start, slice_end
        start = slice_end + timedelta(days=1)


def normalize_product_token(raw):
    """
    Normalize product strings into tokens used for product_index keys.
    Lowercase, replace spaces/dashes with underscores and map common
    aliases (e.g. apache/httpd -> http_server).
    """
    if not raw:
        return raw
    tok = raw.lower().replace(" ", "_").replace("-", "_")

    # Common explicit aliases and substring matches
    aliases = {
        "http_server": ["apache", "httpd"],
        "nginx": ["nginx"],
        "sql_server": ["sql_server", "microsoft_sql", "microsoft_sql_server"],
        "mysql": ["mysql"],
        "openssl": ["openssl", "open_ssl"],
        "php": ["php"],
        "postgresql": ["postgresql", "postgres"],
    }

    for token, keys in aliases.items():
        for k in keys:
            if k in tok:
                return token

    return tok


###############################################################################
# EXPLOIT DETECTION
###############################################################################

def check_exploit_vulners(cve_id):
    """
    Check if a CVE has a known exploit.
    This checks ExploitDB and Metasploit databases.
    Returns True if an exploit is available, False otherwise.
    """
    try:
        # Try ExploitDB API
        url = "https://www.exploit-db.com/api/search"
        params = {"cve": cve_id}
        r = requests.get(url, params=params, timeout=3)
        
        if r.status_code == 200:
            try:
                data = r.json()
                results = data.get("results", [])
                if isinstance(results, list) and len(results) > 0:
                    return True
            except:
                pass
                
        return False
    except Exception:
        # Network timeout or error - fail silently
        return False


def enrich_with_exploits(normalized_data, sample_check=True):
    """
    Enrich normalized CVE data with exploit information.
    If sample_check is True, only checks a sample to save time.
    If it fails/times out, silently continues without exploit data.
    """
    try:
        exploit_count = 0
        cve_count = 0
        
        # Collect all unique CVE IDs
        cve_ids = set()
        for cpe_list in normalized_data["cpe"].values():
            for entry in cpe_list:
                cve_ids.add(entry["id"])
        
        cve_ids = sorted(list(cve_ids))
        
        if sample_check:
            # Check every Nth CVE to save API calls
            step = max(1, len(cve_ids) // 100)  # Sample ~100 CVEs
            cves_to_check = cve_ids[::step]
        else:
            cves_to_check = cve_ids
        
        print(f"[*] Checking {len(cves_to_check)} CVEs for exploit availability...")
        
        # Map checked results back to all instances
        exploit_cache = {}
        for cve_id in cves_to_check:
            has_exploit = check_exploit_vulners(cve_id)
            exploit_cache[cve_id] = has_exploit
            if has_exploit:
                exploit_count += 1
        
        # Apply to all CPE entries
        for cpe_list in normalized_data["cpe"].values():
            for entry in cpe_list:
                if entry["id"] in exploit_cache and exploit_cache[entry["id"]]:
                    entry["is_exploit"] = True
        
        print(f"[*] Exploit check complete: found {exploit_count} CVEs with known exploits (from {len(cves_to_check)} checked)")
        
    except Exception as e:
        print(f"[!] Exploit enrichment skipped ({e})")
    
    return normalized_data


###############################################################################
# NORMALIZATION
###############################################################################

def normalize_cves(raw):
    data = {
        "cpe": {},
        "product": {}
    }

    # track seen IDs per cpe and per product/version to avoid duplicates
    seen_cpe = {}
    seen_product_version = {}

    for item in tqdm(raw, desc="Normalizing CVEs"):
        try:
            cve = item.get("cve")
            if not cve:
                continue
            
            cve_id = cve.get("id")
            if not cve_id:
                continue

            # Extract CVSS score, trying multiple versions
            cvss = None
            metrics = cve.get("metrics", {})
            for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if key in metrics and metrics[key]:
                    try:
                        cvss = float(metrics[key][0]["cvssData"]["baseScore"])
                        break
                    except (KeyError, IndexError, ValueError, TypeError):
                        continue

            # Ensure cvss is a valid float
            if cvss is None or not isinstance(cvss, (int, float)):
                cvss = 0.0
            else:
                cvss = float(cvss)

            entry = {
                "id": cve_id,
                "cvss": cvss,
                "type": "cve",
                "is_exploit": False
            }

            configurations = cve.get("configurations", [])
            for config in configurations:
                if not isinstance(config, dict):
                    continue
                    
                for node in config.get("nodes", []):
                    if not isinstance(node, dict):
                        continue
                        
                    for match in node.get("cpeMatch", []):
                        if not isinstance(match, dict) or not match.get("vulnerable"):
                            continue

                        cpe23 = match.get("criteria")
                        if not cpe23 or not isinstance(cpe23, str):
                            continue

                        # Convert CPE 2.3 to 2.2 format
                        cpe22 = cpe23_to_cpe22(cpe23)
                        if cpe22:
                            # dedupe entries per CPE
                            lst = data["cpe"].setdefault(cpe22, [])
                            sc = seen_cpe.setdefault(cpe22, set())
                            if entry["id"] not in sc:
                                lst.append(entry.copy())
                                sc.add(entry["id"])

                        # Extract product and version from CPE
                        product, version = extract_product_version_from_cpe23(cpe23)
                        if not product or not isinstance(product, str):
                            continue

                        # Determine version range for matching
                        vstart = match.get("versionStartIncluding") or match.get("versionStartExcluding")
                        vend = match.get("versionEndIncluding") or match.get("versionEndExcluding")

                        # Handle version determination
                        if version and version != "*" and version != "":
                            # Use explicit version from CPE
                            vrange = str(version)
                        else:
                            # Fallback to version ranges
                            if vstart and vend:
                                vrange = f"{vstart}-{vend}"
                            elif vstart:
                                vrange = f"{vstart}-*"
                            elif vend:
                                vrange = f"*-{vend}"
                            else:
                                vrange = "*"

                        # Normalize product token and store with deduplication
                        product_token = normalize_product_token(product)
                        if not product_token:
                            continue
                            
                        versions = data["product"].setdefault(product_token, {})
                        lst = versions.setdefault(vrange, [])
                        sp = seen_product_version.setdefault(product_token, {})
                        sv = sp.setdefault(vrange, set())
                        if entry["id"] not in sv:
                            lst.append(entry.copy())
                            sv.add(entry["id"])

        except Exception as e:
            continue

    return data


###############################################################################
# LUA OUTPUT
###############################################################################

def lua_escape(s):
    return s.replace("\\", "\\\\").replace('"', '\\"')


def write_lua_table(data):
    cpe_count = sum(len(vulns) for vulns in data["cpe"].values())
    product_count = sum(len(vulns) for versions in data["product"].values() for vulns in versions.values())
    
    with open(LUA_FILE, "w") as f:
        f.write("return {\n")

        # CPE MAP
        f.write("  cpe = {\n")
        for cpe, vulns in data["cpe"].items():
            if not vulns:
                continue
            f.write(f'    ["{lua_escape(cpe)}"] = {{\n')
            for v in vulns:
                # Validate entry has all required fields
                if not all(k in v for k in ["id", "cvss", "type", "is_exploit"]):
                    continue
                cvss_val = float(v["cvss"]) if isinstance(v["cvss"], (int, float)) else 0.0
                exploit_str = "true" if v.get("is_exploit") else "false"
                f.write(f'      {{ id="{lua_escape(v["id"])}", cvss={cvss_val}, type="{lua_escape(v["type"])}", is_exploit={exploit_str} }},\n')
            f.write("    },\n")
        f.write("  },\n\n")

        # PRODUCT MAP
        f.write("  product = {\n")
        for product, versions in data["product"].items():
            if not versions:
                continue
            f.write(f'    ["{lua_escape(product)}"] = {{\n')
            for version, vulns in versions.items():
                if not vulns:
                    continue
                f.write(f'      ["{lua_escape(version)}"] = {{\n')
                for v in vulns:
                    # Validate entry has all required fields
                    if not all(k in v for k in ["id", "cvss", "type", "is_exploit"]):
                        continue
                    cvss_val = float(v["cvss"]) if isinstance(v["cvss"], (int, float)) else 0.0
                    exploit_str = "true" if v.get("is_exploit") else "false"
                    f.write(f'        {{ id="{lua_escape(v["id"])}", cvss={cvss_val}, type="{lua_escape(v["type"])}", is_exploit={exploit_str} }},\n')
                f.write("      },\n")
            f.write("    },\n")
        f.write("  }\n")

        f.write("}\n")

    print(f"[+] Wrote Lua file → {LUA_FILE}")
    print(f"[+] CPE entries: {len(data['cpe'])} CPEs with {cpe_count} vulnerabilities")
    print(f"[+] Product entries: {len(data['product'])} products with {product_count} vulnerabilities")


###############################################################################
# ZIP
###############################################################################

def zip_bundle():
    # Validate that both files exist before creating the zip
    if not os.path.exists(LUA_FILE):
        print(f"[-] Error: {LUA_FILE} not found")
        raise FileNotFoundError(f"Required file not found: {LUA_FILE}")
    
    if not os.path.exists(NSE_FILE):
        print(f"[-] Error: {NSE_FILE} not found")
        raise FileNotFoundError(f"Required file not found: {NSE_FILE}")
    
    with zipfile.ZipFile(ZIP_FILE, "w", zipfile.ZIP_DEFLATED) as z:
        z.write(LUA_FILE)
        z.write(NSE_FILE)
        try:
            z.setpassword(ZIP_PASSWORD)
        except:
            pass

    print(f"[+] Created offline bundle → {ZIP_FILE}")


###############################################################################
# MAIN
###############################################################################

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--no-nvd-download", action="store_true")
    args = parser.parse_args()

    # load cached or download
    if args.no_nvd_download and os.path.exists(CACHE_FILE):
        print("[+] Loading cached CVEs")
        raw = json.load(open(CACHE_FILE))
    else:
        print("[*] Downloading from NVD API...")
        raw = []
        for year in range(START_YEAR, CURRENT_YEAR + 1):
            print(f"[+] Year {year}")
            for start, end in generate_date_ranges(year):
                raw.extend(fetch_cves(start, end))

        json.dump(raw, open(CACHE_FILE, "w"))
        print(f"[+] Saved {CACHE_FILE}")

    normalized = normalize_cves(raw)
    
    # Enrich with exploit data from Vulners
    print("[*] Enriching with exploit data...")
    normalized = enrich_with_exploits(normalized, sample_check=True)
    
    write_lua_table(normalized)
    zip_bundle()

    print("\n[✔] Offline database ready!")
    print("Run:")
    print("    nmap -sV --script=vulners-offline.nse <target>")


if __name__ == "__main__":
    main()
