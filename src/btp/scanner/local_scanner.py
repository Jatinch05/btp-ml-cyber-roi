# secure_scope_local_scanner.py
# FULLY STANDALONE - Works from Downloads folder once the user downloads the file

import subprocess
import xml.etree.ElementTree as ET
import datetime
import requests
import sys
import os
import shutil
import hashlib
from pathlib import Path

# ==================== COPIED MAPPING LOGIC ====================
ALIASES = {
    "msrpc": "microsoft windows rpc",
    "ms-wbt-server": "ms-wbt-server",
    "microsoft-ds": "microsoft-ds",
    "netbios-ssn": "netbios-ssn",
    "netbios-ns": "netbios-ns",
    "kestrel": "microsoft kestrel httpd",
    "tornado": "tornado httpd",
    "vmware-auth": "vmware authentication daemon",
}

SERVICE_MAPPING = {
    "http": "Web Exploit", "https": "Web Exploit", "apache": "Web Exploit",
    "nginx": "Web Exploit", "tomcat": "Web Exploit", "iis": "Web Exploit",
    "ssh": "SSH Brute Force", "rdp": "Remote Access Abuse",
    "ms-wbt-server": "Remote Access Abuse", "telnet": "Credential Sniffing",
    "smb": "Lateral Movement", "microsoft-ds": "Lateral Movement",
    "netbios": "Lateral Movement", "rpc": "Privilege Escalation",
    "msrpc": "Privilege Escalation", "mysql": "Database Attack",
}

def service_to_attack(service_name):
    if not service_name:
        return "Unknown"
    s = service_name.lower().strip()
    for key, attack in SERVICE_MAPPING.items():
        if key in s:
            return attack
    return "Unknown"

def normalize_vuln(name):
    if not name:
        return ""
    s = name.lower().strip()
    if s in ALIASES:
        return ALIASES[s]
    if "kestrel" in s:
        return "microsoft kestrel httpd"
    if "tornado" in s:
        return "tornado httpd"
    return s


def script_hash() -> str:
    with open(__file__, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest().lower()


def expected_hash() -> str:
    env_hash = os.getenv("SECURESCOPE_AGENT_SHA256", "").strip().lower()
    if env_hash:
        return env_hash

    checksum_path = Path(__file__).with_suffix(".py.sha256")
    if checksum_path.exists():
        content = checksum_path.read_text(encoding="utf-8").strip()
        if content:
            return content.split()[0].lower()

    return ""


def readiness_checks() -> list[str]:
    issues: list[str] = []

    if shutil.which("nmap") is None:
        issues.append("Nmap is not installed or not on PATH. Install Nmap and make sure 'nmap --version' works.")

    expected = expected_hash()
    if not expected:
        issues.append(
            "Checksum file is missing. Download secure_scope_local_scanner.py.sha256 and keep it next to the script, or set SECURESCOPE_AGENT_SHA256."
        )
    else:
        current = script_hash()
        if current != expected:
            issues.append(
                "Script checksum mismatch. Re-download the script and checksum together, then verify they match before running."
            )

    return issues

def print_readiness_result() -> bool:
    issues = readiness_checks()
    if issues:
        print("Readiness checks failed. Fix the following before continuing:")
        for issue in issues:
            print(f"- {issue}")
        return False

    print("Readiness checks passed.")
    return True


def choose_scan_mode() -> tuple[str, list[str]]:
    print("\nChoose scan mode:")
    print("  1) Fast scan - common ports only, intended to finish quickly")
    print("  2) Thorough scan - full port sweep with service detection")

    while True:
        choice = input("Select 1 or 2: ").strip().lower()
        if choice in {"1", "fast", "f"}:
            return "fast", ["nmap", "-Pn", "-F", "-sV", "-T4", "--max-retries", "1"]
        if choice in {"2", "thorough", "t"}:
            return "thorough", ["nmap", "-Pn", "-sV", "-p-", "-T4"]
        print("Please enter 1 for fast scan or 2 for thorough scan.")


def load_scan_timestamp() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

# ==================== MAIN SCANNER ====================
def main():
    print("=== SecureScope Standalone Local Agent ===")

    if not print_readiness_result():
        sys.exit(1)

    target = input("\nEnter target IP or hostname: ").strip()
    if not target:
        print("No target provided.")
        sys.exit(1)

    mode_name, cmd = choose_scan_mode()

    if mode_name == "fast":
        print(f"\nRunning fast scan against {target} ...")
    else:
        print(f"\nRunning thorough scan against {target} ... (this may take some time)")

    # Run nmap locally
    xml_path = f"scan_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.xml"
    cmd = cmd + ["-oX", xml_path, target]
    subprocess.run(cmd, check=True)

    # Parse XML
    tree = ET.parse(xml_path)
    root = tree.getroot()
    results = []

    for host in root.findall("host"):
        ip = host.find("address").get("addr")
        for port in host.findall(".//port"):
            if port.find("state").get("state") != "open":
                continue
            service = port.find("service")
            svc = service.get("name") if service is not None else None
            product = service.get("product") if service is not None else None
            version = service.get("version") if service is not None else None
            cpe_node = service.find("cpe") if service is not None else None
            cpe = cpe_node.text.strip() if cpe_node is not None and cpe_node.text else None

            results.append({
                "Host": ip,
                "Port": port.get("portid"),
                "Service": svc,
                "Product": product,
                "Version": version,
                "CPE": cpe,
                "scan_timestamp": load_scan_timestamp()
            })

    print(f"Found {len(results)} open ports. Sending to backend...")

    # Send to backend (external call)
    try:
        backend_url = os.getenv("SECURESCOPE_BACKEND_URL", "http://127.0.0.1:8000").strip().rstrip("/")
        api_key = os.getenv("SECURESCOPE_API_KEY", "").strip()
        timeout_seconds = int(os.getenv("SECURESCOPE_UPLOAD_TIMEOUT", "900"))
        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["X-API-Key"] = api_key

        r = requests.post(
            f"{backend_url}/upload_raw_scan",
            json=results,
            headers=headers,
            timeout=timeout_seconds
        )
        if r.status_code == 200:
            print("SUCCESS! Results sent to dashboard.")
        else:
            print("Backend error:", r.text)
    except requests.Timeout:
        print("Backend request timed out. Increase SECURESCOPE_UPLOAD_TIMEOUT and retry.")
    except Exception as e:
        print("Could not connect to backend. Is FastAPI running?")
        print(e)
    finally:
        try:
            os.remove(xml_path)
        except OSError:
            pass

if __name__ == "__main__":
    main()