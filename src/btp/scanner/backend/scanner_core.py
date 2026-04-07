# backend/scanner_core.py
import subprocess
import xml.etree.ElementTree as ET
import pandas as pd
import datetime
import os
from typing import Any
from mapping import service_to_attack, normalize_vuln
import nvdlib

def _extract_cvss_fields(cve: Any) -> tuple[float | None, str]:
    cvss = None
    severity = "Unknown"

    for score_attr, sev_attr in [("v31score", "v31severity"), ("v30score", "v30severity"), ("v2score", "v2severity")]:
        s = getattr(cve, score_attr, None)
        sev = getattr(cve, sev_attr, None)
        if s is not None:
            cvss = float(s)
            severity = sev or severity
            break

    if cvss is None and hasattr(cve, "score") and isinstance(cve.score, (list, tuple)):
        if len(cve.score) > 2 and cve.score[2] is not None:
            cvss = float(cve.score[2])
        if len(cve.score) > 3 and cve.score[3]:
            severity = cve.score[3]

    return cvss, severity


def _candidate_rank(cve: Any, version_hint: str) -> tuple[float, float]:
    cvss, _ = _extract_cvss_fields(cve)
    cvss_value = cvss if cvss is not None else -1.0

    version_bonus = 0.0
    if version_hint:
        hint = version_hint.lower().strip()
        descriptions = getattr(cve, "descriptions", []) or []
        desc_text = " ".join(
            d.value.lower() for d in descriptions if hasattr(d, "value") and isinstance(d.value, str)
        )
        if hint and hint in desc_text:
            version_bonus = 0.5

    return cvss_value, version_bonus


def _search_nvd(api_key: str, **kwargs) -> list[Any]:
    search_kwargs = {**kwargs}
    if api_key:
        search_kwargs["key"] = api_key
        search_kwargs["delay"] = 1
    return nvdlib.searchCVE(**search_kwargs)


def get_nvd_info(product: str, version: str = None, cpe: str = None) -> dict:
    """Real CVSS + CVE from NVD (free tier)"""
    if (not product or product.lower() in ["unknown", "none", "", "nan"]) and not cpe:
        return {"CVE": "N/A", "CVSS": None, "Severity": "Unknown", "CVE_Count": 0}
    
    try:
        keyword = f"{product} {version or ''}".strip()
        api_key = os.getenv("NVD_API_KEY", "").strip()
        no_key_cpe_lookup = os.getenv("SECURESCOPE_NVD_ENABLE_CPE_NO_KEY", "false").strip().lower() == "true"
        if api_key:
            query_candidates = [keyword, str(product).strip(), str(product).strip().split()[0]]
            keyword_limit = 5
            cpe_limit = 10
        else:
            # Keeping no-key mode fast because NVD enforces longer delays per request.
            query_candidates = [keyword, str(product).strip()]
            keyword_limit = 2
            cpe_limit = 2
        seen = set()
        result_by_id: dict[str, Any] = {}

        if cpe and str(cpe).strip().startswith("cpe:/") and (api_key or no_key_cpe_lookup):
            cpe_results = _search_nvd(api_key, cpeName=str(cpe).strip(), limit=cpe_limit)
            for item in cpe_results:
                if getattr(item, "id", None):
                    result_by_id[item.id] = item

        for query in query_candidates:
            q = (query or "").strip()
            if not q or q.lower() in seen:
                continue
            seen.add(q.lower())

            keyword_results = _search_nvd(api_key, keywordSearch=q, limit=keyword_limit)
            for item in keyword_results:
                if getattr(item, "id", None):
                    result_by_id[item.id] = item
            if keyword_results:
                break

        results = list(result_by_id.values())
        
        if not results:
            return {"CVE": "N/A", "CVSS": None, "Severity": "Unknown", "CVE_Count": 0}
        
        cve = max(results, key=lambda item: _candidate_rank(item, version or ""))
        cvss, severity = _extract_cvss_fields(cve)
        
        return {
            "CVE": cve.id,
            "CVSS": round(cvss, 1) if cvss is not None else None,
            "Severity": severity,
            "CVE_Count": len(results)
        }
    except Exception:
        return {"CVE": "N/A", "CVSS": None, "Severity": "Unknown", "CVE_Count": 0}

def run_nmap(target: str, local: bool = False) -> str:
    """Run nmap - works on server or locally"""
    xml_path = f"data/raw/scan_{'local' if local else 'server'}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.xml"
    cmd = ["nmap", "-sV", "-p-", "-T4", "-oX", xml_path, target]
    subprocess.run(cmd, check=True)
    return xml_path

def parse_and_enrich(xml_path: str) -> list[dict]:
    """Shared parsing + NVD + remediation logic"""
    tree = ET.parse(xml_path)
    root = tree.getroot()
    rows = []

    for host in root.findall("host"):
        ip = host.find("address").get("addr")
        for port in host.findall(".//port"):
            state = port.find("state").get("state")
            if state != "open":
                continue

            service = port.find("service")
            svc = service.get("name") if service is not None else None
            product = service.get("product") if service is not None else None
            version = service.get("version") if service is not None else None
            cpe_node = service.find("cpe") if service is not None else None
            cpe = cpe_node.text.strip() if cpe_node is not None and cpe_node.text else None

            attack = service_to_attack(svc)
            vuln_raw = product if product else svc
            vuln = normalize_vuln(vuln_raw)

            nvd = get_nvd_info(product or svc, version, cpe)

            rows.append({
                "scan_timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
                "Host": ip,
                "Port": port.get("portid"),
                "Service": svc,
                "Product": product,
                "Version": version,
                "CPE": cpe,
                "Attack_Type": attack,
                "Security_Vulnerability_Type": vuln,
                "CVE": nvd["CVE"],
                "CVSS_Score": nvd["CVSS"],
                "NVD_Severity": nvd["Severity"],
                "Incident_Severity": nvd["Severity"] if nvd["Severity"] != "Unknown" else ("Medium" if any(x in str(vuln).lower() for x in ["apache", "mysql", "tomcat"]) else "Low")
            })

    df = pd.DataFrame(rows)
    return df.to_dict(orient="records")