from __future__ import annotations

import datetime as dt
import difflib
import hashlib
import os
import shutil
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pandas as pd

try:
    import nvdlib  # type: ignore
except Exception:  # pragma: no cover
    nvdlib = None

# Maps bare service names to well-known product names for better NVD hits.
SERVICE_PRODUCT_HINTS: dict[str, str] = {
    "ssh": "OpenSSH",
    "http": "Apache HTTP Server",
    "https": "Apache HTTP Server",
    "mysql": "MySQL",
    "postgres": "PostgreSQL",
    "mssql": "Microsoft SQL Server",
    "rdp": "Microsoft Remote Desktop",
    "ms-wbt-server": "Microsoft Remote Desktop",
    "smb": "Samba",
    "microsoft-ds": "Samba",
    "telnet": "linux telnetd",
    "ftp": "vsftpd",
    "vnc": "RealVNC",
    "dns": "ISC BIND",
    "domain": "ISC BIND",
    "smtp": "Postfix",
    "imap": "Dovecot",
    "pop3": "Dovecot",
    "redis": "Redis",
    "mongo": "MongoDB",
    "ldap": "OpenLDAP",
    "snmp": "Net-SNMP",
    "exec": "netkit-rsh rexecd",
    "login": "rlogind",
    "shell": "rshd",
    "java-rmi": "Java RMI",
    "rmiregistry": "Java RMI",
    "bindshell": "Metasploitable",
    "nfs": "NFS",
    "rpcbind": "rpcbind",
    "tcpwrapped": "tcpwrapper",
    "ajp13": "Apache Tomcat",
    "x11": "X.Org X11",
    "irc": "UnrealIRCd",
    "distccd": "distcc",
}

# Tracks the timestamp of the last NVD API call for free-tier pacing.
_last_nvd_call: float = 0.0
_NVD_FREE_TIER_DELAY: float = 6.5  # seconds between calls without API key


def _nvd_search_with_retry(max_retries: int = 3, **kwargs) -> list[Any]:
    """Call nvdlib.searchCVE with exponential backoff on rate-limit errors."""
    for attempt in range(max_retries):
        try:
            return list(nvdlib.searchCVE(**kwargs))
        except Exception as exc:
            msg = str(exc).lower()
            if "403" in msg or "rate" in msg or "limit" in msg:
                wait = 6 * (attempt + 1)
                print(f"[NVD] Rate limited, waiting {wait}s (attempt {attempt + 1}/{max_retries})")
                time.sleep(wait)
            else:
                raise
    return []

ROOT = Path(__file__).resolve().parents[2]
SCANNER_DIR = ROOT / "src" / "btp" / "scanner"
AGENT_SCRIPT_PATH = SCANNER_DIR / "local_scanner.py"
REMEDIATION_PATH = SCANNER_DIR / "backend" / "data" / "raw" / "remediation_tools.csv"
SCANNER_RESULTS_PATH = SCANNER_DIR / "backend" / "data" / "processed" / "scanner_mapped_with_controls.csv"

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
    "http": "Web Exploit",
    "https": "Web Exploit",
    "apache": "Web Exploit",
    "nginx": "Web Exploit",
    "tomcat": "Web Exploit",
    "iis": "Web Exploit",
    "ajp": "Web Exploit",
    "tornado": "Web Exploit",
    "kestrel": "Web Exploit",
    "ssh": "SSH Brute Force",
    "rdp": "Remote Access Abuse",
    "ms-wbt-server": "Remote Access Abuse",
    "telnet": "Credential Sniffing",
    "vnc": "Remote Access Abuse",
    "smb": "Lateral Movement",
    "microsoft-ds": "Lateral Movement",
    "netbios": "Lateral Movement",
    "rpc": "Privilege Escalation",
    "msrpc": "Privilege Escalation",
    "mysql": "Database Attack",
    "postgres": "Database Attack",
    "mssql": "Database Attack",
    "mongo": "Database Attack",
    "redis": "Database Attack",
    "smtp": "Email Service",
    "imap": "Credential Attack",
    "pop3": "Credential Attack",
    "dns": "DNS Abuse",
    "snmp": "Information Disclosure",
    "ldap": "Directory Attack",
    "kerberos": "Credential Attack",
    "docker": "Container Escape",
    "kubernetes": "Cluster Attack",
    "vmware": "Privilege Escalation",
    "rmi": "RCE Exploit",
    "distccd": "RCE Exploit",
    "irc": "Botnet Channel",
    "pando-pub": "Unknown",
    "ici": "Unknown",
    "ethernetip-1": "Remote Access Abuse",
}

ATTACK_TYPE_SEVERITY_MAP = {
    "Web Exploit": "HIGH",
    "SSH Brute Force": "HIGH",
    "Remote Access Abuse": "HIGH",
    "Credential Sniffing": "MEDIUM",
    "Lateral Movement": "MEDIUM",
    "Privilege Escalation": "HIGH",
    "Database Attack": "HIGH",
    "Email Service": "MEDIUM",
    "Credential Attack": "MEDIUM",
    "DNS Abuse": "MEDIUM",
    "Information Disclosure": "MEDIUM",
    "Directory Attack": "MEDIUM",
    "Container Escape": "CRITICAL",
    "Cluster Attack": "HIGH",
    "RCE Exploit": "CRITICAL",
    "Botnet Channel": "HIGH",
    "Unknown": "MEDIUM",
}


@dataclass
class ReadinessCheck:
    name: str
    passed: bool
    details: str
    fix: str | None = None


def service_to_attack(service_name: Any) -> str:
    if service_name is None:
        return "Unknown"
    s = str(service_name).lower().strip()
    for key, attack in SERVICE_MAPPING.items():
        if key in s:
            return attack
    return "Unknown"


def normalize_vuln(name: Any) -> str:
    if name is None:
        return ""
    s = str(name).lower().strip()
    if s in ALIASES:
        return ALIASES[s]
    if "kestrel" in s:
        return "microsoft kestrel httpd"
    if "tornado" in s:
        return "tornado httpd"
    if "apache" in s:
        return "apache"
    if "nginx" in s:
        return "nginx"
    if "mysql" in s:
        return "mysql"
    if "microsoft windows rpc" in s or s.startswith("msrpc"):
        return "microsoft windows rpc"
    return s


def _extract_cvss_fields(cve: Any) -> tuple[float | None, str]:
    cvss = None
    severity = "Unknown"
    for score_attr, sev_attr in (("v31score", "v31severity"), ("v30score", "v30severity"), ("v2score", "v2severity")):
        score = getattr(cve, score_attr, None)
        sev = getattr(cve, sev_attr, None)
        if score is not None:
            cvss = float(score)
            severity = sev or severity
            break
    if cvss is None and hasattr(cve, "score") and isinstance(cve.score, (list, tuple)):
        if len(cve.score) > 2 and cve.score[2] is not None:
            cvss = float(cve.score[2])
        if len(cve.score) > 3 and cve.score[3]:
            severity = cve.score[3]
    return cvss, severity


# Noise words to skip when splitting product names into fallback queries.
_NOISE_WORDS = {"the", "a", "an", "for", "and", "or", "of", "in", "on", "to", "with", "is"}


def _build_nvd_query_candidates(product: str, version: str, cpe: str, *, thorough: bool = False) -> list[str]:
    candidates: list[str] = []

    def add_candidate(value: str) -> None:
        cleaned = " ".join(value.replace("/", " ").replace("_", " ").split()).strip()
        if cleaned and cleaned not in candidates:
            candidates.append(cleaned)

    add_candidate(f"{product} {version}".strip())
    add_candidate(product)

    lowered = product.lower()
    if "tomcat" in lowered:
        add_candidate("tomcat")
        add_candidate("apache tomcat")
    if "coyote" in lowered:
        add_candidate("coyote")
        add_candidate("coyote http connector")
        add_candidate("apache coyote http connector")
    if "apache" in lowered:
        add_candidate("apache")
    if "coyote_http_connector" in lowered:
        add_candidate("coyote_http_connector")
        add_candidate("apache coyote_http_connector")
    if "bind" in lowered:
        add_candidate("ISC BIND")
    if "rmi" in lowered or "grmi" in lowered:
        add_candidate("Java RMI")
        add_candidate("GNU Classpath")
    if "rexec" in lowered or "netkit" in lowered:
        add_candidate("netkit")
        add_candidate("rexec")
    if "metasploit" in lowered:
        add_candidate("Metasploitable")

    cpe_text = cpe.strip()
    if cpe_text.startswith("cpe:/"):
        cpe_parts = [part for part in cpe_text.split(":") if part and part not in {"cpe", "/a", "/o", "/h"}]
        if len(cpe_parts) >= 3:
            add_candidate(" ".join(cpe_parts[1:3]))
            add_candidate(" ".join(cpe_parts[1:4]))

    # In thorough mode, also try significant individual words from the product name.
    if thorough:
        words = [w for w in product.replace("-", " ").replace("_", " ").split() if w.lower() not in _NOISE_WORDS and len(w) > 2]
        for w in words:
            add_candidate(w)

    return candidates


def get_nvd_info(product: Any, version: Any = None, cpe: Any = None, *, thorough: bool = True) -> dict[str, Any]:
    if nvdlib is None:
        print(f"[NVD] nvdlib not available, skipping lookup for {product}")
        return {"CVE": "N/A", "CVSS": None, "Severity": "Unknown", "CVE_Count": 0}

    product_str = str(product or "").strip()
    service_str = product_str  # keep original for hint lookup
    if not product_str or product_str.lower() in {"unknown", "none", "", "nan"}:
        hint = SERVICE_PRODUCT_HINTS.get(service_str.lower())
        if hint:
            print(f"[NVD] Bare service '{service_str}' -> product hint '{hint}'")
            product_str = hint
        elif not cpe:
            print(f"[NVD] Empty product and no CPE, skipping lookup")
            return {"CVE": "N/A", "CVSS": None, "Severity": "Unknown", "CVE_Count": 0}

    cpe_limit = 10 if thorough else 5
    kw_limit = 5 if thorough else 3
    max_retries = 3 if thorough else 1

    try:
        print(f"[NVD] Lookup attempt: product={product_str}, version={version}, cpe={cpe}, thorough={thorough}")
        version_str = str(version or "").strip()
        api_key = os.getenv("NVD_API_KEY", "").strip() or None
        if api_key:
            print(f"[NVD] Using NVD API key")
        else:
            print(f"[NVD] No API key; using free-tier (rate-limited)")
        query_candidates = _build_nvd_query_candidates(product_str, version_str, str(cpe or ""), thorough=thorough)
        # In thorough mode, also try the bare service name as a fallback candidate
        if thorough and service_str.lower() != product_str.lower():
            bare = service_str.strip()
            if bare and bare not in query_candidates:
                query_candidates.append(bare)
        # Also try a SERVICE_PRODUCT_HINTS lookup for the service name as fallback
        if thorough:
            hint = SERVICE_PRODUCT_HINTS.get(service_str.lower())
            if hint and hint not in query_candidates:
                query_candidates.append(hint)
        print(f"[NVD] Query candidates: {query_candidates}")

        result_by_id: dict[str, Any] = {}

        def _pace_nvd_call() -> None:
            """Enforce free-tier pacing when no API key is set."""
            global _last_nvd_call
            if not api_key:
                elapsed = time.time() - _last_nvd_call
                if elapsed < _NVD_FREE_TIER_DELAY:
                    wait = _NVD_FREE_TIER_DELAY - elapsed
                    print(f"[NVD] Pacing: waiting {wait:.1f}s for free-tier rate limit")
                    time.sleep(wait)
            _last_nvd_call = time.time()

        cpe_text = str(cpe or "").strip()
        if cpe_text.startswith("cpe:/"):
            try:
                print(f"[NVD] Searching CPE: {cpe_text}")
                cpe_kwargs: dict[str, Any] = {"cpeName": cpe_text, "limit": cpe_limit}
                if api_key:
                    cpe_kwargs["key"] = api_key
                    cpe_kwargs["delay"] = 1
                _pace_nvd_call()
                for item in _nvd_search_with_retry(max_retries=max_retries, **cpe_kwargs):
                    if getattr(item, "id", None):
                        result_by_id[item.id] = item
                print(f"[NVD] CPE search found {len(result_by_id)} CVEs")
            except Exception as cpe_exc:
                print(f"[NVD] CPE search failed ({type(cpe_exc).__name__}: {cpe_exc}), continuing with keyword searches")

        for query in query_candidates:
            q = (query or "").strip()
            if not q:
                continue
            # In thorough mode keep searching until we find at least one; in fast mode stop at first hit
            if not thorough and result_by_id:
                break
            # In thorough mode, once we have results, stop trying additional fallback words
            if thorough and result_by_id and len(query_candidates) > 4 and query_candidates.index(q) >= 4:
                break
            print(f"[NVD] Keyword search: {q}")
            kw_kwargs: dict[str, Any] = {"keywordSearch": q, "limit": kw_limit}
            if api_key:
                kw_kwargs["key"] = api_key
                kw_kwargs["delay"] = 1
            _pace_nvd_call()
            results = _nvd_search_with_retry(max_retries=max_retries, **kw_kwargs)
            for item in results:
                if getattr(item, "id", None):
                    result_by_id[item.id] = item
            print(f"[NVD] Keyword search found {len([i for i in results if getattr(i, 'id', None)])} CVEs")

        if not result_by_id:
            print(f"[NVD] No CVEs found; falling back to heuristic severity")
            return {"CVE": "N/A", "CVSS": None, "Severity": "Unknown", "CVE_Count": 0}

        def rank(candidate: Any) -> tuple[float, float]:
            cvss, _ = _extract_cvss_fields(candidate)
            score = cvss if cvss is not None else -1.0
            version_bonus = 0.0
            version_hint = str(version or "").lower().strip()
            if version_hint:
                desc = " ".join(
                    d.value.lower()
                    for d in (getattr(candidate, "descriptions", []) or [])
                    if hasattr(d, "value") and isinstance(d.value, str)
                )
                if version_hint in desc:
                    version_bonus = 0.5
            return score, version_bonus

        cve = max(result_by_id.values(), key=rank)
        cvss, severity = _extract_cvss_fields(cve)
        print(f"[NVD] Best match: {cve.id}, CVSS={cvss}, Severity={severity}")
        return {
            "CVE": cve.id,
            "CVSS": round(cvss, 1) if cvss is not None else None,
            "Severity": severity,
            "CVE_Count": len(result_by_id),
        }
    except Exception as e:
        print(f"[NVD] Exception during lookup: {type(e).__name__}: {e}")
        return {"CVE": "N/A", "CVSS": None, "Severity": "Unknown", "CVE_Count": 0}


def attach_remediation(df: pd.DataFrame) -> pd.DataFrame:
    rem = pd.read_csv(REMEDIATION_PATH)

    out = df.copy()
    out["key"] = out["Security_Vulnerability_Type"].astype(str).str.lower().str.strip().replace({"0": "", "none": ""}).fillna("")
    rem["key"] = rem["Vulnerability_Type"].astype(str).str.lower().str.strip().replace({"0": "", "none": ""}).fillna("")

    merged = out.merge(rem, on="key", how="left", suffixes=("", "_rem"))

    missing_idx = merged[merged["Recommended_Control"].isna()].index
    for i in missing_idx:
        sv = str(merged.at[i, "Security_Vulnerability_Type"]).lower().strip()
        if not sv:
            continue
        for _, r in rem.iterrows():
            rv = str(r["Vulnerability_Type"]).lower()
            if rv and (rv in sv or sv in rv):
                for col in ["Recommended_Control", "Mitigation_Tool", "Control_Cost_USD", "Effectiveness_percent", "ROI_Tag"]:
                    merged.at[i, col] = r.get(col)
                break

    rem_keys = rem["key"].dropna().unique().tolist()
    missing_idx = merged[merged["Recommended_Control"].isna()].index
    for i in missing_idx:
        sv = str(merged.at[i, "Security_Vulnerability_Type"]).lower().strip()
        if not sv:
            continue
        matches = difflib.get_close_matches(sv, rem_keys, n=1, cutoff=0.6)
        if matches:
            r = rem[rem["key"] == matches[0]].iloc[0]
            for col in ["Recommended_Control", "Mitigation_Tool", "Control_Cost_USD", "Effectiveness_percent", "ROI_Tag"]:
                merged.at[i, col] = r.get(col)

    defaults = {
        "Recommended_Control": "General Hardening",
        "Mitigation_Tool": "Manual Review",
        "Control_Cost_USD": 1000,
        "Effectiveness_percent": 60,
        "ROI_Tag": "Medium",
    }
    merged = merged.fillna(defaults)
    merged["Control_Cost_USD"] = merged["Control_Cost_USD"].astype(int)
    merged["Effectiveness_percent"] = merged["Effectiveness_percent"].astype(int)

    text_cols = [
        "Service",
        "Product",
        "Version",
        "Security_Vulnerability_Type",
        "Recommended_Control",
        "Mitigation_Tool",
    ]
    for c in text_cols:
        if c in merged.columns:
            merged[c] = merged[c].astype(str).str.strip().replace({"": "Unknown", "nan": "Unknown", "None": "Unknown"})

    SCANNER_RESULTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    merged.to_csv(SCANNER_RESULTS_PATH, index=False)
    return merged


def process_raw_scan(raw_results: list[dict[str, Any]]) -> pd.DataFrame:
    df = pd.DataFrame(raw_results)

    if "scan_timestamp" not in df.columns:
        df["scan_timestamp"] = dt.datetime.now(dt.timezone.utc).isoformat()

    if "Service" not in df.columns:
        df["Service"] = "Unknown"

    if "scan_mode" not in df.columns:
        df["scan_mode"] = "thorough"

    df["Attack_Type"] = df["Service"].apply(service_to_attack)
    df["Security_Vulnerability_Type"] = df.apply(
        lambda row: normalize_vuln(row.get("Product") or row.get("Service")), axis=1
    )

    # In fast mode, enrich only the highest-risk half of unique findings.
    # Risk is inferred from mapped attack type severity.
    severity_rank = {
        "CRITICAL": 4,
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1,
    }

    def row_lookup_key(row: pd.Series) -> tuple[str, str, str]:
        query = str(row.get("Product") or row.get("Service") or "").strip().lower()
        version = str(row.get("Version") or "").strip().lower()
        cpe = str(row.get("CPE") or "").strip().lower()
        return (query, version, cpe)

    def row_risk_score(row: pd.Series) -> int:
        attack_type = str(row.get("Attack_Type") or "Unknown")
        sev = ATTACK_TYPE_SEVERITY_MAP.get(attack_type, "MEDIUM")
        return severity_rank.get(sev, 2)

    fast_mode_mask = df["scan_mode"].astype(str).str.lower().isin({"fast", "demo", "quick"})
    fast_allowed_keys: set[tuple[str, str, str]] = set()
    if fast_mode_mask.any():
        fast_df = df.loc[fast_mode_mask].copy()
        fast_df["_lookup_key"] = fast_df.apply(row_lookup_key, axis=1)
        fast_df["_risk"] = fast_df.apply(row_risk_score, axis=1)

        key_to_risk: dict[tuple[str, str, str], int] = {}
        for _, row in fast_df.iterrows():
            key = row["_lookup_key"]
            if not any(key):
                continue
            risk = int(row["_risk"])
            key_to_risk[key] = max(risk, key_to_risk.get(key, 0))

        ranked_keys = sorted(key_to_risk.items(), key=lambda item: item[1], reverse=True)
        # Include ALL High and Critical findings — no budget fraction so none are skipped.
        # Medium/Low findings are excluded from NVD lookups in fast mode.
        fast_allowed_keys = {key for key, risk in ranked_keys if risk >= severity_rank["HIGH"]}

    nvd_cache: dict[tuple[str, str, str], dict[str, Any]] = {}

    def add_nvd(row: pd.Series) -> pd.Series:
        key = row_lookup_key(row)

        mode = str(row.get("scan_mode") or "thorough").strip().lower()
        is_fast_mode = mode in {"fast", "demo", "quick"}
        row["NVD_Mode"] = "partial_high_critical" if is_fast_mode else "full"

        should_lookup_nvd = not is_fast_mode or key in fast_allowed_keys

        if key not in nvd_cache:
            if should_lookup_nvd:
                nvd_cache[key] = get_nvd_info(
                    row.get("Product") or row.get("Service"),
                    row.get("Version"),
                    row.get("CPE"),
                    thorough=not is_fast_mode,
                )
            else:
                nvd_cache[key] = {"CVE": "N/A", "CVSS": None, "Severity": "Unknown", "CVE_Count": 0}

        nvd = nvd_cache[key]
        row["CVE"] = nvd.get("CVE", "N/A")
        row["CVSS_Score"] = nvd.get("CVSS")
        row["NVD_Severity"] = nvd.get("Severity", "Unknown")

        if is_fast_mode:
            nvd_sev = str(row.get("NVD_Severity") or "Unknown").upper().strip()
            if nvd_sev not in {"HIGH", "CRITICAL"}:
                row["CVE"] = "N/A"
                row["CVSS_Score"] = None
        
        attack_type = str(row.get("Attack_Type", "Unknown"))
        heuristic_severity = ATTACK_TYPE_SEVERITY_MAP.get(attack_type, "MEDIUM")
        
        if row.get("NVD_Severity") and row.get("NVD_Severity") != "Unknown":
            row["Incident_Severity"] = row.get("NVD_Severity")
        else:
            print(f"[HEURISTIC] No valid NVD severity for {row.get('Product', 'Unknown')} ({attack_type}), using fallback: {heuristic_severity}")
            row["NVD_Severity"] = heuristic_severity
            row["Incident_Severity"] = heuristic_severity
        return row

    df = df.apply(add_nvd, axis=1)
    return attach_remediation(df)


def latest_scan_results() -> list[dict[str, Any]]:
    if not SCANNER_RESULTS_PATH.exists():
        return []
    df = pd.read_csv(SCANNER_RESULTS_PATH).fillna("")
    return df.to_dict(orient="records")


def agent_script_text() -> str:
    return AGENT_SCRIPT_PATH.read_text(encoding="utf-8")


def agent_script_sha256(script_text: str | None = None) -> str:
    content = script_text if script_text is not None else agent_script_text()
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def scanner_readiness() -> dict[str, Any]:
    checks: list[ReadinessCheck] = []

    checks.append(
        ReadinessCheck(
            name="Python available",
            passed=True,
            details=f"Backend Python: {shutil.which('python') or 'managed runtime'}",
        )
    )

    checks.append(
        ReadinessCheck(
            name="Nmap installed on scanner host",
            passed=False,
            details="Cannot verify from browser. Run local precheck on target machine.",
            fix="Install Nmap from https://nmap.org/download and ensure 'nmap --version' works.",
        )
    )

    checks.append(
        ReadinessCheck(
            name="Backend upload endpoint",
            passed=True,
            details="/upload_raw_scan available.",
        )
    )

    checks.append(
        ReadinessCheck(
            name="NVD enrichment",
            passed=nvdlib is not None,
            details="nvdlib available." if nvdlib is not None else "nvdlib not available; CVE enrichment degraded.",
            fix="Install nvdlib package if missing.",
        )
    )

    return {
        "ready": all(c.passed for c in checks if c.name != "Nmap installed on scanner host"),
        "checks": [c.__dict__ for c in checks],
        "instructions": [
            "1) Download agent script + checksum",
            "2) Verify checksum on target machine",
            "3) Run script and provide target IP/hostname",
            "4) Return to this page and refresh uploaded findings",
        ],
    }


def summarize_for_prefill(rows: list[dict[str, Any]]) -> dict[str, Any]:
    if not rows:
        return {
            "suggested_attack_type": "Other",
            "suggested_incident_severity": 2,
            "suggested_records_compromised": 10000,
            "row_count": 0,
        }

    df = pd.DataFrame(rows)
    attack = str(df["Attack_Type"].mode().iloc[0]) if "Attack_Type" in df.columns and not df["Attack_Type"].dropna().empty else "Other"

    sev_map = {
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4,
    }
    if "NVD_Severity" in df.columns and not df["NVD_Severity"].dropna().empty:
        sev_text = str(df["NVD_Severity"].mode().iloc[0]).upper().strip()
        severity = sev_map.get(sev_text, 2)
    else:
        severity = 2

    high_findings = 0
    if "CVSS_Score" in df.columns:
        cvss = pd.to_numeric(df["CVSS_Score"], errors="coerce")
        high_findings = int((cvss >= 7.0).sum())
    suggested_records = max(1000, high_findings * 5000)

    return {
        "suggested_attack_type": attack,
        "suggested_incident_severity": severity,
        "suggested_records_compromised": suggested_records,
        "row_count": int(len(df)),
    }
