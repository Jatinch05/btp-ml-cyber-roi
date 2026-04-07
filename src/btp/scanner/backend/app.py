import ipaddress
import logging
import os
import re
import time
from collections import defaultdict, deque

from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from scan_and_map import full_scan
import pandas as pd
from mapping import service_to_attack, normalize_vuln

logger = logging.getLogger("securescope.api")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")

ALLOWED_ORIGINS = [
    origin.strip() for origin in os.getenv(
        "SECURESCOPE_ALLOWED_ORIGINS",
        "http://localhost:8501,http://127.0.0.1:8501",
    ).split(",") if origin.strip()
]
API_KEY = os.getenv("SECURESCOPE_API_KEY", "").strip()
ENABLE_SERVER_SIDE_SCAN = os.getenv("SECURESCOPE_ENABLE_SERVER_SIDE_SCAN", "false").strip().lower() == "true"
MAX_UPLOAD_ROWS = int(os.getenv("SECURESCOPE_MAX_UPLOAD_ROWS", "2000"))
RATE_LIMIT_WINDOW_SEC = int(os.getenv("SECURESCOPE_RATE_LIMIT_WINDOW_SEC", "60"))
RATE_LIMIT_MAX_REQUESTS = int(os.getenv("SECURESCOPE_RATE_LIMIT_MAX_REQUESTS", "60"))

HOSTNAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9.-]{0,253}[a-zA-Z0-9]$")
REQUEST_HITS: dict[str, deque[float]] = defaultdict(deque)

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
    return response


def require_api_key(x_api_key: str | None = Header(default=None, alias="X-API-Key")) -> None:
    # Backward compatible local mode: only enforce when a key is configured.
    if API_KEY and x_api_key != API_KEY:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")


def rate_limit(request: Request) -> None:
    host = request.client.host if request.client else "unknown"
    now = time.time()
    bucket = REQUEST_HITS[host]

    while bucket and now - bucket[0] > RATE_LIMIT_WINDOW_SEC:
        bucket.popleft()

    if len(bucket) >= RATE_LIMIT_MAX_REQUESTS:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Too many requests")

    bucket.append(now)


def validate_target(target: str) -> str:
    cleaned = (target or "").strip()
    if not cleaned or len(cleaned) > 255:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid target")

    try:
        ip = ipaddress.ip_address(cleaned)
        if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Target IP range is not allowed")
        return str(ip)
    except ValueError:
        pass

    if not HOSTNAME_RE.match(cleaned) or ".." in cleaned:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid hostname")

    return cleaned

@app.get("/scan")
def scan_endpoint(target: str, _: None = Depends(require_api_key), __: None = Depends(rate_limit)):
    if not ENABLE_SERVER_SIDE_SCAN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Server-side scan endpoint is disabled",
        )

    safe_target = validate_target(target)
    df = full_scan(safe_target)
    df = df.fillna("")
    return df.to_dict(orient="records")

# NEW: Local Agent endpoint
@app.post("/upload_scan_results")
async def upload_scan_results(results: list[dict], _: None = Depends(require_api_key), __: None = Depends(rate_limit)):
    if not results:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No scan results provided")
    if len(results) > MAX_UPLOAD_ROWS:
        raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="Too many scan rows")

    df = pd.DataFrame(results)
    from scan_and_map import attach_remediation
    enriched = attach_remediation(df)
    enriched = enriched.fillna("")
    return {"status": "success", "data": enriched.to_dict(orient="records")}

@app.post("/upload_raw_scan")
async def upload_raw_scan(raw_results: list[dict], _: None = Depends(require_api_key), __: None = Depends(rate_limit)):
    """Receive minimal scan data from standalone agent and fully process it"""
    try:
        if not raw_results:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No scan results provided")
        if len(raw_results) > MAX_UPLOAD_ROWS:
            raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="Too many scan rows")

        df = pd.DataFrame(raw_results)
        
        # Add the missing columns that attach_remediation expects
        df["Attack_Type"] = df["Service"].apply(service_to_attack) if "Service" in df.columns else "Unknown"
        df["Security_Vulnerability_Type"] = df.apply(
            lambda row: normalize_vuln(row.get("Product") or row.get("Service")), axis=1
        )

        # Enrich local-agent uploads with NVD CVE/CVSS details.
        from scanner_core import get_nvd_info
        nvd_cache: dict[tuple[str, str, str], dict] = {}

        def add_nvd_columns(row):
            query = str(row.get("Product") or row.get("Service") or "").strip().lower()
            version = str(row.get("Version") or "").strip().lower()
            cpe = str(row.get("CPE") or "").strip().lower()
            cache_key = (query, version, cpe)
            if cache_key not in nvd_cache:
                nvd_cache[cache_key] = get_nvd_info(
                    row.get("Product") or row.get("Service"),
                    row.get("Version"),
                    row.get("CPE"),
                )
            nvd = nvd_cache[cache_key]
            row["CVE"] = nvd.get("CVE", "N/A")
            row["CVSS_Score"] = nvd.get("CVSS")
            row["NVD_Severity"] = nvd.get("Severity", "Unknown")
            return row

        df = df.apply(add_nvd_columns, axis=1)
        
        # Call existing enrichment
        from scan_and_map import attach_remediation
        enriched = attach_remediation(df)
        
        enriched = enriched.fillna("")
        return {"status": "success", "data": enriched.to_dict(orient="records")}
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("upload_raw_scan failed: %s", e)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal processing error")