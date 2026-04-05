const ACRONYM_MAP = {
  api: "API",
  ddos: "DDoS",
  iot: "IoT",
  ot: "OT",
  pii: "PII",
  phi: "PHI",
  ip: "IP",
  gps: "GPS",
  scada: "SCADA",
  pos: "POS",
  sql: "SQL",
};

export const GENERAL_DATA_CATEGORY_OPTIONS = [
  "Personal Data",
  "Financial Data",
  "Health Data",
  "Location and Mobility Data",
  "Operational and Device Data",
  "Intellectual Property Data",
  "Digital Asset Data",
  "Other",
];

export const GENERAL_DATA_CATEGORY_TO_RAW = {
  "Personal Data": "pii_customer",
  "Financial Data": "Financial,PII",
  "Health Data": "PHI,Device_Data",
  "Location and Mobility Data": "Vehicle_Data,Location",
  "Operational and Device Data": "SCADA_Data,Grid_Info",
  "Intellectual Property Data": "Trade_Secrets,Designs",
  "Digital Asset Data": "Cryptocurrency",
  Other: "pii_customer",
};

export const GENERAL_THREAT_SCENARIO_OPTIONS = [
  "API & Platform Abuse",
  "Account Takeover & Credential Theft",
  "Application Exploit",
  "Denial of Service",
  "Malware & Ransomware",
  "Data Breach & Exposure",
  "Phishing & Email Abuse",
  "Supply Chain Compromise",
  "Device, IoT & OT Attack",
  "Insider Threat",
  "Other",
];

export const GENERAL_THREAT_SCENARIO_TO_RAW = {
  "API & Platform Abuse": "API_Abuse",
  "Account Takeover & Credential Theft": "Account_Takeover",
  "Application Exploit": "App_Vulnerability",
  "Denial of Service": "DDoS",
  "Malware & Ransomware": "Ransomware",
  "Data Breach & Exposure": "Data_Breach",
  "Phishing & Email Abuse": "Phishing",
  "Supply Chain Compromise": "Supply_Chain",
  "Device, IoT & OT Attack": "IoT_Breach",
  "Insider Threat": "Insider_Threat",
  Other: "Data_Breach",
};

export function generalizeThreatScenario(raw) {
  const value = String(raw ?? "").trim().toLowerCase();
  if (!value) return "Other";

  if (value.includes("api")) return "API & Platform Abuse";
  if (value.includes("account") || value.includes("credential") || value.includes("wallet")) return "Account Takeover & Credential Theft";
  if (value.includes("app_vulnerab") || value.includes("sql") || value.includes("mitm") || value.includes("network") || value.includes("data_exposure")) return "Application Exploit";
  if (value.includes("ddos") || value.includes("denial")) return "Denial of Service";
  if (value.includes("malware") || value.includes("ransom")) return "Malware & Ransomware";
  if (value.includes("data_breach") || value.includes("data_exposure") || value.includes("breach")) return "Data Breach & Exposure";
  if (value.includes("phish") || value.includes("email") || value.includes("compromise")) return "Phishing & Email Abuse";
  if (value.includes("supply")) return "Supply Chain Compromise";
  if (value.includes("iot") || value.includes("ot") || value.includes("connected_car") || value.includes("precision_ag") || value.includes("industrial")) return "Device, IoT & OT Attack";
  if (value.includes("insider")) return "Insider Threat";

  return "Other";
}

export function normalizeLabel(value) {
  const s = String(value ?? "").trim();
  if (!s) return s;

  return s
    .replaceAll("_", " ")
    .replaceAll(",", ", ")
    .split(/\s+/)
    .filter(Boolean)
    .map((part) => ACRONYM_MAP[part.toLowerCase()] ?? part.charAt(0).toUpperCase() + part.slice(1).toLowerCase())
    .join(" ")
    .replace(/\s+,\s+/g, ", ");
}

export function generalizeDataCategory(raw) {
  const value = String(raw ?? "").trim().toLowerCase();
  if (!value) return "Other";

  if (value.includes("crypto") || value.includes("wallet")) return "Digital Asset Data";
  if (value.includes("scada") || value.includes("sensor") || value.includes("grid") || value.includes("device") || value.includes("iot") || value.includes("operational")) {
    return "Operational and Device Data";
  }
  if (value.includes("vehicle") || value.includes("gps") || value.includes("location") || value.includes("travel") || value.includes("passenger")) {
    return "Location and Mobility Data";
  }
  if (value.includes("phi") || value.includes("medical") || value.includes("health") || value.includes("patient")) {
    return "Health Data";
  }
  if (value.includes("financial") || value.includes("payment") || value.includes("transaction") || value.includes("bank") || value.includes("credit")) {
    return "Financial Data";
  }
  if (value.includes("trade_secret") || value.includes("research") || value.includes("design") || value.includes("patent") || value.includes("ip")) {
    return "Intellectual Property Data";
  }
  if (
    value.includes("pii") ||
    value.includes("personal") ||
    value.includes("customer") ||
    value.includes("account") ||
    value.includes("email") ||
    value.includes("message") ||
    value.includes("content") ||
    value.includes("subscriber") ||
    value.includes("legal") ||
    value.includes("academic") ||
    value.includes("business") ||
    value.includes("claims")
  ) {
    return "Personal Data";
  }

  return "Other";
}

export function summarizeDataCategoryRows(rows, topN = 3) {
  const totals = new Map();
  for (const row of rows || []) {
    const rawLabel = row?.data_type ?? row?.Data_Type ?? row?.name ?? row?.category ?? "";
    const count = Number(row?.count ?? row?.Count ?? row?.value ?? 0);
    const normalized = generalizeDataCategory(rawLabel);
    totals.set(normalized, (totals.get(normalized) ?? 0) + (Number.isFinite(count) ? count : 0));
  }

  const sorted = Array.from(totals.entries())
    .map(([data_category, count]) => ({ data_category, count }))
    .sort((a, b) => b.count - a.count);

  const top = sorted.slice(0, topN);
  const otherCount = sorted.slice(topN).reduce((sum, row) => sum + row.count, 0);
  if (otherCount > 0) {
    top.push({ data_category: "Other", count: otherCount });
  }

  const total = top.reduce((sum, row) => sum + row.count, 0) || 1;
  return top.map((row) => ({
    ...row,
    share: row.count / total,
  }));
}
