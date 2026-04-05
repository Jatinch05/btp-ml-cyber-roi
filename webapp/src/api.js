const API_BASE = import.meta.env.VITE_API_BASE || "http://127.0.0.1:8000";

async function parseJson(resp) {
  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`HTTP ${resp.status}: ${text}`);
  }
  return resp.json();
}

export async function healthz() {
  const resp = await fetch(`${API_BASE}/healthz`);
  return parseJson(resp);
}

export async function fetchAnalytics() {
  const resp = await fetch(`${API_BASE}/analytics`);
  return parseJson(resp);
}

export async function predictAndRecommend(payload) {
  const resp = await fetch(`${API_BASE}/predict-and-recommend`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify([payload]),
  });
  const data = await parseJson(resp);
  return Array.isArray(data) ? data[0] : data;
}
