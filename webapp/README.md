# Cyber ROI Web Frontend (React + Vite)

Separate frontend that keeps existing Streamlit apps untouched.

## Run

1. Start backend API (from repo root):

```powershell
uvicorn btp.api:app --host 127.0.0.1 --port 8000 --reload
```

2. Start frontend (from `webapp`):

```powershell
npm install
npm run dev
```

Frontend URL: `http://127.0.0.1:5173`

## Pages

- `Decision Studio`: Input -> prediction -> safeguards -> business return.
- `Data Metrics`: Dataset KPIs and analytics charts.

## Backend Endpoints Used

- `GET /healthz`
- `GET /analytics`
- `POST /predict-and-recommend`

## Config

Set custom API URL:

```powershell
$env:VITE_API_BASE='http://127.0.0.1:8000'
npm run dev
```
