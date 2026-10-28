# OT Sentinel

OT Sentinel is a local-first defensive IT/OT monitoring prototype. It demonstrates persistent event ingestion, deterministic detections, investigation workflows, synthetic scenarios, and a Danish dashboard. **It is not production-ready or safety-certified.** The starter dataset is synthetic. No network capture, device scanning, blocking, or industrial control actions are implemented.

## Start locally

Requirements: Python 3.11+ and Node.js 20+.

In one terminal:

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

In another terminal:

```powershell
cd frontend
npm install
npm run dev
```

Open http://127.0.0.1:5173. API documentation is at http://127.0.0.1:8000/docs. The API binds to localhost. SQLite is created at `data/ot_sentinel.db` in the repository root; the first startup seeds a synthetic dataset once and later restarts preserve data.

Set `OT_SENTINEL_DB` to use a different SQLite file. The default database is `data/ot_sentinel.db` at the repository root. No external service or AI provider is required. The frontend dependencies are locked in `frontend/package-lock.json`.

For backend tests, install `backend/requirements-dev.txt` and run `python -m pytest -q` from `backend`. For frontend tests, run `npm test` from `frontend`.

## Implemented workflows

- Dashboard counts, severity distribution, event timeline, assets, and recommended investigation from API/database records.
- Event search and severity filter, detail drawer, status updates, and persistent analyst notes.
- Deterministic rules for authentication anomalies, unexpected network relationships, unusual remote access, and unapproved configuration changes. Each detection has a rule identifier and evidence explanation. Risk contribution and OT destination adjustment are computed server-side, capped at 100.
- Five local simulation scenarios: normal, authentication anomaly, unexpected IT/OT communication, configuration change, and correlated activity. They only write synthetic application records.
- File preview and commit for JSON, JSONL, and CSV; 5 MB preview cap and 10,000 record commit cap. Imported values are treated as data. Duplicate fingerprints are skipped.
- Network relationship view and zone-based asset topology from stored assets and events.
- Data source status, incident list, and CSV export with formula-prefix escaping.
- API input validation, parameterized SQLAlchemy queries, local-only CORS origins, and health endpoint.

## Detection and risk model

Rules are deterministic and version 1.0. Rule contributions are 44 (authentication), 62 (network relation), 71 (remote access), and 86 (configuration change). The prototype adds 12 points for a PLC/SCADA destination and 8 for Critical severity, then caps at 100. This is a prioritization aid for synthetic demonstrations, not an industry standard. A new connection is an observed baseline deviation, not proof of malicious activity or compromise. The normal scenario uses an approved HMI path and is not promoted by the rule.

Correlation demonstration uses three related indicators on the same OT path within one scenario run. Its incident score is explicitly illustrative. The current incident workflow groups generated records; broader user-managed incident linking and a full migration history are not yet included.

## API overview

`GET /api/health`, `/api/dashboard`, `/api/events`, `/api/events/{id}`, `/api/assets`, `/api/network/relationships`, `/api/incidents`, `/api/sources`, `/api/rules`; `PATCH /api/events/{id}/status`; `POST /api/events/{id}/notes`, `/api/simulation`, `/api/import/preview`, `/api/import/commit`; `GET /api/reports/events.csv`.

## Limitations and next steps

This first implementation is a credible local prototype, not the full scope of the vision. It currently has no Alembic migration history, user authentication, role-based access, audit trail, full report builder, incident editing, live Zeek/Suricata adapter, protocol-deep industrial analysis, external AI provider, custom time filter, or Playwright coverage. Uploaded imports are previewed before a separate confirmation request, but preview state is held in the browser and should be protected with a signed import job before multi-user exposure. Data is synthetic or explicitly imported; `LIVE 0` means zero verified live sources.

Before exposing beyond localhost, add authentication and authorization, HTTPS, backups and restore drills, secret management, audit logging, retention controls, request rate limits, and network restrictions. Treat uploaded logs as sensitive data.
