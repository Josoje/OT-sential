from __future__ import annotations

import csv
import hashlib
import io
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

ROOT = Path(__file__).resolve().parents[2]
DB_PATH = Path(os.getenv("OT_SENTINEL_DB", ROOT / "data" / "ot_sentinel.db"))
DB_PATH.parent.mkdir(parents=True, exist_ok=True)
engine = create_engine(f"sqlite:///{DB_PATH.as_posix()}", connect_args={"check_same_thread": False})
Session = sessionmaker(engine, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


class Asset(Base):
    __tablename__ = "assets"
    id: Mapped[str] = mapped_column(String, primary_key=True)
    name: Mapped[str] = mapped_column(String, unique=True, index=True)
    kind: Mapped[str] = mapped_column(String)
    zone: Mapped[str] = mapped_column(String)
    criticality: Mapped[int] = mapped_column(Integer, default=2)
    synthetic: Mapped[bool] = mapped_column(Boolean, default=True)


class SecurityEvent(Base):
    __tablename__ = "security_events"
    id: Mapped[str] = mapped_column(String, primary_key=True)
    fingerprint: Mapped[str] = mapped_column(String, unique=True, index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    event_type: Mapped[str] = mapped_column(String, index=True)
    severity: Mapped[str] = mapped_column(String, index=True)
    source_asset: Mapped[str] = mapped_column(String, index=True)
    destination_asset: Mapped[str | None] = mapped_column(String, nullable=True)
    source_name: Mapped[str] = mapped_column(String, default="Synthetic")
    description: Mapped[str] = mapped_column(Text)
    protocol: Mapped[str | None] = mapped_column(String, nullable=True)
    status: Mapped[str] = mapped_column(String, default="Ny")
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    detection: Mapped[str | None] = mapped_column(String, nullable=True)
    evidence: Mapped[str] = mapped_column(Text, default="[]")


class AnalystNote(Base):
    __tablename__ = "analyst_notes"
    id: Mapped[str] = mapped_column(String, primary_key=True)
    event_id: Mapped[str] = mapped_column(ForeignKey("security_events.id"), index=True)
    body: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class DataSource(Base):
    __tablename__ = "data_sources"
    id: Mapped[str] = mapped_column(String, primary_key=True)
    name: Mapped[str] = mapped_column(String)
    kind: Mapped[str] = mapped_column(String)
    status: Mapped[str] = mapped_column(String, default="Klar")
    events_processed: Mapped[int] = mapped_column(Integer, default=0)
    last_ingestion: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Incident(Base):
    __tablename__ = "incidents"
    id: Mapped[str] = mapped_column(String, primary_key=True)
    title: Mapped[str] = mapped_column(String)
    severity: Mapped[str] = mapped_column(String)
    risk_score: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String, default="Åben")
    event_ids: Mapped[str] = mapped_column(Text)
    rationale: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


Base.metadata.create_all(engine)
app = FastAPI(title="OT Sentinel API", version="0.1.0", description="Lokal, defensiv IT/OT overvågning med syntetiske data.")
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"], allow_methods=["*"], allow_headers=["*"])

SEED = [
    ("auth_failure", "Middel", "ws-fin-04", None, "Gentagne fejlede loginforsøg for servicekonto", None),
    ("network_connection", "Lav", "ws-ops-02", "scada-hmi-01", "Godkendt HMI-trafik fra driftsstation", "OPC-UA"),
    ("network_connection", "Høj", "ws-eng-01", "plc-line-03", "Ny IT/OT-forbindelse uden for tilladt kommunikationspolitik", "Modbus/TCP"),
    ("remote_access", "Høj", "vpn-gateway-01", "scada-hmi-01", "Fjernadgang uden for vedligeholdelsesvindue", "RDP"),
    ("config_change", "Kritisk", "scada-srv-01", None, "Konfigurationsændring uden godkendt ændringsreference", None),
    ("auth_success", "Information", "ws-ops-02", None, "Brugerlogin fra kendt driftsstation", None),
    ("network_connection", "Middel", "sensor-ot-01", "plc-line-03", "Ny observeret relation på industrielt netværk", "S7comm"),
]

RULES = {
    "auth_failure": ("DET-AUTH-01", "Gentagne fejlede loginforsøg", 44, "Flere fejlede loginforsøg observeret for samme kilde."),
    "network_connection": ("DET-NET-01", "Uventet netværksrelation", 62, "Kommunikationen afviger fra den konfigurerede baseline."),
    "remote_access": ("DET-REMOTE-01", "Usædvanlig fjernadgang", 71, "Fjernadgang blev observeret uden for det forventede vindue."),
    "config_change": ("DET-CONFIG-01", "Uventet konfigurationsændring", 86, "Ændring mangler godkendt reference."),
}


def score(event_type: str, severity: str, source: str, dest: str | None) -> tuple[int, str | None, str]:
    rule = RULES.get(event_type)
    if not rule:
        return {"Kritisk": 90, "Høj": 65, "Middel": 40, "Lav": 15, "Information": 4}.get(severity, 10), None, "[]"
    rule_id, _, base, rationale = rule
    # Transparent prototype model: rule contribution + asset criticality, capped at 100.
    ot_asset = bool(dest and (dest.startswith(("plc-", "scada-"))))
    risk = min(100, base + (12 if ot_asset else 0) + (8 if severity == "Kritisk" else 0))
    return risk, rule_id, json.dumps([rationale, f"Kilde: {source}", f"OT-modtager: {'ja' if ot_asset else 'nej'}"] , ensure_ascii=False)


def add_event(db, event_type, severity, source, dest, description, protocol=None, timestamp=None, source_name="Synthetic"):
    stamp = timestamp or datetime.now(timezone.utc)
    stamp = stamp.replace(tzinfo=timezone.utc) if stamp.tzinfo is None else stamp.astimezone(timezone.utc)
    canonical = "|".join([stamp.isoformat(), event_type, source, dest or "", description])
    fingerprint = hashlib.sha256(canonical.encode()).hexdigest()
    existing = db.scalar(select(SecurityEvent).where(SecurityEvent.fingerprint == fingerprint))
    if existing:
        return existing, False
    risk, detection, evidence = score(event_type, severity, source, dest)
    row = SecurityEvent(id=str(uuid4()), fingerprint=fingerprint, timestamp=stamp, event_type=event_type, severity=severity, source_asset=source, destination_asset=dest, source_name=source_name, description=description, protocol=protocol, status="Ny", risk_score=risk, detection=detection, evidence=evidence)
    db.add(row)
    return row, True


def seed():
    with Session.begin() as db:
        if db.scalar(select(Asset.id).limit(1)):
            return
        assets = [
            ("ws-fin-04", "Arbejdsstation", "Corporate IT", 2), ("ws-ops-02", "Arbejdsstation", "OT operations", 3),
            ("ws-eng-01", "Engineering workstation", "OT operations", 4), ("scada-hmi-01", "HMI", "Industrial control", 5),
            ("scada-srv-01", "SCADA-server", "Industrial control", 5), ("plc-line-03", "PLC", "Industrial control", 5),
            ("vpn-gateway-01", "Firewall", "DMZ", 4), ("sensor-ot-01", "Netværkssensor", "Monitoring", 3),
        ]
        for name, kind, zone, criticality in assets:
            db.add(Asset(id=str(uuid4()), name=name, kind=kind, zone=zone, criticality=criticality, synthetic=True))
        db.add(DataSource(id="demo-source", name="Demodatasæt", kind="Syntetisk", status="Aktiv", events_processed=0))
        now = datetime.now(timezone.utc)
        for i, item in enumerate(SEED):
            event_type, severity, source, dest, desc, protocol = item
            row, _ = add_event(db, event_type, severity, source, dest, desc, protocol, now - timedelta(minutes=(i * 31 + 4)))
            row.source_name = "Syntetisk demo"
        db.flush()
        high_ids = [e.id for e in db.scalars(select(SecurityEvent).where(SecurityEvent.risk_score >= 60)).all()]
        if high_ids:
            db.add(Incident(id=str(uuid4()), title="Uventet aktivitet i OT-miljø", severity="Kritisk", risk_score=88, status="Åben", event_ids=json.dumps(high_ids), rationale="Flere detektioner berører OT-aktiver og omfatter en ny netværksrelation samt ændring uden godkendelse."))
        source = db.get(DataSource, "demo-source")
        source.events_processed = len(SEED)
        source.last_ingestion = now


seed()


class StatusUpdate(BaseModel):
    status: str = Field(pattern="^(Ny|Under undersøgelse|Eskaleret|Lukket|Falsk positiv)$")


class NoteInput(BaseModel):
    body: str = Field(min_length=1, max_length=5000)


class ScenarioInput(BaseModel):
    scenario: str = Field(pattern="^(normal|auth|it_ot|change|correlated)$")


def iso_utc(value: datetime) -> str:
    aware = value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)
    return aware.isoformat().replace("+00:00", "Z")


def event_dict(e: SecurityEvent) -> dict[str, Any]:
    return {"id": e.id, "timestamp": iso_utc(e.timestamp), "event_type": e.event_type, "severity": e.severity, "source_asset": e.source_asset, "destination_asset": e.destination_asset, "source": e.source_name, "description": e.description, "protocol": e.protocol, "status": e.status, "risk_score": e.risk_score, "detection": e.detection, "evidence": json.loads(e.evidence or "[]")}


@app.get("/api/health")
def health():
    with Session() as db:
        db.execute(select(Asset.id).limit(1)).first()
    return {"status": "ok", "environment": "DEMO", "database": "tilgængelig", "live_sources": 0}


@app.get("/api/dashboard")
def dashboard(hours: int = Query(24, ge=1, le=168)):
    with Session() as db:
        events = db.scalars(select(SecurityEvent).order_by(SecurityEvent.timestamp.desc())).all()
        assets = db.scalars(select(Asset)).all()
        incidents = db.scalars(select(Incident).where(Incident.status == "Åben")).all()
        sources = db.scalars(select(DataSource)).all()
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        recent = [e for e in events if e.timestamp.replace(tzinfo=timezone.utc) >= cutoff]
        severity = {x: sum(1 for e in events if e.severity == x) for x in ["Kritisk", "Høj", "Middel", "Lav", "Information"]}
        trend = []
        step = timedelta(hours=hours / 12)
        for i in range(12, -1, -1):
            at = datetime.now(timezone.utc) - i * step
            count = sum(1 for e in recent if at - step <= e.timestamp.replace(tzinfo=timezone.utc) < at)
            trend.append({"label": at.strftime("%H:%M" if hours <= 24 else "%d/%m"), "events": count})
        top_events = [event_dict(e) for e in events[:8]]
        recommendations = [{"id": i.id, "title": i.title, "severity": i.severity, "risk_score": i.risk_score, "rationale": i.rationale} for i in incidents]
        return {"metrics": {"total_events": len(events), "open_incidents": len(incidents), "critical_high": sum(1 for i in incidents if i.severity in ("Kritisk", "Høj")), "assets": len(assets), "active_sources": sum(1 for s in sources if s.status == "Aktiv"), "last_ingestion": max((iso_utc(s.last_ingestion) for s in sources if s.last_ingestion), default=None)}, "severity": severity, "timeline": trend, "events": top_events, "recommendations": recommendations, "assets": [{"name": a.name, "kind": a.kind, "zone": a.zone, "criticality": a.criticality, "synthetic": a.synthetic} for a in assets], "window_hours": hours}


@app.get("/api/events")
def list_events(q: str = "", severity: str | None = None, event_type: str | None = None, asset: str | None = None, status: str | None = None, sort: str = "timestamp", order: str = "desc", page: int = Query(1, ge=1), page_size: int = Query(25, ge=1, le=100)):
    with Session() as db:
        rows = db.scalars(select(SecurityEvent)).all()
        rows = [e for e in rows if (not q or q.casefold() in (e.description + e.source_asset + (e.destination_asset or "")).casefold()) and (not severity or e.severity == severity) and (not event_type or e.event_type == event_type) and (not asset or asset in (e.source_asset, e.destination_asset)) and (not status or e.status == status)]
        key = {"timestamp": lambda x: x.timestamp, "severity": lambda x: ["Information", "Lav", "Middel", "Høj", "Kritisk"].index(x.severity), "risk_score": lambda x: x.risk_score}.get(sort)
        if not key:
            raise HTTPException(400, "Ugyldig sortering")
        rows.sort(key=key, reverse=order != "asc")
        total = len(rows)
        return {"items": [event_dict(e) for e in rows[(page - 1) * page_size:page * page_size]], "total": total, "page": page, "page_size": page_size}


@app.get("/api/events/{event_id}")
def get_event(event_id: str):
    with Session() as db:
        e = db.get(SecurityEvent, event_id)
        if not e:
            raise HTTPException(404, "Hændelse ikke fundet")
        notes = db.scalars(select(AnalystNote).where(AnalystNote.event_id == event_id).order_by(AnalystNote.created_at.desc())).all()
        return {**event_dict(e), "notes": [{"id": n.id, "body": n.body, "created_at": iso_utc(n.created_at)} for n in notes]}


@app.patch("/api/events/{event_id}/status")
def update_status(event_id: str, payload: StatusUpdate):
    with Session.begin() as db:
        e = db.get(SecurityEvent, event_id)
        if not e:
            raise HTTPException(404, "Hændelse ikke fundet")
        e.status = payload.status
        return event_dict(e)


@app.post("/api/events/{event_id}/notes", status_code=201)
def add_note(event_id: str, payload: NoteInput):
    with Session.begin() as db:
        if not db.get(SecurityEvent, event_id):
            raise HTTPException(404, "Hændelse ikke fundet")
        note = AnalystNote(id=str(uuid4()), event_id=event_id, body=payload.body, created_at=datetime.now(timezone.utc))
        db.add(note)
        return {"id": note.id, "body": note.body, "created_at": iso_utc(note.created_at)}


@app.get("/api/assets")
def list_assets():
    with Session() as db:
        return [{"id": a.id, "name": a.name, "kind": a.kind, "zone": a.zone, "criticality": a.criticality, "synthetic": a.synthetic} for a in db.scalars(select(Asset)).all()]


@app.get("/api/network/relationships")
def relationships():
    with Session() as db:
        grouped = {}
        for e in db.scalars(select(SecurityEvent).where(SecurityEvent.destination_asset.is_not(None))).all():
            key = (e.source_asset, e.destination_asset, e.protocol or "Ukendt")
            cur = grouped.setdefault(key, {"source": key[0], "destination": key[1], "protocol": key[2], "count": 0, "suspicious": False, "last_seen": iso_utc(e.timestamp)})
            cur["count"] += 1
            cur["suspicious"] = cur["suspicious"] or e.risk_score >= 60
            if iso_utc(e.timestamp) > cur["last_seen"]: cur["last_seen"] = iso_utc(e.timestamp)
        return list(grouped.values())


@app.get("/api/incidents")
def list_incidents():
    with Session() as db:
        return [{"id": i.id, "title": i.title, "severity": i.severity, "risk_score": i.risk_score, "status": i.status, "event_ids": json.loads(i.event_ids), "rationale": i.rationale, "created_at": iso_utc(i.created_at)} for i in db.scalars(select(Incident).order_by(Incident.created_at.desc())).all()]


@app.get("/api/sources")
def list_sources():
    with Session() as db:
        return [{"id": s.id, "name": s.name, "kind": s.kind, "status": s.status, "events_processed": s.events_processed, "last_ingestion": iso_utc(s.last_ingestion) if s.last_ingestion else None} for s in db.scalars(select(DataSource)).all()]


@app.get("/api/rules")
def rules():
    return [{"id": k, "name": v[1], "severity": ["Middel", "Høj", "Høj", "Kritisk"][idx], "version": "1.0", "enabled": True, "risk_contribution": v[2], "description": v[3]} for idx, (k, v) in enumerate(RULES.items())]


@app.post("/api/simulation")
def simulate(payload: ScenarioInput):
    cases = {
        "normal": [("network_connection", "Lav", "ws-ops-02", "scada-hmi-01", "Godkendt HMI-trafik inden for baseline", "OPC-UA")],
        "auth": [("auth_failure", "Middel", "ws-fin-04", None, "Flere fejlede logins efterfulgt af vellykket login", None)],
        "it_ot": [("network_connection", "Høj", "ws-eng-01", "plc-line-03", "IT/OT-forbindelse uden for tilladt policy", "Modbus/TCP")],
        "change": [("config_change", "Kritisk", "scada-srv-01", None, "Ugodkendt PLC-programkonfiguration ændret", None)],
        "correlated": [("auth_failure", "Middel", "ws-eng-01", None, "Gentagne fejlede loginforsøg på engineering station", None), ("remote_access", "Høj", "vpn-gateway-01", "scada-hmi-01", "Ekstern fjernadgang uden for vindue", "RDP"), ("network_connection", "Høj", "ws-eng-01", "plc-line-03", "Ny forbindelse fra engineering station til PLC", "Modbus/TCP")],
    }
    added = []
    with Session.begin() as db:
        now = datetime.now(timezone.utc)
        for index, item in enumerate(cases[payload.scenario]):
            row, fresh = add_event(db, *item[:5], protocol=item[5], timestamp=now + timedelta(microseconds=index), source_name="Simuleret")
            if fresh: added.append(row)
        source = db.get(DataSource, "demo-source")
        source.events_processed += len(added)
        source.last_ingestion = now
        if payload.scenario == "correlated" and added:
            db.add(Incident(id=str(uuid4()), title="Korrelateret mistænkelig aktivitet", severity="Høj", risk_score=91, status="Åben", event_ids=json.dumps([e.id for e in added]), rationale="Tre relaterede indikatorer på samme OT-sti inden for et kort tidsvindue understøtter en prioriteret undersøgelse."))
    return {"scenario": payload.scenario, "created": len(added), "events": [event_dict(e) for e in added], "message": "Scenariet er føjet til lokale demodata."}


@app.post("/api/import/preview")
async def preview_import(request: Request, filename: str = Query(..., max_length=200)):
    content = await request.body()
    content = content[:5 * 1024 * 1024 + 1]
    if len(content) > 5 * 1024 * 1024:
        raise HTTPException(413, "Filen overstiger grænsen på 5 MB")
    name = filename
    try:
        text = content.decode("utf-8-sig")
        if name.lower().endswith(".jsonl"):
            records = [json.loads(line) for line in text.splitlines() if line.strip()]
        elif name.lower().endswith(".csv"):
            records = list(csv.DictReader(io.StringIO(text)))
        else:
            value = json.loads(text)
            records = value if isinstance(value, list) else value.get("events", [value])
    except Exception as exc:
        raise HTTPException(400, "Filen kunne ikke læses som JSON, JSONL eller CSV") from exc
    valid, invalid = [], 0
    for item in records:
        if not isinstance(item, dict) or not item.get("event_type") or not item.get("timestamp") or not item.get("source_asset"):
            invalid += 1; continue
        try:
            datetime.fromisoformat(str(item["timestamp"]).replace("Z", "+00:00"))
            valid.append({k: item.get(k) for k in ["event_type", "timestamp", "source_asset", "destination_asset", "severity", "description", "protocol"]})
        except ValueError: invalid += 1
    return {"file_name": name, "valid": len(valid), "invalid": invalid, "records": valid[:100], "truncated": len(valid) > 100, "fields": sorted(set().union(*(r.keys() for r in records if isinstance(r, dict)))) if records else []}


@app.post("/api/import/commit")
def commit_import(records: list[dict[str, Any]]):
    if len(records) > 10000:
        raise HTTPException(413, "Maksimalt 10.000 hændelser pr. import")
    created = duplicates = 0
    with Session.begin() as db:
        for item in records:
            try:
                timestamp = datetime.fromisoformat(str(item["timestamp"]).replace("Z", "+00:00"))
            except (ValueError, KeyError):
                continue
            _, fresh = add_event(db, str(item.get("event_type", "unknown"))[:80], str(item.get("severity", "Information"))[:30], str(item["source_asset"])[:200], str(item["destination_asset"])[:200] if item.get("destination_asset") else None, str(item.get("description", "Importeret hændelse"))[:2000], str(item.get("protocol"))[:80] if item.get("protocol") else None, timestamp, "Filimport")
            created += int(fresh); duplicates += int(not fresh)
        source = DataSource(id=str(uuid4()), name="Filimport", kind="Upload", status="Aktiv", events_processed=created, last_ingestion=datetime.now(timezone.utc))
        db.add(source)
    return {"created": created, "duplicates": duplicates}


@app.get("/api/reports/events.csv")
def export_events():
    with Session() as db:
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["timestamp", "severity", "event_type", "source_asset", "destination_asset", "detection", "risk_score", "status", "description"])
        for e in db.scalars(select(SecurityEvent).order_by(SecurityEvent.timestamp.desc())).all():
            values = [e.timestamp.isoformat(), e.severity, e.event_type, e.source_asset, e.destination_asset or "", e.detection or "", e.risk_score, e.status, e.description]
            writer.writerow([("'" + v if isinstance(v, str) and v.startswith(("=", "+", "-", "@")) else v) for v in values])
        return __import__("fastapi").responses.Response(output.getvalue(), media_type="text/csv; charset=utf-8", headers={"Content-Disposition": "attachment; filename=ot-sentinel-events.csv"})
