import html
import ipaddress
import json
import os
import posixpath
import socket
import uuid
from datetime import datetime, timezone
from urllib.parse import unquote, urlsplit

import httpx
from fastapi import Depends, FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from .database import Base, SessionLocal, engine
from .models import Finding, Scan, Target

app = FastAPI(title="Web Assessment Workbench API", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("FRONTEND_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000").split(","),
    allow_methods=["GET", "POST", "PATCH"], allow_headers=["Content-Type"],
)

@app.on_event("startup")
def initialize_database():
    Base.metadata.create_all(bind=engine)

def get_db():
    with SessionLocal() as session:
        yield session

class TargetRequest(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    url: str = Field(min_length=8, max_length=2048)
    owner_contact: str = Field(min_length=3, max_length=200)
    authorized: bool
    in_scope: list[str] = Field(min_length=1, max_length=100)
    out_of_scope: list[str] = Field(default_factory=list, max_length=100)

class VerificationRequest(BaseModel):
    verification: str = Field(pattern="^(confirmed|rejected|needs_review)$")
    assessor_severity: str | None = Field(default=None, pattern="^(critical|high|medium|low|info)$")
    comment: str = Field(default="", max_length=10000)

def validate_public_http_url(value: str) -> str:
    try:
        parsed = urlsplit(value.strip())
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("Use a complete HTTP or HTTPS URL.")
        if parsed.username or parsed.password:
            raise ValueError("URLs must not contain credentials.")
        if parsed.port is not None and not 1 <= parsed.port <= 65535:
            raise ValueError("URL port must be between 1 and 65,535.")
        host = parsed.hostname.rstrip(".").lower()
        if host == "localhost" or host.endswith(".localhost") or host.endswith(".local"):
            raise ValueError("Local and internal hostnames are not allowed.")
        try:
            addresses = {ipaddress.ip_address(host)}
        except ValueError:
            records = socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80), type=socket.SOCK_STREAM)
            addresses = {ipaddress.ip_address(record[4][0]) for record in records}
        if not addresses or any(not address.is_global for address in addresses):
            raise ValueError("Targets must resolve only to public IP addresses.")
        return parsed.geturl()
    except (ValueError, OSError, socket.gaierror) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

def origin(parts):
    default_port = 443 if parts.scheme == "https" else 80
    return parts.scheme.lower(), (parts.hostname or "").lower(), parts.port or default_port

async def check_http(url: str | None, path: str = "") -> dict:
    if not url:
        return {"status": "disconnected", "detail": "Not configured"}
    try:
        async with httpx.AsyncClient(timeout=3, follow_redirects=False) as client:
            response = await client.get(url.rstrip("/") + path)
        if 200 <= response.status_code < 300:
            return {"status": "connected", "detail": f"Health endpoint returned HTTP {response.status_code}"}
        return {"status": "error", "detail": f"Health endpoint returned HTTP {response.status_code}"}
    except Exception as exc:
        return {"status": "error", "detail": f"Health check failed: {type(exc).__name__}"}

@app.get("/health")
async def health():
    zap = await check_http(os.getenv("ZAP_BASE_URL"), "/JSON/core/view/version/?apikey=" + os.getenv("ZAP_API_KEY", ""))
    database = {"status": "disconnected", "detail": "Not configured"}
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        database = {"status": "connected", "detail": "Database query succeeded"}
    except Exception:
        database = {"status": "disconnected", "detail": "Database query failed"}
    return {"status": "ok", "services": {"api": {"status": "connected", "detail": "Responding"}, "database": database, "zap": zap, "ai": {"status": "disconnected", "detail": "Not configured"}}}

@app.post("/targets/validate")
def validate_target(target: TargetRequest, db: Session = Depends(get_db)):
    if not target.authorized:
        raise HTTPException(status_code=400, detail="Explicit authorization is required before registering a target.")
    root = validate_public_http_url(target.url)
    root_host = urlsplit(root).hostname
    normalized_scope = [validate_public_http_url(item) for item in target.in_scope]
    if any(urlsplit(item).hostname != root_host or origin(urlsplit(item)) != origin(urlsplit(root)) for item in normalized_scope):
        raise HTTPException(status_code=422, detail="Every in-scope URL must use the registered target host, scheme, and port.")
    normalized_out = [validate_public_http_url(item) for item in target.out_of_scope]
    saved = Target(id=str(uuid.uuid4()), name=target.name, url=root, owner_contact=target.owner_contact,
                   in_scope=normalized_scope, out_of_scope=normalized_out, authorization_confirmed=True)
    db.add(saved)
    db.commit()
    return {"valid": True, "target": target_payload(saved), "message": "Authorization and public URL checks passed. Target saved; no scan was started."}

def target_payload(target: Target) -> dict:
    return {"id": target.id, "name": target.name, "url": target.url, "owner_contact": target.owner_contact,
            "in_scope": target.in_scope, "out_of_scope": target.out_of_scope,
            "authorization_confirmed": target.authorization_confirmed,
            "created_at": target.created_at.isoformat() if target.created_at else None}

def finding_payload(finding: Finding) -> dict:
    return {"id": finding.id, "scan_id": finding.scan_id, "title": finding.title, "url": finding.url,
            "category": finding.category, "scanner_severity": finding.scanner_severity,
            "description": finding.description, "remediation": finding.remediation, "evidence": finding.evidence,
            "classification": finding.classification, "scanner_observation": finding.scanner_observation,
            "verification": finding.verification, "assessor_severity": finding.assessor_severity,
            "assessor_comment": finding.assessor_comment,
            "created_at": finding.created_at.isoformat() if finding.created_at else None}

def scan_payload(scan: Scan, db: Session) -> dict:
    return {"id": scan.id, "target_id": scan.target_id, "source": scan.source, "status": scan.status,
            "configuration": scan.configuration, "created_at": scan.created_at.isoformat() if scan.created_at else None,
            "findings_count": db.scalar(select(func.count(Finding.id)).where(Finding.scan_id == scan.id)) or 0}

@app.get("/targets")
def list_targets(db: Session = Depends(get_db)):
    return [target_payload(item) for item in db.scalars(select(Target).order_by(Target.created_at.desc())).all()]

@app.get("/scans")
def list_scans(target_id: str | None = None, db: Session = Depends(get_db)):
    query = select(Scan)
    if target_id:
        query = query.where(Scan.target_id == target_id)
    return [scan_payload(item, db) for item in db.scalars(query.order_by(Scan.created_at.desc())).all()]

def url_in_scope(candidate: str, target: Target) -> bool:
    try:
        parsed = urlsplit(candidate)
        if parsed.scheme not in {"http", "https"} or parsed.username or parsed.password or origin(parsed) != origin(urlsplit(target.url)):
            return False
        path = posixpath.normpath(unquote(unquote(parsed.path or "/")))
        if not path.startswith("/"):
            path = "/" + path
        allowed = False
        for entry in target.in_scope:
            scope = urlsplit(entry)
            base = posixpath.normpath(unquote(unquote(scope.path or "/")))
            if path == base or base == "/" or path.startswith(base.rstrip("/") + "/"):
                allowed = True
                break
        if not allowed:
            return False
        for entry in target.out_of_scope:
            scope = urlsplit(entry)
            base = posixpath.normpath(unquote(unquote(scope.path or "/")))
            if origin(scope) == origin(parsed) and (path == base or path.startswith(base.rstrip("/") + "/")):
                return False
        return True
    except ValueError:
        return False

@app.post("/targets/{target_id}/scans/import-zap")
def import_zap(target_id: str, file: UploadFile = File(...), db: Session = Depends(get_db)):
    target = db.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found.")
    raw = file.file.read(10_000_001)
    if len(raw) > 10_000_000:
        raise HTTPException(status_code=413, detail="ZAP JSON file exceeds the 10 MB limit.")
    try:
        report = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=422, detail="Upload a valid ZAP JSON report.") from exc
    sites = report.get("site", []) if isinstance(report, dict) else []
    if not isinstance(sites, list):
        raise HTTPException(status_code=422, detail="ZAP JSON must contain a site list.")
    alerts = [alert for site in sites if isinstance(site, dict) for alert in site.get("alerts", []) if isinstance(alert, dict)]
    if len(alerts) > 1000:
        raise HTTPException(status_code=413, detail="ZAP report contains more than 1,000 alerts.")
    scan_id = str(uuid.uuid4())
    scan = Scan(id=scan_id, target_id=target.id, configuration={"source":"uploaded_zap_json", "active_scan":False}, raw_output=report)
    db.add(scan)
    created = 0
    skipped = 0
    for alert in alerts:
        instances = alert.get("instances") or [{}]
        for instance in instances:
            if not isinstance(instance, dict):
                continue
            url = str(instance.get("uri") or alert.get("url") or "")
            if not url_in_scope(url, target):
                skipped += 1
                continue
            observation = {"alert":alert.get("alert"), "risk":alert.get("risk"), "confidence":alert.get("confidence"),
                           "url":url, "method":instance.get("method"), "param":instance.get("param"),
                           "attack":instance.get("attack"), "evidence":instance.get("evidence"), "reference":alert.get("reference")}
            finding = Finding(id=str(uuid.uuid4()), scan_id=scan_id, title=str(alert.get("alert") or "ZAP alert"), url=url,
                              category=str(alert.get("name") or "Unclassified scanner alert"),
                              scanner_severity=str(alert.get("risk") or "Informational").lower(),
                              description=str(alert.get("description") or ""), remediation=str(alert.get("solution") or ""),
                              evidence=str(instance.get("evidence") or instance.get("attack") or ""),
                              classification={"cwe":alert.get("cweid"), "wasc":alert.get("wascid"), "reference":alert.get("reference")},
                              scanner_observation=observation)
            db.add(finding)
            created += 1
    db.commit()
    return {"scan_id":scan_id, "status":"complete", "findings_imported":created, "instances_skipped_outside_scope":skipped,
            "confirmed_findings":0, "message":"Imported scanner observations only. Every finding still needs assessor review."}

@app.get("/findings")
def list_findings(target_id: str | None = None, verification: str | None = None, db: Session = Depends(get_db)):
    query = select(Finding)
    if target_id:
        query = query.join(Scan, Finding.scan_id == Scan.id).where(Scan.target_id == target_id)
    if verification:
        query = query.where(Finding.verification == verification)
    return [finding_payload(item) for item in db.scalars(query.order_by(Finding.created_at.desc())).all()]

@app.patch("/findings/{finding_id}/verification")
def verify_finding(finding_id: str, decision: VerificationRequest, db: Session = Depends(get_db)):
    finding = db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found.")
    if decision.verification == "confirmed" and not decision.assessor_severity:
        raise HTTPException(status_code=422, detail="Set an assessor severity when confirming a finding.")
    finding.verification = decision.verification
    finding.assessor_severity = decision.assessor_severity if decision.verification == "confirmed" else None
    finding.assessor_comment = decision.comment
    finding.verified_at = datetime.now(timezone.utc)
    db.commit()
    return finding_payload(finding)

@app.get("/reports/{scan_id}")
def assessment_report(scan_id: str, db: Session = Depends(get_db)):
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")
    target = db.get(Target, scan.target_id)
    findings = db.scalars(select(Finding).where(Finding.scan_id == scan_id).order_by(Finding.created_at)).all()
    confirmed = [item for item in findings if item.verification == "confirmed"]
    rows = "".join(
        "<article><h2>" + html.escape(item.title) + "</h2><p><b>Severity:</b> "
        + html.escape(item.assessor_severity or "Unassigned") + " · <b>Scanner severity:</b> "
        + html.escape(item.scanner_severity) + " · <b>URL:</b> " + html.escape(item.url)
        + "</p><p>" + html.escape(item.description) + "</p><p><b>Evidence:</b> "
        + html.escape(item.evidence or "No evidence supplied") + "</p><p><b>Remediation:</b> "
        + html.escape(item.remediation) + "</p></article>" for item in confirmed
    )
    in_scope = "".join("<li>" + html.escape(item) + "</li>" for item in target.in_scope)
    out_scope = "".join("<li>" + html.escape(item) + "</li>" for item in target.out_of_scope)
    report = (
        "<!doctype html><html><meta charset='utf-8'><title>Assessment report</title>"
        "<style>body{font:16px/1.6 Arial,sans-serif;max-width:850px;margin:40px auto;color:#191919}"
        "h1{color:#e85002}article{border-top:1px solid #ccc;padding:12px 0}</style>"
        "<h1>Security Assessment Report</h1><p><b>Target:</b> " + html.escape(target.name) + " (" + html.escape(target.url) + ")</p>"
        "<p><b>Owner contact:</b> " + html.escape(target.owner_contact) + "</p>"
        "<p><b>Authorization:</b> assessor confirmation recorded at registration; authorization documents were not independently verified by this platform.</p>"
        "<h2>Assessment scope</h2><b>In scope</b><ul>" + in_scope + "</ul><b>Out of scope</b><ul>" + out_scope + "</ul>"
        "<h2>Method and tools</h2><p>OWASP ZAP JSON report imported by the assessor. No spider, passive scan, active scan, or Nmap command was initiated by this platform.</p>"
        "<p><b>Import configuration:</b> " + html.escape(json.dumps(scan.configuration, sort_keys=True)) + "</p>"
        "<p><b>Import date:</b> " + html.escape(scan.created_at.isoformat()) + "</p>"
        "<p><b>Confirmed findings:</b> " + str(len(confirmed)) + " · <b>Unconfirmed:</b> " + str(len(findings)-len(confirmed)) + "</p>"
        "<h2>Confirmed vulnerabilities</h2>" + (rows or "<p>No findings have been confirmed by an assessor.</p>")
        + "<h2>Limitations</h2><p>This report includes uploaded ZAP observations and assessor decisions only. "
        "AI analysis and independent technical validation were not performed by this version.</p>"
        "<h2>Conclusion</h2><p>" + str(len(confirmed)) + " finding(s) were marked Confirmed by the assessor. "
        "This result is limited to the supplied scanner report and recorded review.</p></html>"
    )
    from fastapi.responses import HTMLResponse
    return HTMLResponse(report, headers={"Content-Disposition":"attachment; filename=assessment-" + scan_id + ".html"})
