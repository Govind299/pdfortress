"""
main.py
-------
FastAPI REST API server for PDFortress.
Handles file uploads, runs analysis (via Celery or direct fallback),
enforces IP rate-limiting, and serves scan endpoints to the React frontend.

Author: Raj Patel (23DIT050) & Govind Suthar (D24DIT094)
"""

import os
import uuid
import json
import time
from collections import defaultdict
from typing import Optional, List
from fastapi import FastAPI, File, UploadFile, Form, HTTPException, Depends, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from database import get_db, init_db, Scan, cleanup_expired_scans
from analyzer import analyze_pdf
from report_exporter import export_json_report, export_pdf_report


app = FastAPI(
    title="PDFortress API",
    description="Multi-layered static analysis pipeline for PDF malware detection.",
    version="1.0.0"
)

# Allow all localhost frontend origins (port 3000, 127.0.0.1, etc.)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------------------------------------------------------------------
# Server Hardening & API Rate Limiting (Raj Patel - 23DIT050)
# -------------------------------------------------------------------
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MB Limit
RATE_LIMIT_DURATION = 60          # 60 seconds window
MAX_UPLOADS_PER_MINUTE = 10        # Max 10 uploads per minute per IP

client_upload_timestamps = defaultdict(list)

@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    """
    Enforces IP-based request throttling on POST /api/upload.
    Restricts client IP to a maximum of 10 uploads per minute.
    Returns HTTP 429 Too Many Requests when rate limit is exceeded.
    """
    if request.url.path == "/api/upload" and request.method == "POST":
        client_ip = request.client.host if request.client else "127.0.0.1"
        now = time.time()

        # Clean up timestamps older than 60s
        client_upload_timestamps[client_ip] = [
            t for t in client_upload_timestamps[client_ip] if now - t < RATE_LIMIT_DURATION
        ]

        if len(client_upload_timestamps[client_ip]) >= MAX_UPLOADS_PER_MINUTE:
            return JSONResponse(
                status_code=429,
                content={
                    "detail": f"API Rate Limit Exceeded. Maximum {MAX_UPLOADS_PER_MINUTE} uploads per minute per IP allowed."
                }
            )
        client_upload_timestamps[client_ip].append(now)

    response = await call_next(request)
    return response


# Directory where uploaded PDFs will be saved
UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Create database tables on startup
init_db()


# -------------------------------------------------------------------
# Endpoints
# -------------------------------------------------------------------

@app.get("/health", tags=["System"])
def health_check():
    """
    Simple health check to verify the server is running.
    Returns 200 OK if everything is operational.
    """
    return {"status": "ok", "service": "PDFortress API"}


@app.post("/api/upload", tags=["Analysis"])
async def upload_pdf(
    file: UploadFile = File(...),
    password: Optional[str] = Form(None),
    db: Session = Depends(get_db)
):
    """
    Accepts a PDF upload, validates it, checks 100MB file size limit & IP rate limit,
    saves it securely, runs static analysis, and returns the scan ID.

    Security measures:
    - Validates file extension is .pdf
    - Enforces 100MB maximum file size limit (HTTP 413 Payload Too Large)
    - Enforces IP Rate-Limiting (HTTP 429 Too Many Requests)
    - Strips original filename and replaces with UUID to prevent path traversal
    - Optional password authentication for encrypted PDF decryption
    """

    # Validation: Only accept PDF files
    if not file.filename.lower().endswith(".pdf"):
        raise HTTPException(
            status_code=400,
            detail="Invalid file type. Only PDF files are accepted."
        )

    contents = await file.read()

    # Server Hardening: Enforce 100 MB Maximum File Size Limit
    if len(contents) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=413,
            detail="File size exceeds maximum allowed limit of 100 MB."
        )

    # Secure Storage: Replace original name with a random UUID
    safe_filename = f"{uuid.uuid4().hex}.pdf"
    file_path = os.path.join(UPLOAD_DIR, safe_filename)

    with open(file_path, "wb") as f:
        f.write(contents)

    # Create initial pending scan record in database
    scan_record = Scan(
        original_filename=file.filename,
        stored_filename=safe_filename,
        status="PENDING",
        verdict="Processing...",
        risk_score=0.0
    )
    db.add(scan_record)
    db.commit()
    db.refresh(scan_record)

    analysis_report = {}

    # Run analysis (Celery async dispatch if Redis is online, otherwise instant fallback)
    celery_queued = False
    try:
        import redis
        r = redis.Redis(host="localhost", port=6379, socket_connect_timeout=0.1)
        if r.ping():
            from celery_worker import process_pdf_scan
            process_pdf_scan.delay(scan_record.id, file_path, password)
            message = "File uploaded and task queued for Celery analysis."
            celery_queued = True
    except Exception:
        celery_queued = False

    if not celery_queued:
        # Instant microsecond fallback execution if Redis is offline
        analysis_report = analyze_pdf(file_path, password=password)
        scan_record.verdict = analysis_report["verdict"]
        scan_record.risk_score = analysis_report["risk_score"]
        scan_record.is_encrypted = 1 if analysis_report["is_encrypted"] else 0
        scan_record.page_count = analysis_report.get("page_count")
        scan_record.author = analysis_report.get("author")
        scan_record.analysis_summary = json.dumps(analysis_report)
        scan_record.status = "COMPLETED"
        db.commit()
        db.refresh(scan_record)
        message = "File uploaded and analyzed directly."

    return {
        "message": message,
        "scan_id": scan_record.id,
        "original_filename": file.filename,
        "verdict": scan_record.verdict,
        "risk_score": scan_record.risk_score,
        "status": scan_record.status,
        "is_encrypted": bool(scan_record.is_encrypted),
        "page_count": scan_record.page_count,
        "author": scan_record.author,
        "sha256": analysis_report.get("sha256", ""),
        "dangerous_tags_found": analysis_report.get("dangerous_tags_found", {}),
        "yara_matches": analysis_report.get("yara_matches", []),
        "virustotal": analysis_report.get("virustotal", {}),
        "warnings": analysis_report.get("warnings", [])
    }




@app.get("/api/scans", tags=["History"])
def get_scan_history(
    limit: Optional[int] = Query(None, ge=1, le=100),
    offset: Optional[int] = Query(0, ge=0),
    db: Session = Depends(get_db)
):
    """
    Returns historical scan logs with optional server-side pagination (limit & offset).
    """
    query = db.query(Scan).order_by(Scan.upload_time.desc())
    total_count = query.count()

    if limit is not None:
        query = query.offset(offset).limit(limit)

    scans = query.all()

    scans_list = [
        {
            "id": s.id,
            "original_filename": s.original_filename,
            "upload_time": s.upload_time.isoformat() if s.upload_time else None,
            "status": getattr(s, "status", "COMPLETED"),
            "verdict": s.verdict,
            "risk_score": s.risk_score,
            "is_encrypted": bool(s.is_encrypted),
            "page_count": s.page_count,
            "author": s.author,
        }
        for s in scans
    ]

    if limit is not None:
        return {
            "total": total_count,
            "scans": scans_list
        }
    return scans_list


@app.get("/api/scans/{scan_id}", tags=["Analysis"])
def get_single_scan(scan_id: int, db: Session = Depends(get_db)):
    """
    Returns the status and full security report for a specific scan ID.
    Used by the frontend polling loop and detail modal window.
    """
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan record not found")

    summary = json.loads(scan.analysis_summary) if scan.analysis_summary else {}

    return {
        "scan_id": scan.id,
        "original_filename": scan.original_filename,
        "upload_time": scan.upload_time.isoformat() if scan.upload_time else None,
        "status": scan.status or "COMPLETED",
        "verdict": scan.verdict,
        "risk_score": scan.risk_score,
        "is_encrypted": bool(scan.is_encrypted),
        "page_count": scan.page_count,
        "author": scan.author,
        "sha256": summary.get("sha256", ""),
        "dangerous_tags_found": summary.get("dangerous_tags_found", {}),
        "yara_matches": summary.get("yara_matches", []),
        "virustotal": summary.get("virustotal", {}),
        "warnings": summary.get("warnings", []),
    }


# -------------------------------------------------------------------
# Week 8 Additions: Batch Endpoints, Exporters & DB Cleanup (Raj Patel)
# -------------------------------------------------------------------

@app.post("/api/upload/batch", tags=["Analysis"])
async def upload_pdf_batch(
    files: List[UploadFile] = File(...),
    db: Session = Depends(get_db)
):
    """
    Accepts concurrent multi-file PDF payload arrays, assigns a batch tracking UUID,
    and queues all documents for security analysis.
    Author: Raj Patel (23DIT007)
    """
    if not files:
        raise HTTPException(status_code=400, detail="No files provided in batch upload request.")

    batch_id = uuid.uuid4().hex
    queued_scans = []

    for file in files:
        if not file.filename.lower().endswith(".pdf"):
            continue

        contents = await file.read()
        if len(contents) > MAX_FILE_SIZE:
            continue

        safe_filename = f"{uuid.uuid4().hex}.pdf"
        file_path = os.path.join(UPLOAD_DIR, safe_filename)

        with open(file_path, "wb") as f:
            f.write(contents)

        scan_record = Scan(
            original_filename=file.filename,
            stored_filename=safe_filename,
            status="PENDING",
            verdict="Processing...",
            risk_score=0.0,
            batch_id=batch_id
        )
        db.add(scan_record)
        db.commit()
        db.refresh(scan_record)

        # Run analysis (direct synchronous fallback or celery)
        analysis_report = analyze_pdf(file_path)
        scan_record.verdict = analysis_report["verdict"]
        scan_record.risk_score = analysis_report["risk_score"]
        scan_record.is_encrypted = 1 if analysis_report["is_encrypted"] else 0
        scan_record.page_count = analysis_report.get("page_count")
        scan_record.author = analysis_report.get("author")
        scan_record.analysis_summary = json.dumps(analysis_report)
        scan_record.status = "COMPLETED"
        db.commit()

        queued_scans.append({
            "scan_id": scan_record.id,
            "filename": scan_record.original_filename,
            "verdict": scan_record.verdict,
            "risk_score": scan_record.risk_score
        })

    return {
        "batch_id": batch_id,
        "total_files": len(files),
        "processed_count": len(queued_scans),
        "scans": queued_scans
    }


@app.get("/api/scans/batch/{batch_id}", tags=["Analysis"])
def get_batch_status(batch_id: str, db: Session = Depends(get_db)):
    """
    Delivers aggregated completion status, item counts, and scan IDs for a batch job.
    Author: Raj Patel (23DIT007)
    """
    scans = db.query(Scan).filter(Scan.batch_id == batch_id).all()
    if not scans:
        raise HTTPException(status_code=404, detail=f"No batch found with ID {batch_id}")

    completed = sum(1 for s in scans if s.status == "COMPLETED")
    
    return {
        "batch_id": batch_id,
        "total_items": len(scans),
        "completed_items": completed,
        "status": "COMPLETED" if completed == len(scans) else "PROCESSING",
        "scans": [
            {
                "scan_id": s.id,
                "filename": s.original_filename,
                "verdict": s.verdict,
                "risk_score": s.risk_score,
                "status": s.status
            }
            for s in scans
        ]
    }


@app.get("/api/scans/{scan_id}/export/pdf", tags=["Reporting"])
def export_pdf_security_report(scan_id: int, db: Session = Depends(get_db)):
    """
    Generates and downloads a structured PDF security audit report.
    Author: Govind Suthar (D24DIT094)
    """
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan record not found")

    summary = json.loads(scan.analysis_summary) if scan.analysis_summary else {}
    scan_data = {
        "scan_id": scan.id,
        "original_filename": scan.original_filename,
        "upload_time": scan.upload_time.isoformat() if scan.upload_time else "",
        "verdict": scan.verdict,
        "risk_score": scan.risk_score,
        "is_encrypted": bool(scan.is_encrypted),
        "page_count": scan.page_count,
        "author": scan.author,
        "sha256": summary.get("sha256", ""),
        "dangerous_tags_found": summary.get("dangerous_tags_found", {}),
        "yara_matches": summary.get("yara_matches", []),
        "virustotal": summary.get("virustotal", {}),
        "warnings": summary.get("warnings", [])
    }

    pdf_bytes = export_pdf_report(scan_data)
    filename = f"PDFortress_Audit_Scan_{scan_id}.pdf"

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )


@app.get("/api/scans/{scan_id}/export/json", tags=["Reporting"])
def export_json_security_report(scan_id: int, db: Session = Depends(get_db)):
    """
    Generates and downloads a structured JSON security audit report.
    Author: Govind Suthar (D24DIT094)
    """
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan record not found")

    summary = json.loads(scan.analysis_summary) if scan.analysis_summary else {}
    scan_data = {
        "scan_id": scan.id,
        "original_filename": scan.original_filename,
        "upload_time": scan.upload_time.isoformat() if scan.upload_time else "",
        "verdict": scan.verdict,
        "risk_score": scan.risk_score,
        "is_encrypted": bool(scan.is_encrypted),
        "page_count": scan.page_count,
        "author": scan.author,
        "sha256": summary.get("sha256", ""),
        "dangerous_tags_found": summary.get("dangerous_tags_found", {}),
        "yara_matches": summary.get("yara_matches", []),
        "virustotal": summary.get("virustotal", {}),
        "warnings": summary.get("warnings", [])
    }

    json_bytes = export_json_report(scan_data)
    filename = f"PDFortress_Audit_Scan_{scan_id}.json"

    return Response(
        content=json_bytes,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )


@app.post("/api/admin/cleanup", tags=["System"])
def trigger_server_cleanup(hours: int = 24):
    """
    Triggers automated cleanup of temporary files and database logs older than specified hours.
    Author: Raj Patel (23DIT007)
    """
    result = cleanup_expired_scans(hours=hours, upload_dir=UPLOAD_DIR)
    return {
        "status": "success",
        "message": f"Cleaned {result['cleaned_files']} temporary files and {result['cleaned_records']} expired database records older than {hours} hours."
    }

