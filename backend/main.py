"""
main.py
-------
FastAPI application entry point for PDFortress.
Exposes three REST API endpoints:
  - GET  /health          → Server health check
  - POST /api/upload      → Secure PDF upload + analysis trigger
  - GET  /api/scans       → Retrieve scan history

Author: Govind Suthar (D24DIT094)
"""

import uuid
import os
import json

from fastapi import FastAPI, File, UploadFile, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from database import init_db, get_db, Scan
from analyzer import analyze_pdf

# -------------------------------------------------------------------
# App initialization
# -------------------------------------------------------------------
app = FastAPI(
    title="PDFortress API",
    description="A multi-layered PDF malware static analysis platform.",
    version="0.1.0"
)

# Allow all localhost frontend origins (port 3000, 127.0.0.1, etc.)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

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
async def upload_pdf(file: UploadFile = File(...), db: Session = Depends(get_db)):
    """
    Accepts a PDF upload, validates it, saves it securely, runs static
    analysis, and returns the full security report.

    Security measures:
    - Validates the file extension is .pdf
    - Strips the original filename and replaces it with a UUID
      to prevent path traversal attacks.
    """

    # --- Validation: Only accept PDF files ---
    if not file.filename.lower().endswith(".pdf"):
        raise HTTPException(
            status_code=400,
            detail="Invalid file type. Only PDF files are accepted."
        )

    # --- Secure Storage: Replace original name with a random UUID ---
    safe_filename = f"{uuid.uuid4().hex}.pdf"
    file_path = os.path.join(UPLOAD_DIR, safe_filename)

    contents = await file.read()
    with open(file_path, "wb") as f:
        f.write(contents)

    # --- Create initial pending scan record in database ---
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

    # --- Run analysis (Celery async dispatch with sync fallback) ---
    try:
        from celery_worker import process_pdf_scan
        process_pdf_scan.delay(scan_record.id, file_path)
        message = "File uploaded and task queued for Celery analysis."
    except Exception as err:
        # Fallback to direct synchronous execution if Celery dispatch fails
        analysis_report = analyze_pdf(file_path)
        scan_record.verdict = analysis_report["verdict"]
        scan_record.risk_score = analysis_report["risk_score"]
        scan_record.is_encrypted = 1 if analysis_report["is_encrypted"] else 0
        scan_record.page_count = analysis_report.get("page_count")
        scan_record.author = report.get("author") if (report := analysis_report) else None
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
        "status": scan_record.status
    }


@app.get("/api/scans", tags=["History"])
def get_scan_history(db: Session = Depends(get_db)):
    """
    Returns a list of all previously scanned files with their verdicts.
    Used to populate the scan history dashboard on the frontend.
    """
    scans = db.query(Scan).order_by(Scan.upload_time.desc()).all()

    return [
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


@app.get("/api/scans/{scan_id}", tags=["Analysis"])
def get_single_scan(scan_id: int, db: Session = Depends(get_db)):
    """
    Returns the status and full security report for a specific scan ID.
    Used by the frontend polling loop to track asynchronous task progress.
    """
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan record not found")

    summary = json.loads(scan.analysis_summary) if scan.analysis_summary else {}

    return {
        "scan_id": scan.id,
        "original_filename": scan.original_filename,
        "status": scan.status or "COMPLETED",
        "verdict": scan.verdict,
        "risk_score": scan.risk_score,
        "is_encrypted": bool(scan.is_encrypted),
        "page_count": scan.page_count,
        "author": scan.author,
        "dangerous_tags_found": summary.get("dangerous_tags_found", {}),
        "yara_matches": summary.get("yara_matches", []),
        "warnings": summary.get("warnings", []),
    }
