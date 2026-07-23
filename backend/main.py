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

# Allow the React frontend (running on port 3000) to call this API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
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

    # --- Run the static analysis engine ---
    analysis_report = analyze_pdf(file_path)

    # --- Save result to database ---
    scan_record = Scan(
        original_filename=file.filename,
        stored_filename=safe_filename,
        verdict=analysis_report["verdict"],
        risk_score=analysis_report["risk_score"],
        is_encrypted=1 if analysis_report["is_encrypted"] else 0,
        page_count=analysis_report.get("page_count"),
        author=analysis_report.get("author"),
        analysis_summary=json.dumps(analysis_report),
    )
    db.add(scan_record)
    db.commit()
    db.refresh(scan_record)

    return {
        "message": "Analysis complete.",
        "scan_id": scan_record.id,
        "original_filename": file.filename,
        "verdict": analysis_report["verdict"],
        "risk_score": analysis_report["risk_score"],
        "is_encrypted": analysis_report["is_encrypted"],
        "page_count": analysis_report["page_count"],
        "author": analysis_report["author"],
        "dangerous_tags_found": analysis_report["dangerous_tags_found"],
        "warnings": analysis_report["warnings"],
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
            "verdict": s.verdict,
            "risk_score": s.risk_score,
            "is_encrypted": bool(s.is_encrypted),
            "page_count": s.page_count,
            "author": s.author,
        }
        for s in scans
    ]
