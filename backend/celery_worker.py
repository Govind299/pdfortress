"""
celery_worker.py
----------------
Asynchronous background task queue definition for PDFortress.
Handles background PDF parsing without blocking the primary API server.

Author: Govind Suthar (D24DIT094)
"""

import os
import json
from celery import Celery

from database import SessionLocal, Scan
from analyzer import analyze_pdf

# Redis broker URL
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

celery_app = Celery(
    "pdfortress_worker",
    broker=REDIS_URL,
    backend=REDIS_URL
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
)


@celery_app.task(name="tasks.process_pdf_scan")
def process_pdf_scan(scan_id: int, file_path: str):
    """
    Background worker task. Reads the PDF file from disk, runs static analysis,
    and updates the database record with findings.
    """
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return {"error": f"Scan ID {scan_id} not found in database"}

        scan.status = "PROCESSING"
        db.commit()

        # Run static analysis engine (PyMuPDF + raw byte scanning)
        report = analyze_pdf(file_path)

        # Update database with results
        scan.verdict = report["verdict"]
        scan.risk_score = report["risk_score"]
        scan.is_encrypted = 1 if report["is_encrypted"] else 0
        scan.page_count = report.get("page_count")
        scan.author = report.get("author")
        scan.analysis_summary = json.dumps(report)
        scan.status = "COMPLETED"

        db.commit()
        return report

    except Exception as e:
        if scan:
            scan.status = "FAILED"
            db.commit()
        raise e
    finally:
        db.close()
