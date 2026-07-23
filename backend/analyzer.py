"""
analyzer.py
-----------
Core static analysis engine for PDFortress.
Safely inspects the raw structure of a PDF file WITHOUT executing it.

Two-tool approach:
  1. PyMuPDF (fitz) - Extracts metadata (pages, author, encryption status)
  2. Raw byte scanning - Detects dangerous structural keywords (pdfid-style)

Author: Govind Suthar (D24DIT094)
"""

import fitz  # PyMuPDF
import json


# -------------------------------------------------------------------
# Risk weights for each dangerous structural keyword found in the PDF.
# Based on known PDF malware research (Cannell et al., Leder & Werner).
# -------------------------------------------------------------------
RISK_WEIGHTS = {
    "/JS":             50,   # Embedded JavaScript
    "/JavaScript":     50,   # Alternate JS tag
    "/OpenAction":     60,   # Auto-executes when the PDF is opened
    "/Launch":         80,   # Launches an external program/command
    "/EmbeddedFiles":  30,   # Files hidden inside the PDF structure
    "/AA":             20,   # Additional Actions (triggers on events)
    "/RichMedia":      20,   # Embedded Flash or rich media
    "/XFA":            15,   # XML Forms Architecture (often abused)
}

# -------------------------------------------------------------------
# Verdict thresholds
# -------------------------------------------------------------------
VERDICT_SAFE       = "Safe"
VERDICT_SUSPICIOUS = "Suspicious"
VERDICT_MALICIOUS  = "Malicious"


def _compute_verdict(score: float) -> str:
    """Maps a numeric risk score to a human-readable verdict."""
    if score >= 71:
        return VERDICT_MALICIOUS
    elif score >= 31:
        return VERDICT_SUSPICIOUS
    return VERDICT_SAFE


def _scan_raw_bytes(file_path: str) -> dict:
    """
    Reads the PDF as raw bytes and counts occurrences of dangerous keywords.
    This is equivalent to what the pdfid tool does internally.
    Returns a dict of {keyword: count}.
    """
    findings = {}
    try:
        with open(file_path, "rb") as f:
            raw_content = f.read().decode("latin-1", errors="replace")

        for keyword in RISK_WEIGHTS:
            count = raw_content.count(keyword)
            if count > 0:
                findings[keyword] = count
    except Exception as e:
        findings["_scan_error"] = str(e)

    return findings


def analyze_pdf(file_path: str) -> dict:
    """
    Main analysis function. Takes the path to a stored PDF and returns
    a complete analysis report as a Python dictionary.

    Steps:
      1. Open safely with PyMuPDF to extract metadata.
      2. Check for encryption (password-protected files).
      3. Scan raw bytes for dangerous structural keywords.
      4. Calculate the final risk score and verdict.
    """
    report = {
        "file_path": file_path,
        "verdict": VERDICT_SAFE,
        "risk_score": 0.0,
        "is_encrypted": False,
        "page_count": 0,
        "author": "Unknown",
        "creator": "Unknown",
        "dangerous_tags_found": {},
        "warnings": [],
        "analysis_successful": True,
    }

    # ------------------------------------------------------------------
    # STEP 1: Open the PDF and extract metadata using PyMuPDF
    # ------------------------------------------------------------------
    try:
        doc = fitz.open(file_path)
    except Exception as e:
        report["analysis_successful"] = False
        report["warnings"].append(f"Could not open file: {str(e)}")
        report["verdict"] = VERDICT_SUSPICIOUS
        report["risk_score"] = 40.0
        return report

    # ------------------------------------------------------------------
    # STEP 2: Check for encryption (password protection)
    # Mentor Query #3 — Addressing handling of encrypted PDFs.
    # ------------------------------------------------------------------
    if doc.is_encrypted:
        report["is_encrypted"] = True
        report["warnings"].append(
            "File is password-protected (encrypted). "
            "Deep structural analysis is not possible on encrypted files. "
            "Treat with caution."
        )
        report["verdict"] = VERDICT_SUSPICIOUS
        report["risk_score"] = 40.0
        doc.close()
        return report

    # Extract PDF metadata
    # Mentor Query #1 — This is how we view PDF properties.
    metadata = doc.metadata
    report["page_count"] = doc.page_count
    report["author"] = metadata.get("author", "Unknown") or "Unknown"
    report["creator"] = metadata.get("creator", "Unknown") or "Unknown"
    doc.close()

    # ------------------------------------------------------------------
    # STEP 3: Scan raw bytes for dangerous structural keywords
    # Mentor Query #2 — This is how malware is detected.
    # ------------------------------------------------------------------
    dangerous_tags = _scan_raw_bytes(file_path)
    report["dangerous_tags_found"] = dangerous_tags

    # ------------------------------------------------------------------
    # STEP 4: Calculate risk score
    # ------------------------------------------------------------------
    total_score = 0.0
    for tag, count in dangerous_tags.items():
        if tag in RISK_WEIGHTS and count > 0:
            total_score += RISK_WEIGHTS[tag]

    report["risk_score"] = round(total_score, 2)
    report["verdict"] = _compute_verdict(total_score)

    return report
