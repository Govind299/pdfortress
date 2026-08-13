"""
create_test_pdfs.py
-------------------
Helper script to generate local test PDF files for PDFortress Week 6 feature testing:
  1. large_105mb_test.pdf (>100MB File Size Limit Test)
  2. protected_safe_sample.pdf (Clean Password-Protected PDF, Password: secret123)
  3. protected_malicious_sample.pdf (Encrypted PDF with embedded /JS & /OpenAction tags, Password: malware123)
"""

import os
import fitz  # PyMuPDF

def generate_test_files():
    print("--- Generating PDFortress Week 6 Test PDF Files ---")

    # ------------------------------------------------------------------
    # 1. Clean Encrypted PDF (Password: secret123)
    # ------------------------------------------------------------------
    doc_safe = fitz.open()
    page1 = doc_safe.new_page()
    page1.insert_text((50, 50), "PDFortress Test: Clean Password-Protected Document.", fontsize=14)
    page1.insert_text((50, 80), "This document contains no malicious triggers.", fontsize=12)
    
    # Save with encryption (AES 128 bit)
    doc_safe.save(
        "protected_safe_sample.pdf",
        encryption=fitz.PDF_ENCRYPT_AES_128,
        user_pw="secret123",
        owner_pw="secret123"
    )
    doc_safe.close()
    print("[SUCCESS] Created: protected_safe_sample.pdf (Password: secret123)")

    # ------------------------------------------------------------------
    # 2. Malicious Encrypted PDF with Embedded /JS & /OpenAction (Password: malware123)
    # ------------------------------------------------------------------
    raw_pdf_content = (
        b"%PDF-1.7\n"
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n"
        b"4 0 obj\n<< /Type /Action /S /JavaScript /JS (eval(unescape('%3Cscript%3Ealert%28%22PDFortress%20Payload%22%29%3C%2Fscript%3E'))) >>\nendobj\n"
        b"xref\n0 5\n0000000000 65535 f \n0000000009 00000 n \n0000000074 00000 n \n0000000131 00000 n \n0000000200 00000 n \n"
        b"trailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n320\n%%EOF\n"
    )

    doc_mal = fitz.open("pdf", raw_pdf_content)
    doc_mal.save(
        "protected_malicious_sample.pdf",
        encryption=fitz.PDF_ENCRYPT_AES_128,
        user_pw="malware123",
        owner_pw="malware123"
    )
    doc_mal.close()

    print("[SUCCESS] Created: protected_malicious_sample.pdf (Password: malware123)")

    # ------------------------------------------------------------------
    # 3. Large >100MB PDF File (105 MB Binary Test File)
    # ------------------------------------------------------------------
    with open("large_105mb_test.pdf", "wb") as f:
        f.write(b"%PDF-1.7\n%PDFortress 105MB Size Test\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")
        chunk = b"X" * (1024 * 1024)
        for _ in range(105):
            f.write(chunk)
        f.write(b"\n%%EOF\n")
    
    actual_mb = round(os.path.getsize("large_105mb_test.pdf") / (1024 * 1024), 2)
    print(f"[SUCCESS] Created: large_105mb_test.pdf (File Size: {actual_mb} MB)")

    print("\n--- All test files successfully created in core_app/backend ---")

if __name__ == "__main__":
    generate_test_files()
