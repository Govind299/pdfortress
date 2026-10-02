<div align="center">

# 🛡️ PDFortress

### Multi-Layered Zero-Trust PDF Malware Detection & Threat Analysis Platform

[![Python](https://img.shields.io/badge/Python-3.12%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-18.3-61DAFB?logo=react&logoColor=black)](https://react.dev/)
[![PyMuPDF](https://img.shields.io/badge/PyMuPDF-1.24%2B-red?logo=adobe-acrobat-reader&logoColor=white)](https://pymupdf.readthedocs.io/)
[![YARA](https://img.shields.io/badge/YARA-4.5%2B-green?logo=virustotal&logoColor=white)](https://virustotal.github.io/yara/)
[![Redis](https://img.shields.io/badge/Redis-5.0%2F7.0-DC382D?logo=redis&logoColor=white)](https://redis.io/)
[![Celery](https://img.shields.io/badge/Celery-5.3%2B-37814A?logo=celery&logoColor=white)](https://docs.celeryq.dev/)
[![Accuracy](https://img.shields.io/badge/Benchmark_Accuracy-98.20%25-brightgreen)](https://github.com/Govind299/pdfortress)
[![Latency](https://img.shields.io/badge/Avg_Scan_Latency-3.05_ms-blueviolet)](https://github.com/Govind299/pdfortress)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

<p align="center">
  <b>A production-grade, zero-execution security engine designed to detect, deconstruct, and score weaponized Portable Document Format (PDF) files in real time.</b>
</p>

[Key Features](#-key-features) • [System Architecture](#-system-architecture) • [Empirical Benchmarks](#-empirical-benchmarks) • [Quickstart Guide](#-quickstart-guide) • [API Reference](#-api-reference) • [Browser Extension](#-browser-extension) • [The Team](#-the-team)

---

</div>

## 📌 Executive Summary

Traditional antivirus engines and basic file scanners often fail against weaponized PDF files because attackers obfuscate malicious payloads inside compressed streams, abuse valid PDF specification tags (`/Launch`, `/OpenAction`, `/JS`), or hide malicious code behind document encryption. Furthermore, dynamic sandboxing—while thorough—imposes **30 to 60+ seconds** of latency per document and remains susceptible to environment-aware sandbox evasion.

**PDFortress** solves this problem through a **zero-execution, deterministic, three-stage static analysis pipeline**. By disassembling PDF structural object hierarchies, matching byte-level exploit patterns via compiled YARA rules, and cross-referencing global threat intelligence, PDFortress evaluates document risk in just **3.05 milliseconds** per file—with **zero risk of payload execution** on the host infrastructure.

---

## ⚡ Key Features

- **Zero-Disk In-Memory Decryption:** Password-protected PDFs are authenticated and decrypted strictly in volatile RAM using PyMuPDF (`doc.authenticate()` & `doc.tobytes()`). Decrypted plaintext streams never touch disk storage, preserving privacy and eliminating leakage risks.
- **Three-Stage Defense-in-Depth Pipeline:**
  1. *Stage 1 (PyMuPDF Structural Extraction):* Heuristic parsing of high-risk operators (`/JS`, `/OpenAction`, `/Launch`, `/EmbeddedFiles`, `/AA`, `/RichMedia`, `/XFA`).
  2. *Stage 2 (Compiled YARA Signatures):* Deep byte-level matching targeting obfuscated JavaScript decoding routines, shellcode NOP-sleds, and embedded PE executable headers (`MZ`).
  3. *Stage 3 (VirusTotal v3 Intelligence):* SHA-256 cryptographic multi-hashing cross-referenced across 70+ global antivirus vendors with automated EICAR detection overrides.
- **Transparent Mathematical Scoring:** Uses a deterministic weighted scoring formula ($0.40S_{\text{Heur}} + 0.35S_{\text{YARA}} + 0.25S_{\text{VT}}$) with critical malware overrides ($\ge 85.0$), avoiding unexplainable black-box machine learning predictions.
- **High-Availability Asynchronous Architecture:** Powered by FastAPI, Celery, and Redis for distributed background processing, with an automatic **zero-downtime microsecond fallback** if Redis is offline.
- **Server Hardening & Defenses:** Enforces strict 100 MB file size limits (HTTP 413), randomized UUIDv4 storage names to block path traversal, and in-memory IP rate-limiting (10 uploads/min, HTTP 429).
- **Vercel Geist Dark/Light UI:** Interactive React dashboard featuring an animated circular SVG Risk Gauge (`RiskGaugeSVG`), a 3-stage visual timeline stepper (`StageTimeline`), dynamic HTML5 canvas background, and search/filter historical audit tables.
- **Audit Reporting:** One-click programmatic generation of branded PDF security certificates and machine-readable JSON reports.
- **PDFortress Shield (Browser Extension):** Lightweight Chrome/Edge Manifest V3 extension prototype enabling client-side drag-and-drop scanning directly from the browser.

---

## 🏗️ System Architecture

```
                                  +-----------------------+
                                  |     USER BROWSER      |
                                  | React 18 / Geist UI   |
                                  +-----------+-----------+
                                              |
                          HTTP REST (Upload / Status Queries)
                                              v
                      +-----------------------------------------------+
                      |            FASTAPI REST GATEWAY               |
                      |  • IP Rate Limiter (10 uploads/min)           |
                      |  • 100 MB Payload Ceiling                     |
                      |  • UUIDv4 Path Traversal Protection           |
                      +-------+-------------------------------+-------+
                              |                               |
                     Redis Available?                   Redis Offline?
                              |                               |
                              v                               v
                  +-----------------------+       +-----------------------+
                  |  CELERY / REDIS QUEUE |       | IN-PROCESS FALLBACK   |
                  | Asynchronous Worker   |       | Sub-5ms Direct Sync   |
                  +-----------+-----------+       +-----------+-----------+
                              |                               |
                              +---------------+---------------+
                                              |
                                              v
                              +-------------------------------+
                              |    CORE SECURITY PIPELINE     |
                              |  (Zero File Execution Policy) |
                              +---------------+---------------+
                                              |
                 +----------------------------+----------------------------+
                 |                            |                            |
                 v                            v                            v
      +----------------------+     +----------------------+     +----------------------+
      |       STAGE 1        |     |       STAGE 2        |     |       STAGE 3        |
      |   PyMuPDF Parsing    |     |      YARA Rules      |     |  VirusTotal v3 Intel |
      |  • /JS, /OpenAction  |     |  • Obfuscated JS     |     |  • SHA-256 Multi-Hash|
      |  • /Launch, /Embed   |     |  • Shellcode NOP-sled|     |  • 70+ Vendor Ratios |
      |  • RAM Decryption    |     |  • PE Header (MZ)    |     |  • EICAR Override    |
      +----------+-----------+     +----------+-----------+     +----------+-----------+
                 |                            |                            |
                 +----------------------------+----------------------------+
                                              |
                                              v
                              +-------------------------------+
                              |   WEIGHTED RISK SCORING MATH  |
                              | S = 0.40(S1) + 0.35(S2) +     |
                              |     0.25(S3) [Override >= 85] |
                              +---------------+---------------+
                                              |
                                              v
                              +-------------------------------+
                              |    SQLITE / POSTGRESQL DB     |
                              | SQLAlchemy ORM Audit Storage  |
                              +-------------------------------+
```

---

## 📊 Empirical Benchmarks

The platform's detection performance was rigorously validated across an automated **1,000-document empirical benchmark dataset** (`test_benchmark.py`) consisting of 500 benign multi-page business documents (invoices, resumes, forms) and 500 synthetic malicious samples spanning 6 exploit variants:

<div align="center">

| Performance Metric | Design Target | Measured Result | Benchmark Status |
| :--- | :---: | :---: | :---: |
| **Classification Accuracy** | $> 95.0\%$ | **98.20%** | 🟢 **Exceeded** |
| **Precision** | $> 95.0\%$ | **98.39%** | 🟢 **Exceeded** |
| **Recall (Sensitivity)** | $> 95.0\%$ | **98.00%** | 🟢 **Exceeded** |
| **False Positive Rate (FPR)** | $< 1.80\%$ | **1.60%** | 🟢 **Exceeded (Lower is Better)** |
| **F1-Score** | $> 95.0\%$ | **98.19%** | 🟢 **Exceeded** |
| **Average Processing Latency** | $< 250\text{ ms}$ | **3.05 ms** | 🚀 **80x Faster than Target** |

</div>

### Stage-by-Stage Latency Profiling

* **Stage 1 (PyMuPDF Structural Extraction):** `1.42 ms` (46.5%)
* **Stage 2 (Compiled YARA Rule Matching):** `1.18 ms` (38.7%)
* **Stage 3 (SHA-256 Calculation & Scoring Math):** `0.45 ms` (14.8%)
* **Total End-to-End Pipeline Latency:** **`3.05 ms per document`**

---

## 🧩 Tech Stack

| Domain | Technology / Tool | Version | Purpose |
| :--- | :--- | :--- | :--- |
| **Backend Runtime** | Python | `3.12.x` | High-performance core execution runtime |
| **Web Framework** | FastAPI | `0.110+` | Asynchronous REST API routing & Swagger docs |
| **PDF Parser** | PyMuPDF (`fitz`) | `1.24+` | C-based object-tree extraction & RAM decryption |
| **Signature Engine** | YARA (`yara-python`)| `4.5+` | Compiled bytecode exploit signature matching |
| **Task Queue** | Celery + Redis | `5.3+` / `7.0` | Distributed asynchronous task brokering |
| **Database ORM** | SQLAlchemy | `2.0+` | Relational schema modeling & dynamic migrations |
| **Database Engine**| SQLite / PostgreSQL | `3.x` / `15+`| Persistent scan audit logging & history queries |
| **Frontend Framework**| React.js | `18.3` | Single-page application architecture |
| **Design Language**| Vercel Geist Tokens | Vanilla CSS3 | Dark/Light theming, custom SVG risk gauges |
| **Extension Standard**| Manifest V3 | `0.1.0` | Client-side browser inspection prototype |

---

## 📁 Repository Structure

```text
pdfortress/
├── core_app/
│   ├── backend/
│   │   ├── analyzer.py            # Core 3-stage security engine & risk scoring math
│   │   ├── main.py                # FastAPI REST server, rate limiter & endpoints
│   │   ├── database.py            # SQLAlchemy models, migrations & retention cleanup
│   │   ├── celery_worker.py       # Distributed Celery task definition
│   │   ├── report_exporter.py     # Programmatic PDF & JSON report generators
│   │   ├── test_benchmark.py      # Automated 1,000 PDF evaluation benchmark suite
│   │   ├── benchmark_results.json # Verified benchmark performance telemetry
│   │   ├── requirements.txt       # Pinned backend dependencies
│   │   └── rules/
│   │       └── pdf_rules.yar      # Compiled YARA exploit detection signatures
│   │
│   ├── frontend/
│   │   ├── src/
│   │   │   ├── App.js             # Main React view, RiskGaugeSVG & StageTimeline
│   │   │   ├── App.css            # Vercel Geist design tokens & theme rules
│   │   │   ├── ScanHistory.js     # Paginated audit log table & forensic modal
│   │   │   └── components/ui/     # FileUploadCard drag-and-drop & canvas grid
│   │   └── package.json           # Frontend dependencies & dev proxy configuration
│   │
│   └── extension/                 # PDFortress Shield Chrome/Edge Extension
│       ├── manifest.json          # Manifest V3 configuration & host permissions
│       ├── popup.html             # Glassmorphism dark-mode popup interface
│       ├── popup.css              # Tailored extension stylesheet
│       ├── popup.js               # Async API client & drag-and-drop scanner
│       └── icons/                 # Security shield branding assets (16/48/128px)
│
└── README.md                      # Comprehensive project documentation
```

---

## 🚀 Quickstart Guide

### Prerequisites
- **Python:** Version `3.10` or higher
- **Node.js:** Version `18.x` or higher (with npm)
- **Git**

---

### Step 1: Clone Repository

```bash
git clone https://github.com/Govind299/pdfortress.git
cd pdfortress/core_app
```

---

### Step 2: Start Backend Server

```powershell
# Navigate to backend directory
cd backend

# Install dependencies
pip install -r requirements.txt

# Start FastAPI server with live reloading
python -m uvicorn main:app --reload --port 8000
```

* **Interactive Swagger UI:** `http://127.0.0.1:8000/docs`
* **Redoc UI:** `http://127.0.0.1:8000/redoc`
* **API Health Status:** `http://127.0.0.1:8000/health`

---

### Step 3: Start Frontend Dashboard

Open a **second terminal window**:

```powershell
# Navigate to frontend directory
cd core_app/frontend

# Install node dependencies
npm install

# Launch React development server
npm start
```

* **Web Application:** `http://localhost:3000`

---

### Step 4: Run the 1,000 PDF Benchmark Suite

To independently verify the **98.20% accuracy** and **3.05 ms latency** metrics:

```powershell
cd core_app/backend
python test_benchmark.py
```

The test harness will synthesize 500 benign and 500 malicious PDFs, execute scans through the pipeline, output confusion matrix metrics, and update `benchmark_results.json`.

---

## 🌐 Browser Extension (PDFortress Shield)

A lightweight client-side Chrome/Edge browser extension prototype (**Manifest V3**) is included under [`core_app/extension`](core_app/extension):

1. Open your browser and navigate to:
   * **Google Chrome:** `chrome://extensions/`
   * **Microsoft Edge:** `edge://extensions/`
2. Enable **Developer mode** (toggle in the top-right corner).
3. Click **Load unpacked** and select the folder:
   ```text
   pdfortress/core_app/extension
   ```
4. Pin **PDFortress Shield** to your browser toolbar. When the FastAPI backend is running, the popup displays `🟢 API Online` and lets you drag and drop PDFs for instant in-browser inspection!

---

## 📡 API Reference Overview

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/health` | Server health check and database connectivity probe |
| `POST` | `/api/upload` | Multipart file upload; runs static analysis and returns risk report |
| `POST` | `/api/upload/batch` | Multi-file concurrent upload with batch UUID tracking |
| `GET` | `/api/scans` | Paginated scan history with filename search, verdict filter, and date ranges |
| `GET` | `/api/scans/{scan_id}` | Detailed telemetry, detected keywords, YARA hits, and VT consensus |
| `GET` | `/api/scans/batch/{batch_id}` | Aggregated progress and status of a batch job |
| `GET` | `/api/scans/{scan_id}/export/pdf` | Streams downloadable branded PDF audit certificate |
| `GET` | `/api/scans/{scan_id}/export/json`| Streams downloadable machine-readable JSON security dump |
| `POST` | `/api/admin/cleanup` | Administrative purge of temporary files older than retention threshold |

---

## 👥 The Team

This project was engineered by 7th-Semester B.Tech Information Technology students at **Devang Patel Institute of Advance Technology and Research (DPIATR), Charotar University of Science & Technology (CHARUSAT)**:

* **Govind Suthar** (`D24DIT094`) — *Security Analysis Engine & Detection Lead*  
  *Core static parser, in-memory decryption, risk math, 1,000 PDF benchmark harness, and report exporters.*
* **Khushali Desai** (`23DIT050`) — *Frontend Architecture, UI/UX & Visualization Lead*  
  *Vercel Geist design system, animated circular SVG risk gauge, 3-stage stepper, YARA exploit rule authoring, and extension UI.*
* **Raj Patel** (`23DIT007`) — *Backend Architecture, Distributed Pipelines & Data Lead*  
  *FastAPI REST endpoints, Celery/Redis queue, IP rate limiting, database migrations, retention cleanup, and extension API client.*

---

## 📜 License & Ethical Disclaimer

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

> **Responsible Security Disclaimer:**  
> PDFortress is designed solely for defensive cybersecurity research, academic demonstration, malware analysis, and organizational document protection. All test files used in the benchmark harness are synthetically generated or use the inert, industry-standard EICAR test string.
