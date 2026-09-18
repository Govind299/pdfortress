# PDFortress: Comprehensive Individual Contribution & Module Ownership Breakdown

**Project ID:** `PRJ_IT_7_2026_3`  
**Project Title:** PDFortress – Multi-Layered Zero-Trust PDF Malware Detection & Threat Analysis Platform  
**Academic Program:** B.Tech in Information Technology (7th Semester), Devang Patel Institute of Advance Technology and Research (DPIATR), Charotar University of Science & Technology (CHARUSAT)  
**Academic Year:** 2026  
**Repository:** [https://github.com/Govind299/pdfortress.git](https://github.com/Govind299/pdfortress.git)  
**Evaluation Scope:** Project Milestones (Week 1 through Week 10)

---

## 1. Executive Summary & Team Distribution

PDFortress is an enterprise-grade, zero-trust security platform designed to detect malicious PDF documents purely through multi-layered static analysis, structural disassembling, heuristic evaluation, and threat intelligence—without executing payloads in an unconfined environment. 

To ensure complete modular separation, architectural decoupling, and clear engineering accountability, the platform was divided into three primary technical domains:

```
+---------------------------------------------------------------------------------------------------------+
|                                        PDFORTRESS ARCHITECTURE                                          |
+------------------------------------+------------------------------------+-------------------------------+
|       SECURITY ENGINE & CORE       |        FRONTEND & UX DESIGN        |   BACKEND API & DATA INFRA    |
|   Govind Suthar (D24DIT094)        |    Khushali Desai (23DIT050)       |     Raj Patel (23DIT007)      |
+------------------------------------+------------------------------------+-------------------------------+
| - Structural Parser (PyMuPDF)      | - Vercel Geist Design System       | - FastAPI RESTful Service     |
| - In-Memory Decryption Engine      | - Dark/Light Mode Theme Engine     | - SQLAlchemy ORM & Migration  |
| - YARA Signature Matching Engine   | - RiskGaugeSVG Circular Ring       | - Celery & Redis Task Queue   |
| - VirusTotal API v3 Threat Intel   | - StageTimeline Stepper Component  | - Microsecond Sync Fallback   |
| - Weighted Aggregated Scoring Math | - Interactive Scan Detail Modal    | - IP Rate Limiting & 100MB Cap|
| - 1,000 PDF Benchmark Harness     | - Drag-and-Drop Ingestion Card     | - Multi-Criteria Search/Filter|
| - PDF & JSON Security Exporters    | - Responsive Audit Table & Pages   | - Scheduled Retention Cleanup |
+------------------------------------+------------------------------------+-------------------------------+
```

### Team Responsibility Matrix

| Team Member | Student ID | Academic Role / Domain | Core Owned Modules | Ownership Share |
| :--- | :--- | :--- | :--- | :---: |
| **Govind Suthar** | `D24DIT094` | **Security Engine & Detection Lead** | Static Parser, In-Memory Decryption, YARA Signatures, VirusTotal v3, Weighted Risk Math, Benchmark Harness, Report Exporter | **33.3%** |
| **Khushali Desai** | `23DIT050` | **Frontend UI/UX & Visualization Lead** | Vercel Geist UI, Dark/Light Theme System, Circular Risk Gauge, 3-Stage Visual Stepper, Modal Inspector, Drag-and-Drop Card | **33.3%** |
| **Raj Patel** | `23DIT007` | **Backend API & Infrastructure Lead** | FastAPI REST Endpoints, Celery/Redis Distributed Queue, SQLAlchemy ORM, Schema Migration, IP Rate Limiter, Search & Filter APIs | **33.3%** |

---

## 2. Detailed Individual Contributions

---

### 2.1 Govind Suthar (`D24DIT094`) — Security Analysis Engine & Algorithmic Detection Lead

Govind Suthar designed and implemented the core security analysis pipeline, detection logic, algorithmic scoring formulas, benchmarking harness, and automated reporting systems. His work operates strictly in user-space memory, ensuring zero file execution and zero-disk data leakage during password decryption.

#### Owned Modules and Source Files
* `core_app/backend/analyzer.py` — Core static inspection engine, cryptographic hashing, and risk scoring.
* `core_app/backend/rules/pdf_rules.yar` — YARA rulebase detecting PDF exploit patterns and shellcode.
* `core_app/backend/test_benchmark.py` — Automated 1,000 PDF synthetic & real-world evaluation benchmark suite.
* `core_app/backend/benchmark_results.json` — Empirical benchmark dataset and confusion matrix metrics.
* `core_app/backend/report_exporter.py` — Programmatic PDF and JSON security audit certificate generators.

#### Specific Technical Accomplishments & Components Developed
1. **Multi-Stage Static Analysis Engine (`analyzer.py`):**
   * **Stage 1 (PyMuPDF Structural Extraction):** Developed low-level object tree disassembler using `fitz` (PyMuPDF). Extracted structural dictionaries, Cross-Reference (`XREF`) tables, Catalog metadata, and raw content streams without launching external interpreters.
   * **In-Memory Password Decryption (`analyze_pdf`):** Built zero-disk decryption pipeline for encrypted/password-protected PDFs (`doc.authenticate(password)` and `doc.tobytes()`). Decrypts nested RC4/AES encrypted streams directly in volatile memory, preventing plain-text malicious payloads from touching physical storage.
   * **Heuristic Object & Action Tag Scanner (`_scan_raw_bytes`):** Implemented pattern extraction for high-risk PDF action operators and exploit vectors, assigning empirical risk weights:
     * `/Launch` (80 pts): External process execution triggers.
     * `/OpenAction` (60 pts): Auto-executing payloads on document launch.
     * `/JavaScript` & `/JS` (50 pts): Embedded script interpreters frequently abused in heap-spray attacks.
     * `/EmbeddedFiles` (30 pts): Dropper payloads hidden inside internal document hierarchies.
     * `/AA` (20 pts), `/RichMedia` (20 pts), `/XFA` (15 pts): Event-driven macros and XML forms architecture.
   * **Shannon Stream Entropy Calculation:** Built byte-level entropy calculations across decompressed streams to identify high-entropy packed shellcode or obfuscated binary data ($H(X) \ge 7.2$).

2. **YARA Heuristic & Exploit Signature Matching (`rules/pdf_rules.yar`):**
   * Authored and compiled tailored YARA rule collections covering known PDF vulnerability exploits (CVE-2010-2883, CVE-2018-4990), obfuscated JavaScript decoding routines (`unescape`, `eval`, `String.fromCharCode`), launch command executions (`cmd.exe`, `powershell.exe`), and standard antivirus test signatures (`EICAR_Antivirus_Test_Signature`).
   * Integrated `_scan_yara_rules()` to scan raw decompressed streams and map exact rule matches into the analysis payload.

3. **Global Threat Intelligence Client (`_query_virustotal`):**
   * Implemented cryptographic multi-hash calculations (`_compute_sha256`, MD5, SHA-1) on incoming bytes.
   * Constructed an asynchronous HTTP client querying VirusTotal API v3 (`/api/v3/files/{hash}`).
   * Built resilient response parsing handling rate limits (HTTP 429), caching responses, and extracting vendor consensus ratios (e.g., `positives / total`).

4. **Weighted Mathematical Risk Scoring Engine (`_compute_risk_score`):**
   * Developed the formal composite risk evaluation formula combining all three analysis stages:
     $$\text{Risk Score} = 0.40 \cdot S_{\text{Heuristics}} + 0.35 \cdot S_{\text{YARA}} + 0.25 \cdot S_{\text{VirusTotal}}$$
   * Implemented **Critical Override Logic**: Any document matching the EICAR test signature or having $\ge 50$ positive vendor detections automatically triggers a minimum score override ($\ge 85.0$), ensuring severe threats are never diluted by low heuristic counts.
   * Categorized risks into enterprise security thresholds:
     * **Safe (0–30):** Structural clean document, zero actionable exploit signatures.
     * **Suspicious (31–70):** Ambiguous constructs (e.g., standard JS or form actions without malicious payload).
     * **Malicious (71–100):** Multiple dangerous primitives, shellcode indicators, or confirmed threat intel.

5. **Automated Benchmark Evaluation Suite (`test_benchmark.py`):**
   * Designed a 1,000-document test harness (500 benign synthetic PDFs + 500 malicious samples containing embedded JS, obfuscated streams, and launch triggers).
   * Quantified empirical platform metrics saved directly to `benchmark_results.json`:
     * **Overall Accuracy:** $98.20\%$
     * **Precision:** $98.39\%$
     * **Recall (True Positive Rate):** $98.00\%$
     * **False Positive Rate (FPR):** $1.60\%$ ($< 1.8\%$)
     * **Average Scan Latency:** $3.05\text{ ms per document}$

6. **Automated Audit Exporters (`report_exporter.py`):**
   * Engineered PyMuPDF-based programmatic PDF layout generator (`export_pdf_report`) producing downloadable executive audit certificates with branded headers, risk badges, finding breakdowns, and remediation notes.
   * Created machine-readable JSON security dump exporter (`export_json_report`).

#### Key Commits by Govind Suthar
* `65fc17e`: `feat(engine): implement weighted aggregated risk scoring engine _compute_risk_score() and enterprise policy thresholds`
* `5106388`: `feat(engine): add 1,000 PDF benchmark suite test_benchmark.py and PDF/JSON report exporter module`
* `b9eb7c8`: `feat(engine): implement SHA-256 hash computation and Stage 3 VirusTotal v3 lookup client`
* `b375637`: `feat(engine): implement PyMuPDF in-memory stream decryption scanner for password-protected PDFs`
* `7e3d902`: `fix(ui): prevent long filename overflow with text-overflow ellipsis and fixed table column layout`
* `bc89b8e`: `feat(history): implement 8-item scan log pagination, multi-stage inspection sequence, and detailed threat report`

---

### 2.2 Khushali Desai (`23DIT050`) — Frontend Architecture, UI/UX & Forensic Data Visualization Lead

Khushali Desai designed and developed the entire client-facing user experience, design system, interactive data visualizations, theme engine, and forensic drill-down modal inspectors using modern React and the Vercel Geist design language.

#### Owned Modules and Source Files
* `core_app/frontend/src/App.js` — Core application orchestration, state machines, upload handlers, and custom visual components.
* `core_app/frontend/src/App.css` — Vercel Geist design system architecture, CSS token variables, and responsive layout rules.
* `core_app/frontend/src/ScanHistory.js` — Historical scan audit table, pagination controls, and drill-down forensic inspection modal.
* `core_app/frontend/src/components/ui/FileUploadCard.js` — Interactive drag-and-drop file ingestion zone with progress feedback.
* `core_app/frontend/src/components/ui/dot-grid-bg.js` — Dynamic background micro-interaction canvas.
* `core_app/frontend/src/components/ui/background-ripple-effect.js` — Interactive geometric background visual styling.

#### Specific Technical Accomplishments & Components Developed
1. **Vercel Geist Design System & Architecture (`App.css`):**
   * Built a sleek, modern enterprise security dashboard avoiding generic styles, adhering to Vercel Geist design principles.
   * Defined strict CSS custom properties for uniform color harmonies (`--bg-primary`, `--text-primary`, `--card-bg`, `--colors-hairline`, `--colors-accent`, `--font-mono`, `--font-sans`).
   * Implemented high-contrast typography hierarchies, subtle borders, card hover elevations, and responsive grid layouts.

2. **Dark / Light Mode Theme Switching Engine (`App.js`, `App.css`):**
   * Engineered seamless Dark/Light theme switching with zero layout-shift or page reload.
   * Bound theme preferences to HTML root attributes (`data-theme="dark"` / `data-theme="light"`).
   * Implemented persistent state synchronization via browser `localStorage` (`pdfortress_theme`), preserving user preferences across sessions.

3. **Dynamic Visual Feedback & Data Visualizations:**
   * **`RiskGaugeSVG` Circular Risk Meter:** Developed custom animated SVG gauge displaying real-time risk scores (0–100) with dynamic dash-offset animations and semantic color shifts:
     * Emerald Green (`#10b981`) for Safe ($0-30$)
     * Amber Warning (`#f5a623`) for Suspicious ($31-70$)
     * Crimson Red (`#ee0000`) for Malicious ($71-100$)
   * **`StageTimeline` Visual Stepper:** Created 3-stage visual inspection sequence component displaying live pass/warning/fail statuses across all scanning layers:
     * Stage 1: Structural PyMuPDF Parsing (Clean Structure vs. Malicious Tags)
     * Stage 2: YARA Signature Engine (Zero Hits vs. Rule Match Counts)
     * Stage 3: VirusTotal Threat Intel (Verified Clean vs. Global AV Consensus Ratios)

4. **Forensic Audit Modal Inspector (`ScanHistory.js`):**
   * Engineered an in-depth modal inspection dialog displaying complete forensic evidence for any selected historical scan.
   * Rendered cryptographic signatures (SHA-256), document metadata (Author, Producer, Page Count), structural keyword counts, matched YARA rule definitions, and VirusTotal threat vendor detection bars.
   * Embedded direct trigger buttons for instant client-side download of official PDF certificates and raw JSON security dumps.

5. **Drag-and-Drop Ingestion Interface (`FileUploadCard.js`):**
   * Created intuitive drag-and-drop dropzone supporting both single-file and multi-file document drops.
   * Built interactive drag hover states, animated upload indicators, and client-side pre-validation (restricting uploads to `.pdf` and warning on files $> 100\text{ MB}$).
   * Integrated encrypted document password prompt: dynamically renders secure password input fields whenever an encrypted PDF is detected.

6. **Audit Table & Responsive Layout Guardrails:**
   * Built clean tabular presentation of historical audit records with server-side page navigation (8 items per page).
   * Resolved table layout breaking issues by applying `table-layout: fixed`, `text-overflow: ellipsis`, and column-width constraints to handle arbitrarily long filenames.

#### Key Commits by Khushali Desai
* `dfad395`: `feat(ui): integrate RiskGaugeSVG circular score ring and StageTimeline visual component`
* `0bba14b`: `feat(ui): add Dark/Light mode theme switcher toggle with localStorage persistence and visual PDF/JSON report export action buttons`
* `06e2f54`: `feat(ui): render Stage 3 VirusTotal threat intel card and SHA-256 hash in scan detail modal`
* `74ad360`: `feat(ui): add password input field for encrypted PDFs and interactive scan detail modal inspector`

---

### 2.3 Raj Patel (`23DIT007`) — Backend Architecture, Distributed Task Pipelines & Data Persistence Lead

Raj Patel designed and built the backend API architecture, database models, asynchronous background worker infrastructure, high-availability fallback logic, search/filtering query engines, and server security hardening.

#### Owned Modules and Source Files
* `core_app/backend/main.py` — FastAPI application server, routing, middleware, and request validation.
* `core_app/backend/database.py` — SQLAlchemy ORM schema, session manager, migrations, and cleanup routines.
* `core_app/backend/celery_worker.py` — Distributed Celery task queue definition and background execution worker.

#### Specific Technical Accomplishments & Components Developed
1. **FastAPI RESTful Architecture & Endpoints (`main.py`):**
   * Architected high-performance asynchronous REST API using FastAPI, Pydantic validation, and CORS middleware.
   * Developed comprehensive endpoint suite:
     * `POST /api/upload`: Validates incoming PDF payloads, enforces size caps, sanitizes filenames with UUIDs, coordinates analysis, and persists scan results.
     * `POST /api/upload/batch`: Handles concurrent multi-document uploads, generates batch UUID tracking tokens, and triggers parallel processing.
     * `GET /api/scans`: Serves paginated scan history with advanced server-side search and filtering.
     * `GET /api/scans/{scan_id}`: Delivers detailed scan telemetry and analysis findings for frontend modal inspection.
     * `GET /api/scans/batch/{batch_id}`: Returns real-time completion status and item counts for batch operations.
     * `GET /api/scans/{scan_id}/export/pdf` & `.../export/json`: Dispatches stream responses for generated audit reports.
     * `POST /api/admin/cleanup`: Triggers manual or automated purge of expired temporary files and old scan records.
     * `GET /health`: Health-check endpoint for infrastructure monitoring.

2. **Database Architecture & ORM Modeling (`database.py`):**
   * Engineered the `Scan` relational model in SQLAlchemy ORM, structuring storage for file metadata, risk scores, verdicts, encryption flags, page counts, author strings, batch tracking IDs, and serialized JSON analysis findings.
   * Built database initialization logic (`init_db()`) and **programmatic schema migration**: implemented dynamic table inspection and `ALTER TABLE scans ADD COLUMN batch_id TEXT` execution, preventing database corruption when upgrading existing schemas (`pdfortress_v2.db`).
   * Configured thread-safe session generator (`get_db()`) to cleanly manage database connections across concurrent request lifecycles.

3. **Asynchronous Distributed Task Processing (`celery_worker.py`):**
   * Configured Celery task queue utilizing Redis as an in-memory message broker and backend store for asynchronous document processing (`process_pdf_scan`).
   * **Redis Protocol Compatibility:** Solved Redis 5.x RESP2 compatibility errors (`unknown command HELLO`) by configuring explicit transport settings (`broker_transport_options={"protocol": 2}`).
   * **Zero-Downtime Microsecond Fallback:** Built an intelligent ping check in `upload_pdf`:
     ```python
     r = redis.Redis(host="localhost", port=6379, socket_connect_timeout=0.1)
     if r.ping():
         process_pdf_scan.delay(...) # Celery Queue
     else:
         analyze_pdf(...)            # Instant In-Process Fallback
     ```
     If the external Redis service is offline, the API seamlessly falls back to instant in-process execution without dropping requests or causing connection timeouts.

4. **Server Hardening & Security Defenses (`main.py`):**
   * **IP-Based Rate Limiting Middleware (`rate_limit_middleware`):** Implemented client request throttling on upload endpoints, enforcing a hard limit of 10 uploads per minute per client IP, returning HTTP 429 Too Many Requests when exceeded.
   * **Payload Size Caps:** Enforced strict 100 MB maximum file size limit, terminating oversized payloads immediately with HTTP 413 Payload Too Large.
   * **Path Traversal Prevention:** Sanitized all uploaded documents by generating random UUID v4 filenames (`safe_filename = f"{uuid.uuid4().hex}.pdf"`), preventing directory traversal and arbitrary file overwrite attacks.

5. **Advanced Search, Filtering & Pagination Query Engine (`main.py`):**
   * Upgraded `GET /api/scans` to support server-side query parameters:
     * `query`: Case-insensitive substring search matching original filenames and author metadata.
     * `verdict`: Exact-match filtering across categorical states (`Safe`, `Suspicious`, `Malicious`).
     * `start_date` & `end_date`: ISO timestamp range filtering.
     * `limit` & `offset`: High-performance server-side SQL pagination.

6. **Automated Storage Retention & Cleanup Routine (`cleanup_expired_scans`):**
   * Implemented automated retention routine in `database.py` that purges temporary uploaded files from the disk and removes stale records from SQLite older than a configurable retention window (default 24 hours).

#### Key Commits by Raj Patel
* `eca3a2e`: `feat(api): add FastAPI BackgroundTasks worker and GET /api/scans search, verdict, and date-range filtering parameters`
* `af30fff`: `feat(api): add batch upload endpoints POST /api/upload/batch, batch status retrieval, report download routes, and automated database cleanup routine`
* `4591d73`: `feat(backend): implement IP rate-limiting middleware enforcing 10 uploads per minute limit`
* `52cccc0`: `feat(backend): enforce 100MB upload limit and server-side database pagination parameters`
* `dc99709`: `feat(backend): configure FastAPI CORS middleware, dynamic endpoints, and Webpack dev proxy`

---

## 3. Module & Architectural Interface Contracts

The three subsystems interact seamlessly across clean, well-defined boundaries:

```
[User Browser]
       |
       |  1. Drag-and-drop PDF upload / View Dashboard
       v
[Khushali Desai: React UI / Geist Design System]
       |
       |  2. HTTP REST Requests (POST /api/upload, GET /api/scans)
       v
[Raj Patel: FastAPI Server / Security Middleware]
       |
       +---> [Rate Limiter (10/min) & 100MB Size Validator]
       |
       +---> [Database ORM (SQLAlchemy / SQLite)]  <-- Saves Metadata & Status
       |
       +---> [Celery Task Queue / Instant Synchronous Fallback]
                   |
                   |  3. Dispatches Document Path & Password
                   v
       [Govind Suthar: Core Security Engine]
             |
             +---> Stage 1: PyMuPDF Structural Analysis & Stream Decryption
             +---> Stage 2: YARA Signature Matching
             +---> Stage 3: VirusTotal v3 Threat Intelligence
             +---> Step 4: Weighted Composite Risk Math & Override Evaluation
                   |
                   |  4. Returns Standardized JSON Analysis Report
                   v
       [Raj Patel: Database Updates (Verdict, Score, Findings)]
                   |
                   |  5. Sends JSON Response to Client
                   v
[Khushali Desai: RiskGaugeSVG, StageTimeline & Scan Detail Modal]
```

---

## 4. Responsibility Assignment Matrix (RACI)

* **R (Responsible):** The member who performs the activity / writes the code.
* **A (Accountable):** The member with final approval and ownership of the deliverable.
* **C (Consulted):** The member who provides input or interface requirements.
* **I (Informed):** The member kept updated on progress.

| Platform Component / Task | Govind Suthar (`D24DIT094`) | Khushali Desai (`23DIT050`) | Raj Patel (`23DIT007`) |
| :--- | :---: | :---: | :---: |
| **PyMuPDF Structural Extraction & Decryption** | **R / A** | I | C |
| **YARA Exploit Signatures & Rule Authoring** | **R / A** | I | C |
| **VirusTotal v3 Client & Hash Calculations** | **R / A** | C | C |
| **Weighted Risk Scoring Math & Overrides** | **R / A** | C | C |
| **1,000 PDF Benchmark Suite & Profiling** | **R / A** | I | I |
| **PDF & JSON Security Report Exporters** | **R / A** | C | C |
| **Geist Design System & Dark/Light Theming** | I | **R / A** | I |
| **RiskGaugeSVG & StageTimeline Visuals** | C | **R / A** | I |
| **Scan Detail Forensic Modal Inspector** | C | **R / A** | C |
| **Drag-and-Drop Ingestion Card & UX** | I | **R / A** | C |
| **FastAPI REST Service & Endpoints** | C | C | **R / A** |
| **SQLAlchemy ORM & Database Migrations** | I | I | **R / A** |
| **Celery Queue & Redis Resilient Fallback** | C | I | **R / A** |
| **IP Rate Limiting & 100MB File Caps** | I | I | **R / A** |
| **Search, Filter & Pagination Query Engine**| I | C | **R / A** |
| **Automated Temporary File Retention Cleanup**| I | I | **R / A** |

---

## 5. Verification & Git Log Cross-Reference

All listed contributions are verified against the active codebase, commit records, and test benchmarks in the repository:

* **Core Engine:** Verified through `pytest core_app/backend/test_benchmark.py` (500 benign, 500 malicious samples; 98.20% accuracy, 3.05 ms latency).
* **Frontend UI:** Verified through local development builds (`npm start`) with Geist tokens, SVG gauge rendering, and dark/light mode toggling.
* **Backend API:** Verified through Swagger API documentation (`http://127.0.0.1:8000/docs`) testing single upload, batch upload, rate limiting, and report export endpoints.
* **Commit History:** Exact author attributions match git commit logs pushed to `https://github.com/Govind299/pdfortress.git`.
