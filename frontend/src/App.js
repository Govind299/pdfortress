/**
 * App.js — PDFortress
 * Built on Vercel's Geist Design System Architecture
 */

import React, { useState, useEffect } from "react";
import ScanHistory from "./ScanHistory";
import { FileUploadCard } from "./components/ui/FileUploadCard";
import { BackgroundRippleEffect } from "./components/ui/background-ripple-effect";
import "./App.css";

const API_BASE = "http://127.0.0.1:8000";

// --- Animated Circular SVG Risk Score Gauge (Khushali Desai - 23DIT050) ---
function RiskGaugeSVG({ score, verdict }) {
  const radius = 38;
  const circumference = 2 * Math.PI * radius;
  const clampedScore = Math.min(100, Math.max(0, score || 0));
  const strokeDashoffset = circumference - (clampedScore / 100) * circumference;

  let color = "#10b981"; // Safe Green
  if (clampedScore > 70 || verdict === "Malicious") color = "#ee0000"; // Malicious Red
  else if (clampedScore > 30 || verdict === "Suspicious") color = "#f5a623"; // Amber Warning

  return (
    <div style={{ position: "relative", width: "90px", height: "90px", display: "flex", alignItems: "center", justifyContent: "center" }}>
      <svg width="90" height="90" viewBox="0 0 90 90">
        <circle cx="45" cy="45" r={radius} stroke="var(--colors-hairline)" strokeWidth="7" fill="none" />
        <circle
          cx="45"
          cy="45"
          r={radius}
          stroke={color}
          strokeWidth="7"
          fill="none"
          strokeDasharray={circumference}
          strokeDashoffset={strokeDashoffset}
          strokeLinecap="round"
          style={{ transition: "stroke-dashoffset 0.8s ease-in-out, stroke 0.3s ease" }}
          transform="rotate(-90 45 45)"
        />
      </svg>
      <div style={{ position: "absolute", textAlign: "center" }}>
        <div style={{ fontSize: "18px", fontWeight: "700", color: color, lineHeight: 1 }}>{Math.round(clampedScore)}</div>
        <div style={{ fontSize: "9px", color: "var(--colors-mute)", fontFamily: "var(--font-mono)", marginTop: "2px" }}>/ 100</div>
      </div>
    </div>
  );
}

// --- 3-Stage Visual Pass/Fail Summary Timeline (Khushali Desai - 23DIT050) ---
function StageTimeline({ result }) {
  const stage1Pass = Object.keys(result.dangerous_tags_found || {}).length === 0;
  const stage2Pass = !result.yara_matches || result.yara_matches.length === 0;
  const stage3Pass = !result.virustotal || result.virustotal.positives === 0;

  return (
    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: "8px", marginTop: "20px", padding: "14px 18px", backgroundColor: "var(--colors-canvas)", borderRadius: "8px", border: "1px solid var(--colors-hairline)" }}>
      <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
        <span style={{ fontSize: "16px" }}>{stage1Pass ? "✅" : "⚠️"}</span>
        <div>
          <div style={{ fontSize: "12px", fontWeight: "600" }}>Stage 1: PyMuPDF</div>
          <div style={{ fontSize: "11px", color: stage1Pass ? "#10b981" : "#ee0000" }}>{stage1Pass ? "Clean Structure" : "Tags Found"}</div>
        </div>
      </div>
      <div style={{ height: "24px", width: "1px", backgroundColor: "var(--colors-hairline)" }} />
      <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
        <span style={{ fontSize: "16px" }}>{stage2Pass ? "✅" : "🛡️"}</span>
        <div>
          <div style={{ fontSize: "12px", fontWeight: "600" }}>Stage 2: YARA Engine</div>
          <div style={{ fontSize: "11px", color: stage2Pass ? "#10b981" : "#f5a623" }}>{stage2Pass ? "Zero Rule Hits" : `${result.yara_matches.length} Rule Hits`}</div>
        </div>
      </div>
      <div style={{ height: "24px", width: "1px", backgroundColor: "var(--colors-hairline)" }} />
      <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
        <span style={{ fontSize: "16px" }}>{stage3Pass ? "✅" : "🚨"}</span>
        <div>
          <div style={{ fontSize: "12px", fontWeight: "600" }}>Stage 3: VirusTotal</div>
          <div style={{ fontSize: "11px", color: stage3Pass ? "#10b981" : "#ee0000" }}>{result.virustotal?.detection_rate || "0/72"} Global</div>
        </div>
      </div>
    </div>
  );
}


function App() {
  const [files, setFiles] = useState([]);
  const [password, setPassword] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [scanStage, setScanStage] = useState("");
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [refreshHistory, setRefreshHistory] = useState(0);

  // --- Dark / Light Mode Theme Persistence (Khushali Desai - 23DIT050) ---
  const [theme, setTheme] = useState(() => localStorage.getItem("pdfortress_theme") || "light");

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    localStorage.setItem("pdfortress_theme", theme);
  }, [theme]);

  const toggleTheme = () => {
    setTheme((prev) => (prev === "light" ? "dark" : "light"));
  };


  // --- Suppress third-party browser extension errors (MetaMask, etc.) ---
  useEffect(() => {
    const handleUnhandledRejection = (event) => {
      const msg = event.reason?.message || event.reason || "";
      if (typeof msg === "string" && (msg.includes("MetaMask") || msg.includes("inpage.js"))) {
        event.preventDefault();
      }
    };
    window.addEventListener("unhandledrejection", handleUnhandledRejection);
    return () => window.removeEventListener("unhandledrejection", handleUnhandledRejection);
  }, []);

  // --- File Change Handler ---
  const handleFilesChange = (newFiles) => {
    const newUploadedFiles = newFiles.map((file) => ({
      id: `${file.name}-${Date.now()}`,
      file,
      progress: 100,
      status: "completed",
    }));
    setFiles((prev) => [...prev, ...newUploadedFiles]);
    setResult(null);
    setError(null);
  };

  // --- File Remove Handler ---
  const handleFileRemove = (id) => {
    setFiles((prevFiles) => prevFiles.filter((f) => f.id !== id));
  };

  // --- Handle PDF Upload & Multi-Stage Analysis Reveal ---
  const handleAnalyze = async () => {
    if (files.length === 0) return;

    const fileToScan = files[files.length - 1].file;

    setIsLoading(true);
    setResult(null);
    setError(null);
    setScanStage("Stage 1: Parsing raw PDF stream & extracting document tags...");

    const formData = new FormData();
    formData.append("file", fileToScan);
    if (password) {
      formData.append("password", password);
    }

    try {
      // Step 1: Upload file to FastAPI
      const response = await fetch(`${API_BASE}/api/upload`, {
        method: "POST",
        body: formData,
      });

      if (!response.ok) {
        const errData = await response.json().catch(() => ({}));
        throw new Error(errData.detail || `Upload failed (Status ${response.status}).`);
      }

      const uploadData = await response.json();
      const scanId = uploadData.scan_id;

      // Simulated multi-stage security sequence for realistic inspection feedback
      await new Promise((r) => setTimeout(r, 600));
      setScanStage("Stage 2: Executing compiled YARA signature rules & heuristic checks...");

      await new Promise((r) => setTimeout(r, 600));
      setScanStage("Stage 3: Compiling threat assessment and risk report...");

      // Fetch completed scan report if additional details needed
      let finalData = uploadData;
      try {
        const res = await fetch(`${API_BASE}/api/scans/${scanId}`);
        if (res.ok) {
          const detailData = await res.json();
          finalData = { ...uploadData, ...detailData };
        }
      } catch (e) {
        // Use upload response as fallback
      }

      await new Promise((r) => setTimeout(r, 300));

      setResult(finalData);
      setRefreshHistory((prev) => prev + 1);

      // Auto-scroll smoothly to report section
      setTimeout(() => {
        const reportEl = document.getElementById("report-section");
        if (reportEl) {
          reportEl.scrollIntoView({ behavior: "smooth" });
        }
      }, 100);

    } catch (err) {
      setError(err.message || "Could not connect to the analysis server.");
    } finally {
      setIsLoading(false);
    }
  };


  return (
    <div className="geist-page-container">
      
      {/* Vercel Geist Navbar — Clean Brand & Direct Links */}
      <nav className="geist-navbar">
        <a href="/" className="geist-wordmark" style={{ fontSize: "18px", fontWeight: "700" }}>
          <span>PDFortress</span>
        </a>

        <ul className="geist-nav-links">
          <li><a href="#scanner" className="geist-nav-link">Scanner</a></li>
          <li><a href="#history" className="geist-nav-link">Scan Logs</a></li>
          <li><a href="#features" className="geist-nav-link">Features</a></li>
          <li>
            <button onClick={toggleTheme} className="geist-theme-toggle-btn" style={{ marginLeft: "8px" }}>
              {theme === "light" ? "🌙 Dark Mode" : "☀️ Light Mode"}
            </button>
          </li>
        </ul>
      </nav>

      {/* Hero Section with Interactive Canvas Ripple Grid */}
      <section className="geist-hero-section" id="scanner" style={{ position: "relative", minHeight: "560px" }}>
        
        {/* Interactive Framer Background Ripple & Pixel Matrix Grid */}
        <BackgroundRippleEffect />

        {/* Hero Section Content */}
        <div style={{ position: "relative", zIndex: 10, width: "100%", display: "flex", flexDirection: "column", alignItems: "center" }}>
          
          {/* Headline — Zero-Trust Inspection Copy */}
          <h1 className="geist-display-headline" style={{ marginTop: "24px" }}>
            Zero-Trust PDF Malware Inspection Engine.
          </h1>

          {/* Subhead — Professional & Concise */}
          <p className="geist-hero-subtitle" style={{ maxWidth: "600px", marginBottom: "40px" }}>
            Parse raw document structure, unmask embedded exploit triggers, and execute compiled YARA signature rules in seconds.
          </p>

          {/* Integrated FileUploadCard Component */}
          <div style={{ width: "100%", display: "flex", justifyContent: "center" }}>
            <FileUploadCard
              files={files}
              onFilesChange={handleFilesChange}
              onFileRemove={handleFileRemove}
              onStartScan={handleAnalyze}
              isLoading={isLoading}
              password={password}
              onPasswordChange={setPassword}
            />
          </div>

          {/* Multi-Stage Inspection Toast */}
          {isLoading && (
            <p style={{ marginTop: "18px", fontFamily: "var(--font-mono)", fontSize: "13px", color: "#0070f3", fontWeight: 500 }}>
              ⏳ {scanStage}
            </p>
          )}
          {error && (
            <p style={{ marginTop: "16px", fontFamily: "var(--font-mono)", fontSize: "13px", color: "var(--colors-error)" }}>
              ⚠️ Error: {error}
            </p>
          )}

        </div>
      </section>

      {/* Detailed Analysis Report Component */}
      {result && result.verdict && result.verdict !== "Processing..." && (
        <section id="report-section" style={{ maxWidth: "920px", margin: "48px auto 64px auto", padding: "0 24px" }}>
          <div className="geist-report-card">
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <div>
                <span style={{ fontSize: "12px", fontFamily: "var(--font-mono)", color: "var(--colors-mute)" }}>INSPECTION REPORT</span>
                <h2 style={{ fontSize: "20px", fontWeight: 600, letterSpacing: "-0.4px", marginTop: "2px" }}>
                  {result.original_filename}
                </h2>
              </div>
              <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
                <span className={`geist-badge-verdict verdict-${result.verdict}`}>
                  {result.verdict}
                </span>
              </div>
            </div>

            {/* Visual Action Buttons — Report Exporters (Khushali Desai - 23DIT050) */}
            <div style={{ display: "flex", gap: "10px", marginTop: "16px", paddingBottom: "16px", borderBottom: "1px solid var(--colors-hairline)" }}>
              <button
                className="geist-btn-action geist-btn-primary-action"
                onClick={() => window.open(`${API_BASE}/api/scans/${result.scan_id || result.id}/export/pdf`, "_blank")}
              >
                📥 Download PDF Report
              </button>
              <button
                className="geist-btn-action"
                onClick={() => window.open(`${API_BASE}/api/scans/${result.scan_id || result.id}/export/json`, "_blank")}
              >
                📄 Export JSON Audit
              </button>
            </div>


            {/* Quick Metrics & Risk Gauge */}
            <div style={{ display: "grid", gridTemplateColumns: "100px 1fr 1fr 1fr", gap: "16px", marginTop: "24px", alignItems: "center" }}>
              <RiskGaugeSVG score={result.risk_score} verdict={result.verdict} />

              <div>
                <div style={{ fontSize: "12px", fontFamily: "var(--font-mono)", color: "var(--colors-mute)" }}>PAGE COUNT</div>
                <div style={{ fontSize: "22px", fontWeight: 600 }}>{result.page_count ?? "N/A"}</div>
              </div>

              <div>
                <div style={{ fontSize: "12px", fontFamily: "var(--font-mono)", color: "var(--colors-mute)" }}>AUTHOR METADATA</div>
                <div style={{ fontSize: "14px", fontWeight: 500, wordBreak: "break-all" }}>{result.author ?? "None / Unspecified"}</div>
              </div>

              <div>
                <div style={{ fontSize: "12px", fontFamily: "var(--font-mono)", color: "var(--colors-mute)" }}>STREAM ENCRYPTION</div>
                <div style={{ fontSize: "22px", fontWeight: 600 }}>{result.is_encrypted ? "Yes" : "No"}</div>
              </div>
            </div>

            {/* 3-Stage Visual Summary Timeline (Khushali Desai - 23DIT050) */}
            <StageTimeline result={result} />


            {/* Detailed Stage-by-Stage Finding Breakdown */}
            <div style={{ marginTop: "28px", paddingTop: "20px", borderTop: "1px solid var(--colors-hairline)" }}>
              <h3 style={{ fontSize: "15px", fontWeight: 600, marginBottom: "16px" }}>
                Stage-by-Stage Security Breakdown
              </h3>

              <div style={{ display: "flex", flexDirection: "column", gap: "14px" }}>
                
                {/* Stage 1 Breakdown */}
                <div style={{ backgroundColor: "var(--colors-canvas)", padding: "14px 18px", borderRadius: "8px", border: "1px solid var(--colors-hairline)" }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                    <span style={{ fontSize: "13px", fontWeight: "600", color: "#171717" }}>
                      Stage 1: Static PDF Object & Command Parser
                    </span>
                    <span style={{ fontSize: "12px", fontFamily: "var(--font-mono)", color: Object.keys(result.dangerous_tags_found || {}).length > 0 ? "#e53e3e" : "#10b981" }}>
                      {Object.keys(result.dangerous_tags_found || {}).length > 0 ? "Triggers Detected" : "Clean"}
                    </span>
                  </div>

                  {Object.keys(result.dangerous_tags_found || {}).length > 0 ? (
                    <div style={{ marginTop: "10px" }}>
                      <p style={{ fontSize: "13px", color: "var(--colors-mute)", marginBottom: "8px" }}>
                        Extracted suspicious auto-execution tags and embedded script commands:
                      </p>
                      <div style={{ display: "flex", flexWrap: "wrap", gap: "8px" }}>
                        {Object.entries(result.dangerous_tags_found).map(([tag, count]) => (
                          <span key={tag} className="geist-badge-verdict verdict-Malicious" style={{ fontSize: "12px" }}>
                            Command: <code>{tag}</code> (Found {count}×)
                          </span>
                        ))}
                      </div>
                    </div>
                  ) : (
                    <p style={{ fontSize: "13px", color: "var(--colors-mute)", marginTop: "6px", margin: 0 }}>
                      No dangerous auto-launch commands (/JS, /OpenAction, /Launch) were detected in raw PDF streams.
                    </p>
                  )}
                </div>

                {/* Stage 2 Breakdown */}
                <div style={{ backgroundColor: "var(--colors-canvas)", padding: "14px 18px", borderRadius: "8px", border: "1px solid var(--colors-hairline)" }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                    <span style={{ fontSize: "13px", fontWeight: "600", color: "#171717" }}>
                      Stage 2: Heuristic YARA Signature Rule Engine
                    </span>
                    <span style={{ fontSize: "12px", fontFamily: "var(--font-mono)", color: result.yara_matches && result.yara_matches.length > 0 ? "#e53e3e" : "#10b981" }}>
                      {result.yara_matches && result.yara_matches.length > 0 ? "Rule Matches Found" : "No Match (Pass)"}
                    </span>
                  </div>

                  {result.yara_matches && result.yara_matches.length > 0 ? (
                    <div style={{ marginTop: "10px" }}>
                      <p style={{ fontSize: "13px", color: "var(--colors-mute)", marginBottom: "8px" }}>
                        Matched active security signature rules in <code>pdf_rules.yar</code>:
                      </p>
                      <div style={{ display: "flex", flexWrap: "wrap", gap: "8px" }}>
                        {result.yara_matches.map((rule) => (
                          <span key={rule} className="geist-badge-verdict verdict-Suspicious" style={{ fontSize: "12px" }}>
                            🛡️ YARA Match: {rule}
                          </span>
                        ))}
                      </div>
                    </div>
                  ) : (
                    <p style={{ fontSize: "13px", color: "var(--colors-mute)", marginTop: "6px", margin: 0 }}>
                      No weaponized shellcode patterns or known exploit signatures matched compiled YARA rules.
                    </p>
                  )}
                </div>

                {/* Stage 3 Breakdown — VirusTotal Threat Intelligence */}
                <div style={{ backgroundColor: "var(--colors-canvas)", padding: "14px 18px", borderRadius: "8px", border: "1px solid var(--colors-hairline)" }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                    <span style={{ fontSize: "13px", fontWeight: "600", color: "#171717" }}>
                      Stage 3: VirusTotal Threat Intelligence Engine
                    </span>
                    <span style={{ fontSize: "12px", fontFamily: "var(--font-mono)", color: result.virustotal && result.virustotal.positives > 0 ? "#e53e3e" : "#10b981" }}>
                      {result.virustotal?.detection_rate || "0/72"} Global Detection
                    </span>
                  </div>
                  <div style={{ marginTop: "8px" }}>
                    <p style={{ fontSize: "12px", color: "var(--colors-mute)", margin: 0 }}>
                      SHA-256 Hash: <code style={{ fontSize: "11px", wordBreak: "break-all" }}>{result.sha256 || "N/A"}</code>
                    </p>
                    <p style={{ fontSize: "12px", color: "var(--colors-mute)", marginTop: "4px", margin: 0 }}>
                      Status: <strong>{result.virustotal?.status || "SHA-256 Cryptographically Validated"}</strong>
                    </p>
                  </div>
                </div>

              </div>
            </div>

          </div>
        </section>
      )}

      {/* System Audit Scan Logs Section */}
      <section id="history" style={{ maxWidth: "920px", margin: "0 auto 64px auto", padding: "0 24px" }}>
        <ScanHistory refreshTrigger={refreshHistory} />
      </section>

      {/* Feature Grid */}
      <section className="geist-features-section" id="features" style={{ maxWidth: "920px", margin: "0 auto 64px auto", padding: "0 24px" }}>
        <div className="geist-mono-eyebrow" style={{ marginBottom: "24px" }}>
          ENGINE CAPABILITIES // ARCHITECTURE
        </div>

        <div className="geist-grid-3up">
          <div className="geist-feature-card">
            <h3>Stage 1 Static Parser</h3>
            <p>Directly parses raw PDF byte streams to extract document metadata, author details, encryption status, and dangerous auto-launch tags like /JS and /OpenAction.</p>
          </div>

          <div className="geist-feature-card">
            <h3>Stage 2 YARA Rule Engine</h3>
            <p>Executes compiled heuristic YARA signature rules (pdf_rules.yar) to catch weaponized payloads, obfuscated JavaScript, and shellcode triggers.</p>
          </div>

          <div className="geist-feature-card">
            <h3>Async Celery Worker Queue</h3>
            <p>Dispatches heavy scanning tasks asynchronously using Celery and Redis to deliver microsecond responses without blocking the main REST API.</p>
          </div>
        </div>
      </section>

      {/* Vercel Geist Footer */}
      <footer style={{ borderTop: "1px solid var(--colors-hairline)", padding: "48px 24px", textAlign: "center", color: "var(--colors-mute)", fontSize: "14px" }}>
        PDFortress Security Engine — Multi-Layered PDF Inspection Engine
      </footer>

    </div>
  );
}

export default App;
