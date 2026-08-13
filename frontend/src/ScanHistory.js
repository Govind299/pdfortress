/**
 * ScanHistory.js — PDFortress Scan History Log
 * Built on Vercel Geist System with Server-Side DB Pagination & Interactive Detail Modal
 */

import React, { useEffect, useState } from "react";

const API_BASE = "http://127.0.0.1:8000";
const PAGE_SIZE = 8;

function ScanHistory({ refreshTrigger }) {
  const [scans, setScans] = useState([]);
  const [totalScans, setTotalScans] = useState(0);
  const [loading, setLoading] = useState(true);
  const [currentPage, setCurrentPage] = useState(1);
  const [selectedScan, setSelectedScan] = useState(null);
  const [modalLoading, setModalLoading] = useState(false);

  const fetchScans = async (page = currentPage) => {
    try {
      const offset = (page - 1) * PAGE_SIZE;
      const res = await fetch(`${API_BASE}/api/scans?limit=${PAGE_SIZE}&offset=${offset}`);
      if (res.ok) {
        const data = await res.json();
        if (Array.isArray(data)) {
          setScans(data);
          setTotalScans(data.length);
        } else {
          setScans(data.scans || []);
          setTotalScans(data.total || 0);
        }
      }
    } catch (err) {
      console.error("Failed to fetch scan history", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchScans(currentPage);
    const interval = setInterval(() => fetchScans(currentPage), 2500);
    return () => clearInterval(interval);
  }, [refreshTrigger, currentPage]);

  const totalPages = Math.max(1, Math.ceil(totalScans / PAGE_SIZE));

  const handlePageChange = (page) => {
    if (page >= 1 && page <= totalPages) {
      setCurrentPage(page);
      fetchScans(page);
    }
  };

  const handleRowClick = async (scanId) => {
    setModalLoading(true);
    try {
      const res = await fetch(`${API_BASE}/api/scans/${scanId}`);
      if (res.ok) {
        const fullDetail = await res.json();
        setSelectedScan(fullDetail);
      }
    } catch (err) {
      console.error("Failed to load scan details", err);
    } finally {
      setModalLoading(false);
    }
  };

  return (
    <div className="geist-report-card" style={{ overflow: "hidden", position: "relative" }}>
      <div className="geist-mono-eyebrow" style={{ marginBottom: "16px" }}>
        SYSTEM AUDIT LOGS // HISTORICAL SCANS
      </div>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "16px" }}>
        <h2 style={{ fontSize: "20px", fontWeight: 600, letterSpacing: "-0.4px", margin: 0 }}>
          Recent Security Scan Logs
        </h2>
        {totalScans > 0 && (
          <span style={{ fontSize: "13px", color: "var(--colors-mute)", fontFamily: "var(--font-mono)" }}>
            Total Audit Records: {totalScans}
          </span>
        )}
      </div>

      {loading ? (
        <p style={{ fontFamily: "var(--font-mono)", fontSize: "13px", color: "var(--colors-mute)" }}>
          Loading historical logs...
        </p>
      ) : scans.length === 0 ? (
        <p style={{ color: "var(--colors-mute)", marginTop: "8px", fontSize: "14px" }}>
          No previous scans recorded.
        </p>
      ) : (
        <>
          <div style={{ width: "100%", overflowX: "auto" }}>
            <table className="geist-table" style={{ tableLayout: "fixed", width: "100%" }}>
              <thead>
                <tr>
                  <th style={{ width: "42%" }}>File Name (Click for Details)</th>
                  <th style={{ width: "18%" }}>Status / Verdict</th>
                  <th style={{ width: "12%" }}>Risk Score</th>
                  <th style={{ width: "10%" }}>Encrypted</th>
                  <th style={{ width: "18%" }}>Date</th>
                </tr>
              </thead>
              <tbody>
                {scans.map((s) => (
                  <tr
                    key={s.id}
                    onClick={() => handleRowClick(s.id)}
                    style={{ cursor: "pointer", transition: "background-color 0.15s ease" }}
                    className="geist-table-row-hover"
                  >
                    <td
                      style={{
                        fontWeight: 500,
                        whiteSpace: "nowrap",
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        maxWidth: "0",
                        color: "#0070f3"
                      }}
                      title={s.original_filename}
                    >
                      📄 {s.original_filename}
                    </td>
                    <td>
                      <span className={`geist-badge-verdict verdict-${s.verdict || "Pending"}`}>
                        {s.verdict || s.status || "Processing..."}
                      </span>
                    </td>
                    <td style={{ fontFamily: "var(--font-mono)" }}>{s.risk_score ?? "-"}</td>
                    <td>{s.is_encrypted ? "Yes" : "No"}</td>
                    <td style={{ fontFamily: "var(--font-mono)", fontSize: "12px", color: "var(--colors-mute)" }}>
                      {s.upload_time ? new Date(s.upload_time).toLocaleString() : "-"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Server-Side Pagination Controls */}
          {totalPages > 1 && (
            <div
              style={{
                display: "flex",
                justify: "space-between",
                alignItems: "center",
                marginTop: "20px",
                paddingTop: "16px",
                borderTop: "1px solid var(--colors-hairline)"
              }}
            >
              <button
                type="button"
                onClick={() => handlePageChange(currentPage - 1)}
                disabled={currentPage === 1}
                style={{
                  padding: "6px 14px",
                  fontSize: "13px",
                  fontWeight: "500",
                  borderRadius: "6px",
                  border: "1px solid var(--colors-hairline)",
                  backgroundColor: "var(--colors-canvas)",
                  color: "var(--colors-ink)",
                  cursor: currentPage === 1 ? "not-allowed" : "pointer",
                  opacity: currentPage === 1 ? 0.5 : 1
                }}
              >
                ← Previous
              </button>

              <div style={{ display: "flex", gap: "6px", alignItems: "center" }}>
                {Array.from({ length: totalPages }, (_, i) => i + 1).map((pageNum) => (
                  <button
                    key={pageNum}
                    type="button"
                    onClick={() => handlePageChange(pageNum)}
                    style={{
                      padding: "4px 10px",
                      fontSize: "13px",
                      fontWeight: currentPage === pageNum ? "600" : "400",
                      borderRadius: "6px",
                      border: currentPage === pageNum ? "1px solid #171717" : "1px solid var(--colors-hairline)",
                      backgroundColor: currentPage === pageNum ? "#171717" : "transparent",
                      color: currentPage === pageNum ? "#ffffff" : "var(--colors-ink)",
                      cursor: "pointer"
                    }}
                  >
                    {pageNum}
                  </button>
                ))}
              </div>

              <button
                type="button"
                onClick={() => handlePageChange(currentPage + 1)}
                disabled={currentPage === totalPages}
                style={{
                  padding: "6px 14px",
                  fontSize: "13px",
                  fontWeight: "500",
                  borderRadius: "6px",
                  border: "1px solid var(--colors-hairline)",
                  backgroundColor: "var(--colors-canvas)",
                  color: "var(--colors-ink)",
                  cursor: currentPage === totalPages ? "not-allowed" : "pointer",
                  opacity: currentPage === totalPages ? 0.5 : 1
                }}
              >
                Next →
              </button>
            </div>
          )}
        </>
      )}

      {/* Interactive Scan Detail Modal Popup */}
      {(selectedScan || modalLoading) && (
        <div
          style={{
            position: "fixed",
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            backgroundColor: "rgba(0, 0, 0, 0.6)",
            backdropFilter: "blur(4px)",
            zIndex: 9999,
            display: "flex",
            justifyContent: "center",
            alignItems: "center",
            padding: "24px"
          }}
          onClick={() => setSelectedScan(null)}
        >
          <div
            style={{
              backgroundColor: "var(--colors-canvas-elevated)",
              borderRadius: "12px",
              border: "1px solid var(--colors-hairline)",
              maxWidth: "680px",
              width: "100%",
              maxHeight: "85vh",
              overflowY: "auto",
              padding: "28px",
              boxShadow: "0 20px 40px rgba(0, 0, 0, 0.2)",
              color: "var(--colors-ink)"
            }}
            onClick={(e) => e.stopPropagation()}
          >
            {modalLoading ? (
              <p style={{ fontFamily: "var(--font-mono)", fontSize: "14px", textAlign: "center" }}>
                ⏳ Fetching raw inspection details...
              </p>
            ) : selectedScan && (
              <>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "20px" }}>
                  <div>
                    <span style={{ fontSize: "11px", fontFamily: "var(--font-mono)", color: "var(--colors-mute)" }}>
                      SCAN LOG INSPECTOR // ID #{selectedScan.scan_id}
                    </span>
                    <h2 style={{ fontSize: "18px", fontWeight: "600", marginTop: "4px", wordBreak: "break-all" }}>
                      {selectedScan.original_filename}
                    </h2>
                  </div>
                  <button
                    onClick={() => setSelectedScan(null)}
                    style={{
                      background: "none",
                      border: "none",
                      fontSize: "20px",
                      cursor: "pointer",
                      color: "var(--colors-mute)",
                      padding: "4px 8px"
                    }}
                  >
                    ✕
                  </button>
                </div>

                {/* Metric Badges */}
                <div style={{ display: "flex", gap: "12px", alignItems: "center", marginBottom: "20px" }}>
                  <span className={`geist-badge-verdict verdict-${selectedScan.verdict}`}>
                    {selectedScan.verdict}
                  </span>
                  <span style={{ fontSize: "13px", fontFamily: "var(--font-mono)", color: "var(--colors-mute)" }}>
                    Risk Score: <strong>{selectedScan.risk_score}</strong> / 100
                  </span>
                </div>

                {/* Metadata Grid */}
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "12px", backgroundColor: "var(--colors-canvas)", padding: "14px", borderRadius: "8px", border: "1px solid var(--colors-hairline)", marginBottom: "20px", fontSize: "13px" }}>
                  <div>
                    <span style={{ color: "var(--colors-mute)" }}>Page Count: </span>
                    <strong>{selectedScan.page_count ?? "N/A"}</strong>
                  </div>
                  <div>
                    <span style={{ color: "var(--colors-mute)" }}>Author: </span>
                    <strong>{selectedScan.author ?? "Unknown"}</strong>
                  </div>
                  <div>
                    <span style={{ color: "var(--colors-mute)" }}>Encrypted Stream: </span>
                    <strong>{selectedScan.is_encrypted ? "Yes (Password Required)" : "No"}</strong>
                  </div>
                  <div>
                    <span style={{ color: "var(--colors-mute)" }}>Scan Timestamp: </span>
                    <strong>{selectedScan.upload_time ? new Date(selectedScan.upload_time).toLocaleString() : "N/A"}</strong>
                  </div>
                </div>

                {/* Dangerous Tags Found */}
                {selectedScan.dangerous_tags_found && Object.keys(selectedScan.dangerous_tags_found).length > 0 && (
                  <div style={{ marginBottom: "20px" }}>
                    <div style={{ fontSize: "13px", fontWeight: "600", marginBottom: "8px" }}>
                      Extracted Dangerous Structural Tags:
                    </div>
                    <div style={{ display: "flex", flexWrap: "wrap", gap: "8px" }}>
                      {Object.entries(selectedScan.dangerous_tags_found).map(([tag, count]) => (
                        <span key={tag} className="geist-badge-verdict verdict-Malicious" style={{ fontSize: "12px" }}>
                          <code>{tag}</code> ×{count}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {/* YARA Rule Matches */}
                {selectedScan.yara_matches && selectedScan.yara_matches.length > 0 && (
                  <div style={{ marginBottom: "20px" }}>
                    <div style={{ fontSize: "13px", fontWeight: "600", marginBottom: "8px" }}>
                      YARA Heuristic Signature Rule Matches:
                    </div>
                    <div style={{ display: "flex", flexWrap: "wrap", gap: "8px" }}>
                      {selectedScan.yara_matches.map((rule) => (
                        <span key={rule} className="geist-badge-verdict verdict-Suspicious" style={{ fontSize: "12px" }}>
                          🛡️ YARA Match: {rule}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {/* Raw JSON Inspector */}
                <div>
                  <div style={{ fontSize: "12px", fontFamily: "var(--font-mono)", color: "var(--colors-mute)", marginBottom: "6px" }}>
                    RAW INSPECTION PAYLOAD:
                  </div>
                  <pre
                    style={{
                      backgroundColor: "#171717",
                      color: "#00ff66",
                      padding: "14px",
                      borderRadius: "8px",
                      fontSize: "12px",
                      fontFamily: "var(--font-mono)",
                      overflowX: "auto",
                      maxHeight: "180px"
                    }}
                  >
                    {JSON.stringify(selectedScan, null, 2)}
                  </pre>
                </div>

                <div style={{ marginTop: "20px", textAlign: "right" }}>
                  <button
                    onClick={() => setSelectedScan(null)}
                    style={{
                      padding: "8px 20px",
                      backgroundColor: "#171717",
                      color: "#ffffff",
                      border: "none",
                      borderRadius: "6px",
                      fontSize: "13px",
                      fontWeight: "500",
                      cursor: "pointer"
                    }}
                  >
                    Close Inspector
                  </button>
                </div>
              </>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

export default ScanHistory;
