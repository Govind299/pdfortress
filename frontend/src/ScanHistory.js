/**
 * ScanHistory.js — PDFortress Scan History Log
 * Built on Vercel Geist System with 8-item Pagination Controls
 */

import React, { useEffect, useState } from "react";

const API_BASE = `${window.location.protocol}//${window.location.hostname}:8000`;
const PAGE_SIZE = 8;

function ScanHistory({ refreshTrigger }) {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [currentPage, setCurrentPage] = useState(1);

  const fetchScans = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/scans`);
      if (res.ok) {
        const data = await res.json();
        setScans(data);
      }
    } catch (err) {
      console.error("Failed to fetch scan history", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchScans();
    const interval = setInterval(fetchScans, 2000);
    return () => clearInterval(interval);
  }, [refreshTrigger]);

  const totalPages = Math.max(1, Math.ceil(scans.length / PAGE_SIZE));
  const paginatedScans = scans.slice((currentPage - 1) * PAGE_SIZE, currentPage * PAGE_SIZE);

  const handlePageChange = (page) => {
    if (page >= 1 && page <= totalPages) {
      setCurrentPage(page);
    }
  };

  return (
    <div className="geist-report-card">
      <div className="geist-mono-eyebrow" style={{ marginBottom: "16px" }}>
        SYSTEM AUDIT LOGS // HISTORICAL SCANS
      </div>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "16px" }}>
        <h2 style={{ fontSize: "20px", fontWeight: 600, letterSpacing: "-0.4px", margin: 0 }}>
          Recent Security Scan Logs
        </h2>
        {scans.length > 0 && (
          <span style={{ fontSize: "13px", color: "var(--colors-mute)", fontFamily: "var(--font-mono)" }}>
            Total Logs: {scans.length}
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
          <table className="geist-table">
            <thead>
              <tr>
                <th>File Name</th>
                <th>Status / Verdict</th>
                <th>Risk Score</th>
                <th>Encrypted</th>
                <th>Date</th>
              </tr>
            </thead>
            <tbody>
              {paginatedScans.map((s) => (
                <tr key={s.id}>
                  <td style={{ fontWeight: 500 }}>{s.original_filename}</td>
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

          {/* Pagination Controls */}
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
    </div>
  );
}

export default ScanHistory;
