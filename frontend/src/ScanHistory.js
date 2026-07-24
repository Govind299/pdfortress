/**
 * ScanHistory.js — PDFortress Scan History Dashboard
 * Displays past scans fetched from the /api/scans endpoint.
 * Author: Raj Patel (D24DIT050)
 */

import React, { useEffect, useState } from "react";

const API_BASE = "http://localhost:8000";

function ScanHistory({ refreshTrigger }) {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);

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
  }, [refreshTrigger]);

  return (
    <div className="history-card">
      <h2>📋 Recent Scan History</h2>
      {loading ? (
        <p className="loading-text">Loading history...</p>
      ) : scans.length === 0 ? (
        <p style={{ color: "#777", marginTop: "8px" }}>No previous scans recorded.</p>
      ) : (
        <table className="history-table">
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
            {scans.map((s) => (
              <tr key={s.id}>
                <td>{s.original_filename}</td>
                <td>
                  <span className={`verdict-badge verdict-${s.verdict || "Pending"}`}>
                    {s.verdict || s.status || "Processing..."}
                  </span>
                </td>
                <td>{s.risk_score ?? "-"}</td>
                <td>{s.is_encrypted ? "⚠️ Yes" : "No"}</td>
                <td>{s.upload_time ? new Date(s.upload_time).toLocaleString() : "-"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

export default ScanHistory;
