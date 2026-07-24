/**
 * App.js — PDFortress Frontend
 * Handles PDF file selection, upload, and displaying the analysis report.
 * Author: Raj Patel (D24DIT050)
 */

import React, { useState } from "react";
import ScanHistory from "./ScanHistory";
import "./App.css";

const API_BASE = "http://localhost:8000";

function App() {
  const [selectedFile, setSelectedFile] = useState(null);
  const [isLoading, setIsLoading]       = useState(false);
  const [result, setResult]             = useState(null);
  const [error, setError]               = useState(null);
  const [refreshHistory, setRefreshHistory] = useState(0);

  // --- Handle file selection ---
  const handleFileChange = (e) => {
    setSelectedFile(e.target.files[0]);
    setResult(null);
    setError(null);
  };

  // --- Handle file upload and analysis ---
  const handleAnalyze = async () => {
    if (!selectedFile) return;

    setIsLoading(true);
    setResult(null);
    setError(null);

    const formData = new FormData();
    formData.append("file", selectedFile);

    try {
      const response = await fetch(`${API_BASE}/api/upload`, {
        method: "POST",
        body: formData,
      });

      if (!response.ok) {
        const errData = await response.json();
        throw new Error(errData.detail || "Upload failed.");
      }

      const data = await response.json();
      setResult(data);
      setRefreshHistory((prev) => prev + 1);
    } catch (err) {
      setError(err.message || "Could not connect to the analysis server.");
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="app-container">
      {/* Header */}
      <header className="app-header">
        <h1>🔒 PDFortress</h1>
        <p>Upload a PDF to scan it for hidden malware and suspicious content.</p>
      </header>

      {/* Upload Card */}
      <div className="upload-card">
        <input
          type="file"
          id="pdf-upload"
          accept=".pdf"
          onChange={handleFileChange}
        />
        <label htmlFor="pdf-upload">📄 Choose a PDF File</label>

        {selectedFile && (
          <p className="selected-file">Selected: {selectedFile.name}</p>
        )}

        <br />
        <button
          className="btn-analyze"
          onClick={handleAnalyze}
          disabled={!selectedFile || isLoading}
        >
          {isLoading ? "Analyzing..." : "Analyze File"}
        </button>
      </div>

      {/* Loading indicator */}
      {isLoading && (
        <p className="loading-text">⏳ Running static analysis pipeline...</p>
      )}

      {/* Error message */}
      {error && <p className="error-text">⚠️ Error: {error}</p>}

      {/* Analysis Result */}
      {result && (
        <div className="result-card">
          <h2>Analysis Report — {result.original_filename}</h2>

          {/* Verdict Badge */}
          <span className={`verdict-badge verdict-${result.verdict}`}>
            {result.verdict}
          </span>

          {/* Core Details */}
          <div className="result-detail">
            <p><strong>Risk Score:</strong> {result.risk_score}</p>
            <p><strong>Page Count:</strong> {result.page_count ?? "N/A"}</p>
            <p><strong>Author:</strong> {result.author ?? "Unknown"}</p>
            <p>
              <strong>Encrypted:</strong>{" "}
              {result.is_encrypted ? "⚠️ Yes (password-protected)" : "No"}
            </p>
          </div>

          {/* Dangerous Tags Found */}
          {Object.keys(result.dangerous_tags_found || {}).length > 0 && (
            <div style={{ marginTop: "16px" }}>
              <strong>Dangerous Tags Detected:</strong>
              <ul className="tags-list">
                {Object.entries(result.dangerous_tags_found).map(([tag, count]) => (
                  <li key={tag}>
                    {tag} ×{count}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Warnings (e.g. encryption notice) */}
          {result.warnings && result.warnings.length > 0 && (
            <div className="warning-box">
              {result.warnings.map((w, i) => (
                <p key={i}>⚠️ {w}</p>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Scan History Table */}
      <ScanHistory refreshTrigger={refreshHistory} />
    </div>
  );
}

export default App;
