/**
 * PDFortress Shield - Extension Popup Script
 * Interacts with the local PDFortress FastAPI backend (http://127.0.0.1:8000)
 */

const API_BASE = "http://127.0.0.1:8000";

// DOM Elements
const apiStatus = document.getElementById("apiStatus");
const statusText = document.getElementById("statusText");
const dropZone = document.getElementById("dropZone");
const fileInput = document.getElementById("fileInput");
const uploadSection = document.getElementById("uploadSection");
const loadingState = document.getElementById("loadingState");
const resultSection = document.getElementById("resultSection");

// Result Elements
const verdictBadge = document.getElementById("verdictBadge");
const riskScore = document.getElementById("riskScore");
const resultFilename = document.getElementById("resultFilename");
const metaPages = document.getElementById("metaPages");
const metaEncrypted = document.getElementById("metaEncrypted");
const riskBarFill = document.getElementById("riskBarFill");
const tagsList = document.getElementById("tagsList");
const scanAgainBtn = document.getElementById("scanAgainBtn");

// 1. Check API Health on load
async function checkBackendHealth() {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 2500);

    const res = await fetch(`${API_BASE}/health`, {
      method: "GET",
      signal: controller.signal
    });
    clearTimeout(timeoutId);

    if (res.ok) {
      apiStatus.className = "status-badge online";
      statusText.textContent = "API Online";
      return true;
    } else {
      throw new Error("Bad status");
    }
  } catch (err) {
    apiStatus.className = "status-badge offline";
    statusText.textContent = "API Offline";
    return false;
  }
}

// 2. Drag and drop file listeners
["dragenter", "dragover"].forEach((eventName) => {
  dropZone.addEventListener(eventName, (e) => {
    e.preventDefault();
    e.stopPropagation();
    dropZone.classList.add("dragover");
  });
});

["dragleave", "drop"].forEach((eventName) => {
  dropZone.addEventListener(eventName, (e) => {
    e.preventDefault();
    e.stopPropagation();
    dropZone.classList.remove("dragover");
  });
});

dropZone.addEventListener("drop", (e) => {
  const files = e.dataTransfer.files;
  if (files && files.length > 0) {
    handleFile(files[0]);
  }
});

fileInput.addEventListener("change", (e) => {
  if (e.target.files && e.target.files.length > 0) {
    handleFile(e.target.files[0]);
  }
});

scanAgainBtn.addEventListener("click", () => {
  fileInput.value = "";
  resultSection.classList.add("hidden");
  uploadSection.classList.remove("hidden");
});

// 3. Upload & Inspect PDF
async function handleFile(file) {
  if (!file.name.toLowerCase().endsWith(".pdf")) {
    alert("Please select a valid PDF file (.pdf)");
    return;
  }

  // Switch UI to Loading state
  uploadSection.classList.add("hidden");
  resultSection.classList.add("hidden");
  loadingState.classList.remove("hidden");

  const formData = new FormData();
  formData.append("file", file);

  try {
    const response = await fetch(`${API_BASE}/api/upload`, {
      method: "POST",
      body: formData
    });

    if (!response.ok) {
      const errJson = await response.json().catch(() => ({}));
      throw new Error(errJson.detail || `Server error: HTTP ${response.status}`);
    }

    const data = await response.json();
    renderResult(data);
  } catch (err) {
    alert(`Scan Failed: ${err.message}\nMake sure the PDFortress backend is running at ${API_BASE}`);
    loadingState.classList.add("hidden");
    uploadSection.classList.remove("hidden");
  }
}

// 4. Render Analysis Results
function renderResult(data) {
  loadingState.classList.add("hidden");
  resultSection.classList.remove("hidden");

  const verdict = (data.verdict || "Safe").toLowerCase();
  const score = typeof data.risk_score === "number" ? data.risk_score : 0.0;

  // Verdict badge & score
  verdictBadge.textContent = data.verdict || "SAFE";
  verdictBadge.className = `verdict-pill ${verdict}`;

  riskScore.textContent = `Risk: ${score.toFixed(1)} / 100`;

  // Risk bar
  riskBarFill.style.width = `${Math.min(Math.max(score, 5), 100)}%`;
  riskBarFill.className = `risk-bar-fill ${verdict}`;

  // File metadata
  resultFilename.textContent = data.original_filename || "Document.pdf";
  resultFilename.title = data.original_filename || "Document.pdf";
  metaPages.textContent = `${data.page_count ?? 1} Page(s)`;
  metaEncrypted.textContent = data.is_encrypted ? "Protected (Encrypted)" : "Standard Unencrypted";

  // Dangerous Tags breakdown
  tagsList.innerHTML = "";
  const tags = data.dangerous_tags_found || {};
  const tagEntries = Object.entries(tags).filter(([_, count]) => count > 0);

  if (tagEntries.length > 0) {
    tagEntries.forEach(([tag, count]) => {
      const span = document.createElement("span");
      span.className = "tag-badge";
      span.textContent = `${tag} (${count})`;
      tagsList.appendChild(span);
    });
  } else {
    const span = document.createElement("span");
    span.className = "tag-badge clean";
    span.textContent = "No malicious keywords detected";
    tagsList.appendChild(span);
  }
}

// Initialize on popup launch
document.addEventListener("DOMContentLoaded", () => {
  checkBackendHealth();
});
