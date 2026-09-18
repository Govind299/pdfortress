# 🛡️ PDFortress Shield — Chrome/Edge Browser Extension (Prototype)

A lightweight Manifest V3 client-side browser extension for **PDFortress** that allows users to rapidly inspect untrusted PDF documents for malware, malicious objects (`/JS`, `/Launch`, `/OpenAction`), and suspicious payloads directly from their browser before opening them locally.

---

## 🚀 How to Load in Google Chrome / Microsoft Edge

1. **Open Extensions Page:**
   - In Google Chrome, go to: `chrome://extensions/`
   - In Microsoft Edge, go to: `edge://extensions/`
2. **Enable Developer Mode:**
   - Toggle the **Developer mode** switch in the top right corner to **ON**.
3. **Load the Extension:**
   - Click the **Load unpacked** button.
   - Select this directory:
     ```
     D:\copilot_cli\pdfortress\core_app\extension
     ```
4. **Pin to Toolbar:**
   - Click the puzzle icon (Extensions) in your browser toolbar and pin **PDFortress Shield**.

---

## ⚡ Features in this Prototype

- **Live Backend Health Indicator:** Automatically checks if your PDFortress FastAPI backend (`http://127.0.0.1:8000/health`) is active and displays `🟢 API Online` or `🔴 API Offline`.
- **Instant Drag & Drop Inspector:** Drop any PDF file directly into the extension popup without opening the web dashboard.
- **Immediate Threat Scoring:** Runs the static analysis pipeline instantly, rendering:
  - Security Verdict (`Safe`, `Suspicious`, `Malicious`)
  - Risk Score Meter (0.0 to 100.0)
  - Keyword extraction breakdown (e.g. `/JS (1)`, `/OpenAction (1)`)
  - Encryption & Page count indicators.
- **Direct Dashboard Access:** One-click shortcut to launch the full PDFortress web analytics portal at `http://localhost:3000`.

---

## 🧪 Testing the Extension

1. Ensure the FastAPI backend is running:
   ```bash
   uvicorn main:app --reload
   ```
2. Open the extension popup from your browser toolbar.
3. Confirm the status pill displays `🟢 API Online`.
4. Drag and drop any test PDF (e.g., `suspicious_sample.pdf` or `encrypted_sample.pdf`).
5. Observe the instant analysis verdict and score rendered inside the popup!
