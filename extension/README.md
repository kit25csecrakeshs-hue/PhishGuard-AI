# PhishGuard-AI Chrome Browser Extension (Manifest V3)

A Chrome extension for real-time phishing URL detection and scam threat assessment directly from your browser.

## Features
- **Active Tab Scanning**: Instantly captures the currently active browser tab URL with zero manual copy-pasting.
- **Explainable Threat Indicators**: Displays multi-factor risk scores (0-100), detected structural anomalies, and ML ensemble probability.
- **Color-Coded Visual Risk Badges**: High Risk (Rose), Medium Risk (Amber), Low Risk (Emerald).
- **One-Click Report Copying**: Formats analysis output for SOC teams, incident response tickets, or academic presentations.
- **Privacy-Centric**: Manifest V3 compliant. Requests only `activeTab` and `storage`. Does NOT record browsing history or transmit URLs in the background without user initiation.

## Installation & Local Testing Instructions

1. Ensure the PhishGuard-AI backend server is running:
   ```bash
   npm run dev
   ```
   (Server operates at `http://localhost:3000`)

2. Open Google Chrome or any Chromium-based browser (Brave, Edge, Chromium).

3. In the address bar, navigate to:
   ```text
   chrome://extensions/
   ```

4. Enable **Developer mode** using the toggle switch in the upper-right corner.

5. Click the **Load unpacked** button in the upper-left corner.

6. In the file picker dialog, select the `extension` folder located inside the PhishGuard-AI project directory:
   ```text
   /path/to/PhishGuard-AI/extension
   ```

7. Click **Select Folder**. The "PhishGuard-AI Cyber Threat Shield" icon will appear in your browser extensions toolbar!

8. Pin the extension to your toolbar, navigate to any website or paste a test URL, and click **Analyze Target URL** to see live threat scoring!
