# 🛡️ GuardLink - AI Phishing & Scam Detection

GuardLink is a professional cybersecurity system designed to protect users from phishing, scams, and malicious websites in real-time. It consists of a high-performance **Browser Extension** and a **Cloud-Native Scanner API**.

---

## 📥 Quick Install
Want to try it out? Download the browser extension directly:

**[📦 Download GuardLink Extension (ZIP)](https://github.com/kathirm1323-ai/URL-detection/raw/main/GuardLink_Extension.zip)**

### Installation Steps:
1. **Unzip** the downloaded file.
2. Open Chrome and go to `chrome://extensions/`.
3. Enable **Developer mode** (top right switch).
4. Click **Load unpacked** and select the unzipped folder.

---

## ✨ Features
*   **Real-time Protection:** Automatically scans sites as you visit them.
*   **Brand Impersonation Detection:** Catches fake sites like `amaz0n.com` or `paypa1.com`.
*   **RDAP Domain Analysis:** Checks the registration age of websites using modern cloud-native protocols.
*   **Heuristic Engine:** Analyzes URL structure, TLDs, and suspicious keywords.

---

## ⚙️ How it Works
The system is built with a **FastAPI** backend hosted on **Railway**, ensuring lightning-fast analysis without needing to run any code on your own machine.

### API Endpoint:
`https://url-detection-production-206d.up.railway.app/analyze`

---

## 🛠️ Security Note
GuardLink's detections are heuristic-based. While it catch the vast majority of phishing attempts, always stay vigilant and never enter sensitive data on sites you don't trust.

---
*Created by Kathir & Antigravity AI*
