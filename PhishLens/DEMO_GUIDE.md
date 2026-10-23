# 🛡️ PhishLens AI — Quick Demo & Presentation Guide

## 💡 30-Second Elevator Pitch (For Judges)
> *"Traditional blacklists only block scam websites **hours or days after victims have already lost money**. PhishLens uses AI, domain age verification, and live browser protection to detect and block zero-day phishing websites **before anyone falls for them**. We have built both an **Automatic Chrome Extension** that guards users while browsing, and a **Real-Time Security Dashboard** for deep inspection."*

---

## 🚀 Live Working URLs
- **Web Dashboard**: `http://localhost:5173/`
- **Backend API**: `http://localhost:8000/`
- **Chrome Extension Folder**: `c:\Users\hp\SGU_HackX\PhishLens\extension\dist`

---

## 🎯 3-Step Live Demonstration Flow

### Step 1: Show Chrome Extension (Feature 1)
1. Open Google Chrome.
2. In a tab, open `https://google.com` -> Show green badge (`✓`).
3. Now open a dangerous phishing link (e.g., `https://paypa1-security-verification.com` or demo test page).
4. Show how the extension automatically catches it and warns the user with a **Red Warning Overlay**!
5. Click the extension popup and click the blue **"Dashboard ↗"** button.

### Step 2: Show Automatic Real-Time Dashboard (Feature 2)
1. Point to the **"Automatic Browser Protection"** indicator on the dashboard (`http://localhost:5173/`).
2. Show that whatever site was just opened in Chrome automatically streamed to the dashboard!
3. Highlight the **Circular Risk Gauge** (Score 78 / 100 - Dangerous).
4. Walk through the **User-Friendly Safety Breakdown**:
   - 🔗 **Web Address Check**: Caught look-alike name imitating PayPal (`paypa1`)
   - 📄 **Page Content & Forms**: Looked for fake password forms
   - 🚨 **Scam Blacklist**: Queried threat feeds
   - 🔒 **Security Lock (SSL)**: Validated certificate authenticity
   - 📅 **Website Age**: Checked domain registration creation date
   - 🤖 **AI Pattern Matcher**: Spotted scam patterns using machine learning
5. Show the **AI Safety Assistant** (Powered by Gemini) writing a 2-sentence plain English explanation.

### Step 3: Show "Scan Multiple Links at Once" (Bulk Scanner)
1. Click **"Scan Multiple Links"** in the top navigation bar.
2. Click **"Load Example Links"** -> Click **"Check All Links"**.
3. Watch the progress bar scan 6 links simultaneously and categorize them into Safe / Suspicious / Dangerous.
4. Click **"Download Report (CSV)"** to show that IT and security teams can export findings instantly.
