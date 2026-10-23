# 📊 PhishLens AI — 5-Slide Hackathon Presentation Deck

> **Pitch Theme**: Proactive, AI-driven phishing detection that protects everyday users *before* a site is reported or blacklisted.

---

## 📑 Slide-by-Slide Outline

```
Slide 1: Title & Hook (The Identity & Vision)
Slide 2: The Problem (Why Traditional Blacklists Lag Behind)
Slide 3: The Solution (Two-Way Ecosystem: Chrome Guard + Live Dashboard)
Slide 4: Technology & Detection Engine (6-Shield Multi-Vector Analysis + Gemini AI)
Slide 5: Business Impact, Live Demo & Future Roadmap
```

---

## 🖼️ Slide 1: Title & Hook

### Slide Content
- **Main Title**: **PhishLens AI**
- **Subtitle**: Proactive Phishing & Fake Infrastructure Detector
- **Tagline**: *"Stopping Zero-Day Phishing Before Victims Fall For It"*
- **Team Info**: [Team Name] • SGU HackX 2026
- **Key Badge**: *"Browser Extension + Real-Time Live Security Dashboard"*

### Visual Layout
- Minimalist dark navy / slate background with an animated shield icon or clean logo.
- Bullet pill tags at the bottom: `#ZeroDayProtection` `#GoogleGeminiAI` `#ExplainableSecurity`

### 🎙️ Speaker Notes (What to say — 20 seconds):
> *"Good morning judges! Today, thousands of people lose money to newly registered scam websites every single hour. We are proud to present **PhishLens AI** — a proactive security solution combining an intelligent Chrome Extension and a real-time analytics dashboard to stop fake sites before anyone reports them."*

---

## 🖼️ Slide 2: The Problem — The Blacklist Delay Trap

### Slide Content
- **Header**: Why Current Cyber Defences Fail
- **The Core Flaw: The 'Report Lag'**
  - Blacklists (like Google Safe Browsing, PhishTank) are **reactive**: they require a human victim to report a scam, followed by manual review.
  - **Average window of exposure**: 4 to 24+ hours of active vulnerability.
- **The Modern Threat Landscape**:
  - Attackers use **throwaway domains** registered only 20 minutes prior.
  - **Combosquatting & Typosquatting**: Sites like `paypa1-security-verification.com` bypass legacy lexers.
  - Pixel-perfect kits designed to harvest credentials and OTPs before blacklisting occurs.
- **Key Takeaway**: *"Victims are scammed during the blindspot between site creation and blacklist reporting."*

### Visual Layout
- A split comparison graphic:
  - **Old Way (Blacklists)**: Create Fake Site ➡️ User Gets Scammed ➡️ Site Gets Reported ➡️ Blocked (Too late!)
  - **PhishLens Way**: Create Fake Site ➡️ **AI Catches Patterns at Second 0** ➡️ User Protected!

### 🎙️ Speaker Notes (35 seconds):
> *"The fundamental problem with today's anti-phishing systems is that they are reactive. By the time a malicious domain appears on a blocklist, hundreds of victims have already entered their bank credentials. Scammers exploit this 24-hour gap using cheap throwaway domains and typosquatted names. We need proactive intelligence that detects fake infrastructure the moment a user lands on the page."*

---

## 🖼️ Slide 3: The Solution — Two Integrated Features

### Slide Content
- **Header**: One Intelligent Engine — Two Seamless User Experiences
- **Feature 1: Chrome Extension (Real-Time Auto-Shield)**
  - Runs quietly inside Google Chrome.
  - Inspects every page's DOM (hidden inputs, password fields, suspicious forms) in under 50ms.
  - Displays instant safety badges: 🟢 Safe (`✓`), 🟡 Caution (`?`), 🔴 Dangerous (`!`).
  - Automatically pops up a **Full-Screen Red Danger Warning** on verified scams.
- **Feature 2: Real-Time Security Operations Dashboard**
  - **Live Browser Stream**: What you open in Chrome automatically updates on the dashboard in real-time.
  - **Circular Risk Gauge (0–100)**: Instant threat score.
  - **AI Safety Assistant (Powered by Gemini)**: Explains the risk in plain English for non-technical users.
  - **Bulk Link Scanner**: Paste 50 suspicious links from SMS or emails and get an instant CSV safety report.

### Visual Layout
- Two large feature cards side-by-side with screenshots/mockups:
  - Left card: The Chrome Extension popup with the "Dashboard ↗" button.
  - Right card: The Web Dashboard displaying the 0-100 Risk Gauge and live stream table.

### 🎙️ Speaker Notes (45 seconds):
> *"To solve this, we built a two-way ecosystem. First is our Chrome Extension that acts as a real-time bodyguard in your browser. Whenever you open a link, it checks the page immediately and blocks dangerous sites. Second is our Live Security Dashboard. Any website opened in your browser automatically streams to the dashboard, giving you a full safety breakdown, a 0 to 100 risk score, and plain-English AI explanations powered by Google Gemini."*

---

## 🖼️ Slide 4: The Technology — 6-Shield Multi-Vector Detection

### Slide Content
- **Header**: How PhishLens Detects Scams Proactively
- **Our 6 Security Shields**:
  1. 🔗 **Web Address Heuristics**: Detects token-level typosquatting (`paypa1`), look-alike Unicode characters, and high letter entropy.
  2. 📄 **Page Content & Forms**: Flags credential-harvesting password fields, hidden inputs, and rogue form actions.
  3. 🚨 **Global Scam Databases**: Real-time cross-referencing with live threat intelligence feeds.
  4. 🔒 **Security Lock (TLS/SSL)**: Analyzes Certificate Transparency logs to spot throwaway free certificates.
  5. 📅 **Website Creation Age**: Queries RDAP registration databases (sites < 14 days old get strict scrutiny).
  6. 🤖 **AI Pattern Matcher (SHAP + Scikit-Learn)**: Evaluates 16 machine learning features trained on real phishing corpora.
- **The Gemini AI Layer**: Translates technical risk vectors into simple, actionable warnings for everyday users.

### Visual Layout
- A 6-box grid or circular diagram highlighting the 6 shields feeding into the central **FastAPI Scoring Brain**, outputting the **Risk Score & Gemini AI Explanation**.

### 🎙️ Speaker Notes (45 seconds):
> *"How do we make our decisions? We don't rely on a single rule. We combine six independent security shields running in parallel. We check the domain's registration age, verify SSL certificate freshness, scan for look-alike brand names like 'paypa1', inspect the page for credential theft forms, and run a machine learning classifier with SHAP explainability. Then, Google Gemini 2.0 Flash synthesizes all findings into plain language so any user knows exactly what to do."*

---

## 🖼️ Slide 5: Live Demo, Business Impact & Future Vision

### Slide Content
- **Header**: Real-World Impact & What's Next
- **Live Demo Proof Points**:
  - Tested on `paypa1-security-verification.com` ➡️ Flagged as **🔴 Dangerous (Score: 78/100)** within 1.2 seconds.
  - Tested on legitimate sites like `google.com` ➡️ Cleared as **🟢 Safe (Score: 7/100)** with 0 false alarms.
- **Target Audience & Business Potential**:
  - **B2C**: Free Chrome browser extension protecting families, students, and seniors from UPI/banking phishing.
  - **B2B / Enterprises**: SOC teams use the Bulk Link Inspector and API to vet phishing emails across corporate inboxes.
- **Roadmap (Next 6 Months)**:
  - 📸 Visual brand screenshot comparison using CLIP image embeddings.
  - 📱 Smishing & WhatsApp QR-code phishing detector.
  - 🌐 Threat Intelligence API feed subscription for enterprise firewalls.

### Visual Layout
- Live demo screenshot or URL pill links.
- 3 key metric stat counters: `< 1.5s Scan Time`, `0-Day Accuracy`, `100% User-Friendly`.
- Team contact details and GitHub repo link.

### 🎙️ Speaker Notes (30 seconds):
> *"In our live tests, zero-day scams like fake PayPal lures were caught instantly with zero prior reporting, while real sites like Google passed with flying colors. Looking ahead, this can be deployed as an enterprise email scanner or as a consumer security extension protecting millions of internet users. Thank you, and we'd love to take your questions and show you the live demo!"*

---

## 🎯 Quick Judge Q&A Cheat-Sheet

| Likely Judge Question | Winning 1-Sentence Answer |
|---|---|
| *"How is this different from Google Safe Browsing?"* | *"Google Safe Browsing relies on known reported URLs; PhishLens analyzes domain creation patterns, typosquatting tokens, and page code to catch zero-day scam sites hours before they ever reach Google's list."* |
| *"What if a legitimate startup just bought a new domain?"* | *"Domain age is only 1 of 6 signals — a young domain with valid HTTPS and no brand impersonation or credential harvesting forms will remain in the safe/low-risk zone."* |
| *"Is user browsing data private?"* | *"Yes! PhishLens operates under strict privacy-preserving principles: passwords, cookies, and page text are never stored or transmitted to our database."* |
