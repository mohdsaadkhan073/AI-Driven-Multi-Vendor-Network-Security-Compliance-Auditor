# EliteCore Network Security Compliance Auditor
### AI-Augmented, Vendor-Agnostic Multi-Framework Network Security Compliance & Remediation Platform
**Smart India Hackathon 2026-27 | Team EliteCore**

---

## 1. Executive Summary

Modern enterprise networks consist of diverse, heterogeneous hardware from multiple vendors (Cisco, Juniper, Fortinet, Palo Alto, Arista, and WhiteBox hardware running SONiC). Auditing these devices against global security baselines (**CIS Benchmarks v2.0**, **NIST CSF 2.0 / SP 800-53**, **DISA STIGs**, and **ISO/IEC 27001**) is traditionally paralyzed by proprietary syntax differences and slow, manual spreadsheet checklists.

**EliteCore Auditor** solves this through a three-stage intelligent pipeline:
1. **Vendor-Agnostic Ingestion & Normalization**: Translates proprietary CLI commands into an immutable **Common Security Model (CSM)** JSON schema.
2. **Multi-Framework Deviation Engine**: Simultaneously evaluates the normalized state against all 4 frameworks, extracting line-level configuration evidence and calculating quantitative risk scores.
3. **Adaptive Training Loop (Human-in-the-Loop ⭐)**: When encountering novel, uncatalogued syntax from new vendors or firmware releases, administrators map the command once via an interactive GUI. The AI engine permanently assimilates this rule into its heuristics without requiring backend code redeployment or re-training downtime.
4. **Autonomous Remediation & Executive Reporting**: Generates ready-to-deploy, device-specific CLI hardening scripts and exports audit-ready executive PDF compliance reports.

---

## 2. System Architecture & Tech Stack

```
   [ Raw Network CLI Configs ]
 (Cisco / Juniper / Fortinet / PAN-OS / SONiC)
              │
              ▼
   ┌──────────────────────────────────────────────┐
   │         Ingestion & Normalization            │
   │  • Regex Tokenizer & Keyword Extraction      │
   │  • Dynamic Adaptive Heuristics Evaluator     │
   └──────────────────────┬───────────────────────┘
                          │
                          ▼
            [ Common Security Model (CSM) ]
          (Vendor-Neutral Standardized JSON)
                          │
        ┌─────────────────┴─────────────────┐
        ▼                                   ▼
┌───────────────────────────────┐   ┌───────────────────────────────┐
│   Multi-Framework Engine      │   │    Adaptive Training Loop     │
│ • CIS Benchmarks v2.0         │   │ • Unrecognized Syntax Hunter  │
│ • NIST CSF 2.0 / SP 800-53    │   │ • 1-Click Low-Code Admin Map  │
│ • DISA STIGs (DoD Standard)   │   │ • Dynamic Persistent KB       │
│ • ISO/IEC 27001 (Annex A.8)   │   └───────────────────────────────┘
└───────────────┬───────────────┘
                │
                ▼
┌────────────────────────────────────────────────────────┐
│           Actionable Output & Remediation              │
│ • Executive Scorecard & Line-Level Evidence Highlights │
│ • 1-Click Device-Specific CLI Remediation Scripts      │
│ • Executive PDF Audit Report (ReportLab Engine)        │
└────────────────────────────────────────────────────────┘
```

* **Frontend**: HTML5, Vanilla CSS Design System, Responsive Glassmorphism Architecture, Lucide SVG iconography.
* **Backend**: Python 3.10+, FastAPI (Async REST API, CORS middleware, Pydantic data validation).
* **Compliance Engine**: Custom rule evaluation matrix with automated risk categorization (Critical, High, Medium, Low).
* **Reporting**: ReportLab PDF generator producing branded executive audit reports.
* **Storage**: In-memory and persistent JSON knowledge base (`learned_rules.json`).

---

## 3. Quickstart & Setup Instructions

### Prerequisites
* Python 3.10 or higher installed.

### Installation
1. Navigate to the backend directory:
   ```bash
   cd prototype/backend
   ```
2. Install required dependencies:
   ```bash
   pip install fastapi uvicorn pydantic reportlab jinja2
   ```

### Running the Application

#### Local Development Setup
1. **Start the FastAPI Backend**:
   ```bash
   cd prototype/backend
   pip install -r requirements.txt
   python main.py
   ```
   Backend runs on `http://127.0.0.1:8000` (Interactive API docs at `/docs`).

2. **Start the Standalone Frontend (Vite)**:
   ```bash
   cd prototype/frontend
   npm install
   npm run dev
   ```
   Frontend runs on `http://localhost:3000` (auto-proxies `/api` calls to port 8000).

---

## 4. Production Deployment Guide (Vercel + Render Monorepo)

This repository is pre-configured for seamless decoupled monorepo deployment:

### 🚀 Deploying the Backend on Render
1. Create a new **Web Service** on [Render](https://render.com) and link your GitHub repository.
2. Configure the service settings:
   * **Root Directory**: `prototype/backend` (or `backend` if pushed from the subfolder)
   * **Environment**: `Python 3`
   * **Build Command**: `pip install -r requirements.txt`
   * **Start Command**: `uvicorn main:app --host 0.0.0.0 --port $PORT`
3. Click **Deploy**. Copy your public Render URL (e.g. `https://elitecore-backend.onrender.com`).

### 🌐 Deploying the Frontend on Vercel
1. Create a new project on [Vercel](https://vercel.com) and import the repository.
2. In the project settings:
   * **Root Directory**: Select `prototype/frontend` (or `frontend`)
   * **Framework Preset**: `Vite`
   * **Build Command**: `npm run build`
   * **Output Directory**: `dist`
3. Add Environment Variable:
   * **Key**: `VITE_API_URL`
   * **Value**: Your Render URL (e.g. `https://elitecore-backend.onrender.com`)
4. Click **Deploy**. Vercel will automatically build the production assets and wire all API requests directly to Render!



---

## 4. Live 3-Minute Demo Script (For SIH Judges)

1. **Step 1: Ingestion & Problem Showcase (0:00 - 0:45)**
   * Select the **"Cisco Catalyst (IOS-XE)"** quick preset.
   * Point out the raw configuration on the left panel (line vty with telnet enabled, weak SSH version, no timeout).
   * Click **"Run Security Audit"**.
   * Show the executive score card: **33.3% Overall Compliance** (Red ring, 3 Critical findings).

2. **Step 2: Multi-Framework & Normalization Proof (0:45 - 1:30)**
   * Switch to the **"Common Security Model (CSM)"** tab.
   * Explain to the judges: *"Regardless of whether this is Cisco, Juniper, or Fortinet, our engine isolates syntax from security meaning and outputs this clean JSON baseline."*
   * Point to the framework breakdown: CIS Benchmarks at 40%, NIST CSF at 66.7%, DISA STIGs at 0%.

3. **Step 3: Actionable Remediation (1:30 - 2:00)**
   * In the findings list, click a Critical finding (e.g. *CIS 2.1.1: Insecure Telnet Service*).
   * Highlight the exact **Evidence Line** and the **Synthesized Cisco CLI Script**.
   * Click **"Simulate Auto-Fix"**: Watch the editor update with hardened syntax and the compliance score automatically jump from **33.3% to 83.3%**!

4. **Step 4: The Star Differentiator: Adaptive Training Loop (2:00 - 2:40 ⭐)**
   * Click the **"WhiteBox Switch (Adaptive Demo ⭐)"** preset.
   * Explain: *"When new whitebox hardware or custom firmware with uncatalogued commands is introduced, traditional regex parsers fail."*
   * Switch to the **"Adaptive Training Studio"** tab.
   * Point out the amber alert: `Line 3: session-idle-limit 300`.
   * Click **"Map Syntax"**, select `Inactivity Session Timeout`, and click **"Save to Knowledge Base & Re-Audit"**.
   * Show the judges that the rule was learned permanently and compliance updated dynamically without redeploying code!

5. **Step 5: Executive PDF Deliverable (2:40 - 3:00)**
   * Click **"Export PDF Report"** in the top navigation bar.
   * Open the downloaded PDF: showcase the branded executive report with device metadata, framework score cards, and actionable remediation tables.
