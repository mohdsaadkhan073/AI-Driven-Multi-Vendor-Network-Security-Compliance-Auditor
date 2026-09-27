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

## 4. How to Use & Example Walkthrough

You can test and verify the complete compliance auditing, normalization, remediation, and report generation pipeline using the steps below.

---

### Walkthrough 1: One-Click Evaluation with Built-in Presets

1. **Select a Target Vendor Appliance**:
   * Click any button on the top toolbar:
     * `Cisco Catalyst (IOS-XE)`
     * `Juniper SRX (JunOS)`
     * `Fortinet FortiGate (FortiOS)`
     * `Palo Alto (PAN-OS)`
     * `WhiteBox SONiC (Adaptive Mode)`
   * Notice that the configuration buffer on the left updates instantly with genuine vendor CLI syntax, line numbers, and device metadata (`VENDOR`, `DEVICE`, `BUFFER`).

2. **Execute the Multi-Framework Audit**:
   * Click the blue **"Run Security Audit"** button.
   * Watch the optical scanner laser sweep down the configuration editor.
   * The compliance radial gauge animates and calculates the overall score (e.g., **33.3%** for Cisco with 4/12 controls passed and 3 critical gaps).
   * Check or uncheck any of the **Evaluated Frameworks** (`CIS Benchmarks v2.0`, `NIST CSF 2.0`, `DISA STIGs`, `ISO/IEC 27001`) to see scores update in real time.

3. **Inspect the Common Security Model (CSM)**:
   * Click the **"Common Security Model (CSM)"** tab.
   * View the vendor-neutral JSON AST schema generated by the lexer, showing canonical security flags (`telnet_disabled: false`, `ssh_version: 1`, `idle_timeout_seconds: 0`, `snmp_v3_only: false`).

4. **Trigger 1-Click Automated CLI Remediation**:
   * Click the green **"Simulate Auto-Fix"** button in the header.
   * The engine synthesizes device-specific hardening CLI commands:
     * Disables Telnet and enforces `transport input ssh`
     * Upgrades SSH version to `ip ssh version 2`
     * Sets inactivity timeouts to `exec-timeout 5 0`
     * Hardens SNMP communities from `public` to secure v3 groups
   * The configuration editor is updated with the hardened configuration and the compliance score automatically boosts to **83.3%** / **100%**.

5. **Generate Executive Compliance PDF Report**:
   * Click the **"Export PDF Report"** button in the header.
   * An official, branded compliance report (`EliteCore_Audit_Report_<Device>.pdf`) downloads immediately, containing executive scorecards, framework progress charts, and line-by-line remediation tables.

---

### Walkthrough 2: Testing with a Custom Raw CLI Configuration

To verify custom parsing, paste the following sample configuration directly into the **Raw Configuration Stream** editor:

```text
! Custom Edge Router Configuration (Test Sample)
hostname Core-Gateway-Router
no service password-encryption
enable secret 9 $9$vW8d$K7/O29348924089248209
aaa new-model
ip ssh version 1
no ip http server
snmp-server community public RO
line con 0
 exec-timeout 0 0
line vty 0 4
 transport input telnet ssh
 exec-timeout 0 0
 login local
end
```

#### Steps to Verify:
1. Paste the text above into the left code editor.
2. Click **"Run Security Audit"**.
3. **Verify the Output**:
   * **Overall Compliance Score**: `16.7%` (Red Status)
   * **Passed Controls**: `2/12`
   * **Critical Vulnerabilities Detected**:
     * **CIS 2.1.1 (Critical)**: `Ensure Insecure Telnet Service Is Disabled` (Evidence: line vty transport input contains telnet)
     * **CIS 2.1.2 (Critical)**: `Ensure SSH Version 2 Is Exclusively Configured` (Evidence: `ip ssh version 1`)
     * **CIS 2.1.4 (High)**: `Configure Inactivity Timeout on VTY Sessions` (Evidence: `exec-timeout 0 0`)
     * **CIS 2.2.1 (Medium)**: `Ensure Insecure Default SNMP Community Strings Are Disabled` (Evidence: `snmp-server community public`)
4. Click **"Simulate Auto-Fix"**: Observe automatic CLI remediation and recalculation — the compliance score increases to **66.7%** (8/12 controls passed).

---

### Walkthrough 3: Testing the Adaptive Learning Engine (WhiteBox Mode)

1. Click the **"WhiteBox SONiC (Adaptive Mode)"** preset button.
2. Switch to the **"Adaptive Training Studio"** tab.
3. Observe the uncatalogued syntax detected by the engine:
   * `Line 3: session-idle-limit 300` (Suggested parameter: `idle_timeout_seconds`)
4. Click **"Map Syntax"**, confirm the target parameter (`idle_timeout_seconds`), and click **"Save to Knowledge Base & Re-Audit"**.
5. The engine assimilates the novel whitebox syntax into its knowledge base and recalculates compliance dynamically without server downtime or code changes.
