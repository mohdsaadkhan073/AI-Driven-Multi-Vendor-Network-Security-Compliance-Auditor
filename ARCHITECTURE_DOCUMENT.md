# ARCHITECTURE SPECIFICATION DOCUMENT
## EliteCore Autonomous Network Security Compliance Auditor
**Theme:** Smart Automation / Enterprise Cybersecurity | **Event:** Smart India Hackathon 2026-27

---

### 1. Architectural Philosophy & Problem Definition

Heterogeneous enterprise and national critical network infrastructures comprise a disparate array of hardware vendors—from legacy chassis switches (Cisco Catalyst, Juniper EX) to next-generation firewalls (Palo Alto, Fortinet) and disaggregated whitebox switches (SONiC, Cumulus Linux).

Auditing compliance against mandated national and global baselines (**CIS Benchmarks**, **NIST SP 800-53 / CSF 2.0**, **DISA STIGs**, and **ISO/IEC 27001**) is hindered by two fundamental bottlenecks:
1. **Syntactic Fragmentation**: Identical security requirements (e.g., terminating inactive admin sessions) are expressed in incompatible, vendor-specific syntax (`exec-timeout 5 0` vs `set system login idle-timeout 5` vs `set admintimeout 5`).
2. **Firmware & Hardware Drift**: Hardcoded parser libraries break whenever manufacturers alter syntax tokens or when novel whitebox AI-cluster switches are integrated.

**EliteCore Auditor** introduces a **Model-Driven, Decoupled Architecture** where raw configurations are translated into an immutable, vendor-neutral **Common Security Model (CSM)** before compliance evaluation takes place, augmented by a **Human-in-the-Loop Adaptive Learning Loop**.

---

### 2. Multi-Tier System Architecture

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                            PRESENTATION TIER                                 │
│  • Ingestion Workbench (CLI Syntax Editor, Line-Number Sync)                 │
│  • Executive Scorecard (Real-Time Compliance Ring, Severity Metrics)         │
│  • Framework Matrix (CIS, NIST, DISA STIG, ISO 27001 Progress Trackers)     │
│  • Adaptive Training Studio (Syntax Gap Inspector, 1-Click Mapping Modal)    │
└──────────────────────────────────────┬───────────────────────────────────────┘
                                       │ REST / JSON (HTTP 8000)
┌──────────────────────────────────────▼───────────────────────────────────────┐
│                       INGESTION & NORMALIZATION TIER                         │
│  • Vendor Fingerprinting Engine (Heuristic Header & Syntax Token Detection)  │
│  • Syntax Normalization Parsers (Cisco, Juniper, Fortinet, Palo Alto)       │
│  • Evidence Extraction Engine (Line Number & Exact CLI Command Binding)      │
└──────────────────────────────────────┬───────────────────────────────────────┘
                                       │ Populates
┌──────────────────────────────────────▼───────────────────────────────────────┐
│                     THE COMMON SECURITY MODEL (CSM)                          │
│  Immutable, Vendor-Agnostic Pydantic Schema:                                 │
│  ├── management_access  (ssh_version: 2, telnet_disabled: true, timeout: 300)│
│  ├── access_control     (password_encryption: true, banner_configured: true) │
│  ├── logging_telemetry  (syslog_servers: ["10.10.10.50"], timestamps: true)  │
│  └── snmp_security      (v3_enforced: true, insecure_communities: [])        │
└───────────────────┬───────────────────────────────────────┬──────────────────┘
                    │ Evaluates                             │ Gap Trigger
┌───────────────────▼───────────────┐       ┌───────────────▼──────────────────┐
│     MULTI-FRAMEWORK ENGINE        │       │     ADAPTIVE TRAINING LOOP       │
│ • CIS Benchmarks Evaluation Rules │       │ • Unrecognized Token Detection   │
│ • NIST CSF 2.0 Deviation Matrix   │       │ • Interactive Low-Code GUI Map   │
│ • DISA STIGs DoD Security Checks  │       │ • Dynamic JSON Rule Persistence  │
│ • ISO/IEC 27001 Annex A.8 Rules   │       │ • Zero-Redeployment Assimilation │
└───────────────────┬───────────────┘       └──────────────────────────────────┘
                    │
┌───────────────────▼──────────────────────────────────────────────────────────┐
│                        ACTIONABLE REMEDIATION TIER                           │
│  • Device-Specific CLI Synthesis Engine (Cisco IOS-XE / Junos / FortiOS)     │
│  • In-Memory Hardening Simulator (Validates Score Jump Before Deployment)    │
│  • Executive ReportLab PDF Reporting Engine (Audit Certification Artifacts)  │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

### 3. Core Subsystems & Technical Implementation

#### A. Ingestion & Vendor Fingerprinting
Incoming configuration streams are inspected through an asynchronous FastAPI pipeline. The engine performs token classification to identify vendor architecture (`IOS-XE`, `JunOS`, `FortiOS`, `PAN-OS`, or `SONiC`). Rather than relying on rigid parsing, each parser populates an **Evidence Map** containing exact 1-indexed line numbers and raw command text, establishing strict cryptographic and forensic audit traceability.

#### B. The Common Security Model (CSM) Contract
The CSM serves as the unified "Source of Truth". All downstream evaluation logic is strictly decoupled from vendor-specific syntax. 

```python
class CommonSecurityModel(BaseModel):
    hostname: str
    vendor: str
    ssh_version: Optional[int]
    telnet_disabled: bool
    inactivity_timeout_seconds: Optional[int]
    login_banner_configured: bool
    logging_enabled: bool
    syslog_servers: List[str]
    insecure_community_detected: bool
    evidence_map: Dict[str, Dict[str, Any]]
```

#### C. Multi-Framework Compliance Matrix
The engine compares the normalized CSM against parameterized threshold baselines across the four major frameworks. Findings are classified into four risk severity tiers:
* **CRITICAL**: Cleartext administrative protocols (Telnet active), default SNMP community (`public`/`private`).
* **HIGH**: Absence of session inactivity limits, missing centralized syslog forwarding.
* **MEDIUM**: Unsynchronized system clocks (missing NTP), unencrypted local credentials.
* **LOW**: Non-standard administrative banners.

#### D. The Adaptive Training Loop (Continuous Learning)
To overcome the brittleness of traditional parsers when encountering uncatalogued commands (e.g., custom firmware or whitebox appliances), the **Adaptive Training Engine** implements a human-in-the-loop workflow:
1. **Gap Identification**: Identifies configuration lines bearing security-relevant keywords that were not bound to any CSM parameter.
2. **Low-Code Administrator Mapping**: The admin selects the target parameter and extracted semantic value via an intuitive GUI.
3. **Dynamic Rule Persistence**: The mapping is saved to `learned_rules.json` as a regex extraction rule.
4. **Immediate Re-Evaluation**: The engine applies the newly assimilated rule instantaneously across all active and future audits without restarting the process or recompiling models.

#### E. Autonomous Device-Specific Remediation & PDF Generation
Unlike legacy scanners that only issue warnings, EliteCore synthesizes the exact, copy-pasteable CLI commands formatted specifically for that target vendor's syntax. The built-in **ReportLab PDF engine** compiles device identity, risk metrics, line-level evidence, and complete remediation sequences into an executive audit report ready for regulatory submission.

---

### 4. Non-Functional Requirements & Enterprise Scalability

* **Zero Cloud Latency**: 100% offline and on-premises operational capability—ensuring zero data leakage of sensitive network topologies.
* **Extensible Schema**: Adding a new framework requires only defining a new threshold evaluation function against the existing Common Security Model.
* **Performance**: Sub-100ms normalization and audit time for typical 5,000-line network configuration files.
