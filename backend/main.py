import os
import re
from typing import List, Optional, Dict, Any
from fastapi import FastAPI, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from models import AuditResult, CommonSecurityModel
from parsers import normalize_config
from compliance_engine import evaluate_compliance
from adaptive_engine import get_all_rules, add_adaptive_rule
from pdf_report import generate_pdf_report
from samples import SAMPLES

app = FastAPI(
    title="EliteCore Network Security Compliance Auditor API",
    description="AI-Augmented, Vendor-Agnostic Multi-Framework Compliance & Remediation Platform",
    version="2.0.0"
)

# Enable CORS for Vercel frontend cross-origin requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def get_root():
    return {
        "service": "EliteCore Autonomous Compliance Engine API",
        "version": "2.0.0",
        "documentation": "/docs",
        "status": "online",
        "supported_frameworks": [
            "CIS Benchmarks v2.0",
            "NIST CSF 2.0 / SP 800-53",
            "DISA STIGs (DoD Standard)",
            "ISO/IEC 27001"
        ]
    }

class AuditRequest(BaseModel):
    raw_config: str
    vendor: Optional[str] = "auto"
    selected_frameworks: Optional[List[str]] = ["CIS", "NIST", "DISA_STIG", "ISO_27001"]

class TeachRequest(BaseModel):
    vendor: str
    command_pattern: str
    target_parameter: str
    extracted_value: Any
    description: Optional[str] = ""

class SimulateFixRequest(BaseModel):
    raw_config: str
    vendor: str
    selected_frameworks: Optional[List[str]] = ["CIS", "NIST", "DISA_STIG", "ISO_27001"]

@app.get("/api/health")
def health_check():
    return {
        "status": "healthy",
        "service": "EliteCore Compliance Engine",
        "version": "2.0.0",
        "active_frameworks": ["CIS Benchmarks v2.0", "NIST CSF 2.0", "DISA STIGs", "ISO/IEC 27001"]
    }

@app.get("/api/samples")
def get_sample_configs():
    return SAMPLES

@app.post("/api/audit", response_model=AuditResult)
def run_audit(req: AuditRequest):
    if not req.raw_config or not req.raw_config.strip():
        raise HTTPException(status_code=400, detail="Configuration content cannot be empty.")
    
    # 1. Normalization into Common Security Model
    csm = normalize_config(req.raw_config, req.vendor)
    
    # 2. Multi-Framework Compliance Evaluation
    audit_res = evaluate_compliance(csm, req.selected_frameworks)
    return audit_res

@app.post("/api/simulate-fix")
def simulate_auto_remediation(req: SimulateFixRequest):
    """Applies simulated hardening fixes to the raw config text and recalculates compliance."""
    config_text = req.raw_config
    vendor = req.vendor.lower()
    
    # Apply standard vendor transformations
    if "cisco" in vendor:
        config_text = re.sub(r"transport input[^\n]+", "transport input ssh", config_text)
        config_text = re.sub(r"ip ssh version\s+1", "ip ssh version 2", config_text)
        config_text = re.sub(r"exec-timeout\s+0\s+0", "exec-timeout 5 0", config_text)
        config_text = re.sub(r"snmp-server community public[^\n]+", "snmp-server group SECURE_V3 v3 priv", config_text)
        if "logging host" not in config_text:
            config_text += "\nlogging host 10.10.10.50\nservice timestamps log datetime msec\n"
        if "no service password-encryption" in config_text:
            config_text = config_text.replace("no service password-encryption", "service password-encryption")
            
    elif "juniper" in vendor:
        config_text = re.sub(r"protocol-version\s+v1;", "protocol-version v2;", config_text)
        config_text = re.sub(r"telnet;\s*", "", config_text)
        config_text = re.sub(r"community public", "community private_restricted", config_text)
        if "idle-timeout" not in config_text:
            config_text += "\nset system login idle-timeout 5\n"
            
    elif "fortinet" in vendor:
        config_text = re.sub(r"set admin-telnet enable", "set admin-telnet disable", config_text)
        config_text = re.sub(r"set admintimeout 0", "set admintimeout 5", config_text)
        config_text = re.sub(r'set name "public"', 'set name "company_snmp_v3"', config_text)
        
    elif "palo alto" in vendor:
        config_text = re.sub(r"set deviceconfig system idle-timeout 0", "set deviceconfig system idle-timeout 5", config_text)
        config_text = re.sub(r"disable-telnet no", "disable-telnet yes", config_text)
        
    # Re-evaluate with hardened configuration
    csm = normalize_config(config_text, req.vendor)
    audit_res = evaluate_compliance(csm, req.selected_frameworks)
    
    return {
        "hardened_config": config_text,
        "audit_result": audit_res
    }

@app.get("/api/adaptive/rules")
def list_adaptive_rules():
    return get_all_rules()

@app.post("/api/adaptive/teach")
def teach_adaptive_rule(req: TeachRequest):
    rule = add_adaptive_rule(
        vendor=req.vendor,
        command_pattern=req.command_pattern,
        target_parameter=req.target_parameter,
        extracted_value=req.extracted_value,
        description=req.description
    )
    return {
        "message": "Successfully taught system new command syntax.",
        "rule": rule,
        "total_learned_rules": len(get_all_rules())
    }

@app.post("/api/report/pdf")
def export_pdf(audit_res: AuditResult):
    pdf_bytes = generate_pdf_report(audit_res)
    hostname = audit_res.device_info.get("hostname", "Device").replace(" ", "_")
    filename = f"EliteCore_Compliance_Report_{hostname}.pdf"
    
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename={filename}"
        }
    )

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=True)
