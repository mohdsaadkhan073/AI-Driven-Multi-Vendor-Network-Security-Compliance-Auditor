import json
import os
import re
import uuid
from datetime import datetime
from typing import List, Dict, Any, Optional

RULES_FILE = os.path.join(os.path.dirname(__file__), "data", "learned_rules.json")

DEFAULT_RULES = [
    {
        "id": "rule-whitebox-001",
        "vendor_pattern": "whitebox|sonic|cumulus",
        "command_pattern": r"session-idle-limit\s+(\d+)",
        "target_parameter": "inactivity_timeout_seconds",
        "extracted_value": "{group1}",
        "created_at": "2026-09-20 10:00:00",
        "description": "Whitebox SONiC session idle limit parameter mapped to CSM inactivity_timeout_seconds"
    },
    {
        "id": "rule-huawei-002",
        "vendor_pattern": "huawei|vrp",
        "command_pattern": r"ssh\s+server\s+timeout\s+(\d+)",
        "target_parameter": "inactivity_timeout_seconds",
        "extracted_value": "{group1}",
        "created_at": "2026-09-21 14:30:00",
        "description": "Huawei VRP SSH timeout mapped to CSM inactivity_timeout_seconds"
    }
]

def init_rules_file():
    if not os.path.exists(RULES_FILE):
        os.makedirs(os.path.dirname(RULES_FILE), exist_ok=True)
        with open(RULES_FILE, "w", encoding="utf-8") as f:
            json.dump(DEFAULT_RULES, f, indent=2)

def get_all_rules() -> List[Dict[str, Any]]:
    init_rules_file()
    try:
        with open(RULES_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return DEFAULT_RULES

def save_rules(rules: List[Dict[str, Any]]):
    init_rules_file()
    with open(RULES_FILE, "w", encoding="utf-8") as f:
        json.dump(rules, f, indent=2)

def add_adaptive_rule(vendor: str, command_pattern: str, target_parameter: str, extracted_value: Any, description: str) -> Dict[str, Any]:
    rules = get_all_rules()
    new_rule = {
        "id": f"rule-{uuid.uuid4().hex[:8]}",
        "vendor_pattern": vendor.lower(),
        "command_pattern": command_pattern,
        "target_parameter": target_parameter,
        "extracted_value": extracted_value,
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "description": description or f"Custom learned mapping for {vendor}"
    }
    rules.append(new_rule)
    save_rules(rules)
    return new_rule

def apply_adaptive_rules(lines: List[str], vendor: str, csm_dict: Dict[str, Any]) -> List[str]:
    """Applies learned rules dynamically to the extracted CSM."""
    rules = get_all_rules()
    applied = []
    
    for r in rules:
        vendor_match = re.search(r["vendor_pattern"], vendor, re.IGNORECASE) or r["vendor_pattern"] == "all"
        if not vendor_match:
            continue
            
        pattern = r["command_pattern"]
        for idx, line in enumerate(lines):
            line_str = line.strip()
            match = re.search(pattern, line_str, re.IGNORECASE)
            if match:
                target_param = r["target_parameter"]
                val = r["extracted_value"]
                
                # Check for group replacements
                if isinstance(val, str) and "{group1}" in val and match.groups():
                    val = match.group(1)
                    if val.isdigit():
                        val = int(val)
                elif isinstance(val, str) and val.isdigit():
                    val = int(val)
                elif val in ["true", "True", True]:
                    val = True
                elif val in ["false", "False", False]:
                    val = False
                    
                csm_dict[target_param] = val
                csm_dict["evidence_map"][target_param] = {
                    "line": idx + 1,
                    "text": line_str,
                    "rule_id": r["id"],
                    "learned": True
                }
                applied.append(f"Applied {r['id']} on line {idx+1}: {target_param} = {val}")
    return applied

def detect_unrecognized_tokens(lines: List[str], vendor: str, recognized_lines: set) -> List[Dict[str, Any]]:
    """Identifies lines with security-relevant terms that were NOT captured by static parsers."""
    security_keywords = [
        "timeout", "idle", "session", "crypto", "cipher", "secret", "password", 
        "banner", "audit", "syslog", "logging", "snmp", "ntp", "ssh", "telnet",
        "radius", "tacacs", "login", "aaa"
    ]
    
    candidates = []
    for idx, line in enumerate(lines):
        line_no = idx + 1
        if line_no in recognized_lines:
            continue
            
        text = line.strip()
        if not text or text.startswith("!") or text.startswith("#") or text.startswith("//"):
            continue
            
        text_lower = text.lower()
        matched_kw = [kw for kw in security_keywords if kw in text_lower]
        if matched_kw:
            # Candidate parameter suggestion
            suggested_param = "inactivity_timeout_seconds" if ("timeout" in text_lower or "idle" in text_lower) else \
                              "login_banner_configured" if "banner" in text_lower else \
                              "ssh_version" if "ssh" in text_lower else \
                              "logging_enabled" if ("log" in text_lower or "syslog" in text_lower) else \
                              "snmp_v3_enforced" if "snmp" in text_lower else "password_encryption_enabled"
            
            candidates.append({
                "line": line_no,
                "raw_text": text,
                "keywords": matched_kw,
                "suggested_parameter": suggested_param,
                "suggested_value": 300 if "timeout" in text_lower else True
            })
    return candidates
