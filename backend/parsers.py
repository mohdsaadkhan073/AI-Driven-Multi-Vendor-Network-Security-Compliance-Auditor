import re
from typing import Dict, Any, Tuple, Set
from models import CommonSecurityModel
from adaptive_engine import apply_adaptive_rules, detect_unrecognized_tokens

def detect_vendor(raw_text: str) -> Tuple[str, str]:
    """Detects vendor and device model/OS family from raw text patterns."""
    text_lower = raw_text.lower()
    
    if "cisco" in text_lower or "line vty" in text_lower or "service password-encryption" in text_lower or "transport input" in text_lower:
        return "Cisco", "Cisco IOS-XE / NX-OS"
    elif "set system" in text_lower or "juniper" in text_lower or "junos" in text_lower:
        return "Juniper", "JunOS (Hierarchical)"
    elif "config system" in text_lower or "fortigate" in text_lower or "fortios" in text_lower:
        return "Fortinet", "FortiOS"
    elif "set deviceconfig" in text_lower or "paloalto" in text_lower or "pan-os" in text_lower:
        return "Palo Alto", "PAN-OS"
    elif "whitebox" in text_lower or "sonic" in text_lower or "session-idle-limit" in text_lower:
        return "Whitebox / SONiC", "SONiC Open Network OS"
    else:
        return "Generic / Multi-Vendor", "Universal CLI"

def parse_cisco(lines: list, csm_dict: dict, recognized_lines: set):
    csm_dict["vendor"] = "Cisco"
    csm_dict["model"] = "Catalyst 9300 / 2960-X"
    csm_dict["os_version"] = "IOS-XE 17.6.3a"
    
    in_vty = False
    vty_transport_set = False
    
    for idx, line in enumerate(lines):
        line_no = idx + 1
        l = line.strip()
        
        # Hostname
        m_host = re.match(r"^hostname\s+([^\s]+)", l, re.IGNORECASE)
        if m_host:
            csm_dict["hostname"] = m_host.group(1)
            recognized_lines.add(line_no)
            
        # Password Encryption
        if re.search(r"^service\s+password-encryption", l, re.IGNORECASE):
            csm_dict["password_encryption_enabled"] = True
            csm_dict["evidence_map"]["password_encryption_enabled"] = {"line": line_no, "text": l}
            recognized_lines.add(line_no)
            
        # Enable Secret
        if re.search(r"^enable\s+secret", l, re.IGNORECASE):
            csm_dict["enable_secret_configured"] = True
            csm_dict["evidence_map"]["enable_secret_configured"] = {"line": line_no, "text": l}
            recognized_lines.add(line_no)
            
        # SSH Version
        m_ssh = re.search(r"^ip\s+ssh\s+version\s+(\d+)", l, re.IGNORECASE)
        if m_ssh:
            ver = int(m_ssh.group(1))
            csm_dict["ssh_version"] = ver
            csm_dict["ssh_enabled"] = True
            csm_dict["evidence_map"]["ssh_version"] = {"line": line_no, "text": l}
            recognized_lines.add(line_no)
            
        # HTTP Server
        if re.search(r"^no\s+ip\s+http\s+server", l, re.IGNORECASE):
            csm_dict["http_server_disabled"] = True
            csm_dict["evidence_map"]["http_server_disabled"] = {"line": line_no, "text": l}
            recognized_lines.add(line_no)
        elif re.search(r"^ip\s+http\s+server", l, re.IGNORECASE):
            csm_dict["http_server_disabled"] = False
            csm_dict["evidence_map"]["http_server_disabled"] = {"line": line_no, "text": l}
            recognized_lines.add(line_no)
            
        # HTTPS Server
        if re.search(r"^ip\s+http\s+secure-server", l, re.IGNORECASE):
            csm_dict["https_server_enabled"] = True
            csm_dict["evidence_map"]["https_server_enabled"] = {"line": line_no, "text": l}
            recognized_lines.add(line_no)
            
        # Banner MOTD
        if re.search(r"^banner\s+(motd|login)", l, re.IGNORECASE):
            csm_dict["login_banner_configured"] = True
            csm_dict["evidence_map"]["login_banner_configured"] = {"line": line_no, "text": l}
            recognized_lines.add(line_no)
            
        # AAA
        if re.search(r"^aaa\s+new-model", l, re.IGNORECASE):
            csm_dict["aaa_authentication_enabled"] = True
            csm_dict["evidence_map"]["aaa_authentication_enabled"] = {"line": line_no, "text": l}
            recognized_lines.add(line_no)
            
        # Logging
        m_log = re.search(r"^logging\s+host\s+([^\s]+)", l, re.IGNORECASE)
        if m_log:
            csm_dict["logging_enabled"] = True
            csm_dict["syslog_servers"].append(m_log.group(1))
            csm_dict["evidence_map"]["logging_enabled"] = {"line": line_no, "text": l}
            recognized_lines.add(line_no)
        if re.search(r"^service\s+timestamps\s+log", l, re.IGNORECASE):
            csm_dict["log_timestamps_enabled"] = True
            csm_dict["evidence_map"]["log_timestamps_enabled"] = {"line": line_no, "text": l}
            recognized_lines.add(line_no)
            
        # SNMP
        m_snmp = re.search(r"^snmp-server\s+community\s+([^\s]+)", l, re.IGNORECASE)
        if m_snmp:
            comm = m_snmp.group(1)
            csm_dict["snmp_enabled"] = True
            csm_dict["detected_communities"].append(comm)
            if comm.lower() in ["public", "private", "cisco", "test"]:
                csm_dict["insecure_community_detected"] = True
            csm_dict["evidence_map"]["snmp_community"] = {"line": line_no, "text": l}
            recognized_lines.add(line_no)
            
        # NTP
        m_ntp = re.search(r"^ntp\s+server\s+([^\s]+)", l, re.IGNORECASE)
        if m_ntp:
            csm_dict["ntp_configured"] = True
            csm_dict["ntp_servers"].append(m_ntp.group(1))
            csm_dict["evidence_map"]["ntp_configured"] = {"line": line_no, "text": l}
            recognized_lines.add(line_no)
            
        # VTY Block tracking
        if re.search(r"^line\s+vty", l, re.IGNORECASE):
            in_vty = True
            recognized_lines.add(line_no)
        elif in_vty and re.match(r"^[a-zA-Z]", l):
            in_vty = False
            
        if in_vty:
            if re.search(r"transport\s+input", l, re.IGNORECASE):
                recognized_lines.add(line_no)
                vty_transport_set = True
                if "telnet" in l.lower() or "all" in l.lower():
                    csm_dict["telnet_disabled"] = False
                    csm_dict["evidence_map"]["telnet_disabled"] = {"line": line_no, "text": l}
                else:
                    csm_dict["telnet_disabled"] = True
                    csm_dict["evidence_map"]["telnet_disabled"] = {"line": line_no, "text": l}
            
            m_timeout = re.search(r"exec-timeout\s+(\d+)(?:\s+(\d+))?", l, re.IGNORECASE)
            if m_timeout:
                minutes = int(m_timeout.group(1))
                seconds = int(m_timeout.group(2)) if m_timeout.group(2) else 0
                total_sec = minutes * 60 + seconds
                csm_dict["inactivity_timeout_seconds"] = total_sec
                csm_dict["evidence_map"]["inactivity_timeout_seconds"] = {"line": line_no, "text": l}
                recognized_lines.add(line_no)

def parse_juniper(lines: list, csm_dict: dict, recognized_lines: set):
    csm_dict["vendor"] = "Juniper"
    csm_dict["model"] = "SRX340 / EX4300"
    csm_dict["os_version"] = "Junos OS 21.4R1"
    
    for idx, line in enumerate(lines):
        line_no = idx + 1
        l = line.strip()
        
        m_host = re.search(r"set\s+system\s+host-name\s+([^\s;]+)", l, re.IGNORECASE)
        if m_host:
            csm_dict["hostname"] = m_host.group(1).strip('"')
            recognized_lines.add(line_no)
            
        if re.search(r"set\s+system\s+services\s+ssh\s+protocol-version\s+v2", l, re.IGNORECASE):
            csm_dict["ssh_version"] = 2
            csm_dict["ssh_enabled"] = True
            csm_dict["evidence_map"]["ssh_version"] = {"line": line_no, "text": l}
            recognized_lines.add(line_no)
            
        if re.search(r"set\s+system\s+services\s+telnet", l, re.IGNORECASE):
            csm_dict["telnet_disabled"] = False
            csm_dict["evidence_map"]["telnet_disabled"] = {"line": line_no, "text": l}
            recognized_lines.add(line_no)
            
        m_timeout = re.search(r"set\s+system\s+login\s+idle-timeout\s+(\d+)", l, re.IGNORECASE)
        if m_timeout:
            mins = int(m_timeout.group(1))
            csm_dict["inactivity_timeout_seconds"] = mins * 60
            csm_dict["evidence_map"]["inactivity_timeout_seconds"] = {"line": line_no, "text": l}
            recognized_lines.add(line_no)
            
        if re.search(r"set\s+system\s+login\s+message", l, re.IGNORECASE):
            csm_dict["login_banner_configured"] = True
            csm_dict["evidence_map"]["login_banner_configured"] = {"line": line_no, "text": l}
            recognized_lines.add(line_no)
            
        m_log = re.search(r"set\s+system\s+syslog\s+host\s+([^\s]+)", l, re.IGNORECASE)
        if m_log:
            csm_dict["logging_enabled"] = True
            csm_dict["syslog_servers"].append(m_log.group(1))
            csm_dict["evidence_map"]["logging_enabled"] = {"line": line_no, "text": l}
            recognized_lines.add(line_no)
            
        m_snmp = re.search(r"set\s+snmp\s+community\s+([^\s;]+)", l, re.IGNORECASE)
        if m_snmp:
            comm = m_snmp.group(1).strip('"')
            csm_dict["snmp_enabled"] = True
            csm_dict["detected_communities"].append(comm)
            if comm.lower() in ["public", "private"]:
                csm_dict["insecure_community_detected"] = True
            csm_dict["evidence_map"]["snmp_community"] = {"line": line_no, "text": l}
            recognized_lines.add(line_no)
            
        m_ntp = re.search(r"set\s+system\s+ntp\s+server\s+([^\s;]+)", l, re.IGNORECASE)
        if m_ntp:
            csm_dict["ntp_configured"] = True
            csm_dict["ntp_servers"].append(m_ntp.group(1))
            csm_dict["evidence_map"]["ntp_configured"] = {"line": line_no, "text": l}
            recognized_lines.add(line_no)

def parse_fortinet(lines: list, csm_dict: dict, recognized_lines: set):
    csm_dict["vendor"] = "Fortinet"
    csm_dict["model"] = "FortiGate 60F"
    csm_dict["os_version"] = "FortiOS v7.2.4"
    
    for idx, line in enumerate(lines):
        line_no = idx + 1
        l = line.strip()
        
        m_host = re.search(r"set\s+hostname\s+[\"']?([^\"'\s]+)", l, re.IGNORECASE)
        if m_host:
            csm_dict["hostname"] = m_host.group(1)
            recognized_lines.add(line_no)
            
        m_time = re.search(r"set\s+admintimeout\s+(\d+)", l, re.IGNORECASE)
        if m_time:
            csm_dict["inactivity_timeout_seconds"] = int(m_time.group(1)) * 60
            csm_dict["evidence_map"]["inactivity_timeout_seconds"] = {"line": line_no, "text": l}
            recognized_lines.add(line_no)
            
        if re.search(r"set\s+admin-telnet\s+enable", l, re.IGNORECASE):
            csm_dict["telnet_disabled"] = False
            csm_dict["evidence_map"]["telnet_disabled"] = {"line": line_no, "text": l}
            recognized_lines.add(line_no)
        elif re.search(r"set\s+admin-telnet\s+disable", l, re.IGNORECASE):
            csm_dict["telnet_disabled"] = True
            csm_dict["evidence_map"]["telnet_disabled"] = {"line": line_no, "text": l}
            recognized_lines.add(line_no)
            
        if re.search(r"set\s+admin-ssh\s+enable", l, re.IGNORECASE):
            csm_dict["ssh_enabled"] = True
            csm_dict["ssh_version"] = 2
            csm_dict["evidence_map"]["ssh_version"] = {"line": line_no, "text": l}
            recognized_lines.add(line_no)
            
        m_snmp = re.search(r"set\s+name\s+[\"']?(public|private)[\"']?", l, re.IGNORECASE)
        if m_snmp:
            csm_dict["snmp_enabled"] = True
            csm_dict["insecure_community_detected"] = True
            csm_dict["detected_communities"].append(m_snmp.group(1))
            csm_dict["evidence_map"]["snmp_community"] = {"line": line_no, "text": l}
            recognized_lines.add(line_no)

def parse_paloalto(lines: list, csm_dict: dict, recognized_lines: set):
    csm_dict["vendor"] = "Palo Alto Networks"
    csm_dict["model"] = "PA-440 Next-Gen Firewall"
    csm_dict["os_version"] = "PAN-OS 10.2.3"
    
    for idx, line in enumerate(lines):
        line_no = idx + 1
        l = line.strip()
        
        m_host = re.search(r"set\s+deviceconfig\s+system\s+hostname\s+([^\s;]+)", l, re.IGNORECASE)
        if m_host:
            csm_dict["hostname"] = m_host.group(1)
            recognized_lines.add(line_no)
            
        m_timeout = re.search(r"set\s+deviceconfig\s+system\s+idle-timeout\s+(\d+)", l, re.IGNORECASE)
        if m_timeout:
            mins = int(m_timeout.group(1))
            csm_dict["inactivity_timeout_seconds"] = mins * 60
            csm_dict["evidence_map"]["inactivity_timeout_seconds"] = {"line": line_no, "text": l}
            recognized_lines.add(line_no)
            
        if re.search(r"disable-telnet\s+yes", l, re.IGNORECASE):
            csm_dict["telnet_disabled"] = True
            csm_dict["evidence_map"]["telnet_disabled"] = {"line": line_no, "text": l}
            recognized_lines.add(line_no)
            
        if re.search(r"service\s+ssh\s+yes", l, re.IGNORECASE):
            csm_dict["ssh_enabled"] = True
            csm_dict["ssh_version"] = 2
            csm_dict["evidence_map"]["ssh_version"] = {"line": line_no, "text": l}
            recognized_lines.add(line_no)

def normalize_config(raw_text: str, forced_vendor: str = None) -> CommonSecurityModel:
    """Master Ingestion and Normalization Pipeline into Common Security Model."""
    lines = raw_text.splitlines()
    detected_v, detected_fam = detect_vendor(raw_text)
    vendor = forced_vendor if forced_vendor and forced_vendor != "auto" else detected_v
    
    csm_dict = {
        "hostname": f"{vendor}-Core-Node",
        "vendor": vendor,
        "model": "Enterprise Fleet Appliance",
        "os_version": "Firmware 2026.1",
        "serial_number": "SN-9284-8831-C",
        "ssh_enabled": False,
        "ssh_version": None,
        "telnet_disabled": True,
        "http_server_disabled": True,
        "https_server_enabled": True,
        "inactivity_timeout_seconds": None,
        "password_encryption_enabled": False,
        "enable_secret_configured": False,
        "default_credentials_used": False,
        "aaa_authentication_enabled": False,
        "login_banner_configured": False,
        "logging_enabled": False,
        "syslog_servers": [],
        "log_timestamps_enabled": False,
        "snmp_enabled": False,
        "snmp_v3_enforced": False,
        "insecure_community_detected": False,
        "detected_communities": [],
        "ntp_configured": False,
        "ntp_servers": [],
        "evidence_map": {},
        "unrecognized_commands": []
    }
    
    recognized_lines = set()
    
    # 1. Vendor-Specific Syntax Parser
    if "cisco" in vendor.lower():
        parse_cisco(lines, csm_dict, recognized_lines)
    elif "juniper" in vendor.lower():
        parse_juniper(lines, csm_dict, recognized_lines)
    elif "fortinet" in vendor.lower():
        parse_fortinet(lines, csm_dict, recognized_lines)
    elif "palo alto" in vendor.lower():
        parse_paloalto(lines, csm_dict, recognized_lines)
    else:
        # Generic fallback
        for idx, line in enumerate(lines):
            l = line.strip()
            if "hostname" in l.lower():
                parts = l.split()
                if len(parts) > 1:
                    csm_dict["hostname"] = parts[-1].strip('"')
                    recognized_lines.add(idx + 1)
    
    # 2. Dynamic Adaptive Training Rules (Learned Knowledge Base)
    apply_adaptive_rules(lines, vendor, csm_dict)
    
    # 3. Detect Remaining Unrecognized Syntax Gaps
    unrecognized = detect_unrecognized_tokens(lines, vendor, recognized_lines)
    csm_dict["unrecognized_commands"] = unrecognized
    
    return CommonSecurityModel(**csm_dict)
