from typing import List, Dict, Any, Tuple
from models import CommonSecurityModel, ComplianceFinding, FrameworkScore, AuditResult

def get_device_remediation(vendor: str, control_key: str) -> Tuple[str, str]:
    """Generates vendor-specific remediation commands."""
    v = vendor.lower()
    
    if control_key == "telnet":
        if "cisco" in v:
            return (
                "configure terminal\nline vty 0 15\n transport input ssh\nexit\nwrite memory",
                "Restricts incoming VTY terminal connections strictly to encrypted SSH and disables insecure cleartext Telnet."
            )
        elif "juniper" in v:
            return (
                "edit\ndelete system services telnet\nset system services ssh protocol-version v2\ncommit and-quit",
                "Removes Telnet daemon from JunOS system services and enforces SSH v2."
            )
        elif "fortinet" in v:
            return (
                "config system admin setting\n set admin-telnet disable\n set admin-ssh enable\nend",
                "Disables administrative Telnet access across all management interfaces in FortiOS."
            )
        elif "palo alto" in v:
            return (
                "configure\nset deviceconfig system service disable-telnet yes\nset deviceconfig system service ssh yes\ncommit",
                "Blocks Telnet management services on the Palo Alto management plane."
            )
        else:
            return (
                "# Vendor Remediation Sequence\nservice telnet disable\nservice ssh enable\nsave configuration",
                "Disable cleartext remote terminal services and enforce cryptographic SSH."
            )
            
    elif control_key == "ssh_version":
        if "cisco" in v:
            return (
                "configure terminal\nip ssh version 2\nline vty 0 15\n transport input ssh\nexit\nwrite memory",
                "Forces Cisco IOS SSH server to negotiate only SSH Version 2 protocol."
            )
        elif "juniper" in v:
            return (
                "edit\nset system services ssh protocol-version v2\ncommit and-quit",
                "Restricts JunOS SSH listener strictly to Protocol Version 2."
            )
        elif "fortinet" in v:
            return (
                "config system global\n set strong-crypto enable\nend",
                "Enforces modern SSH ciphers and protocol versions."
            )
        else:
            return (
                "configure terminal\nssh-server protocol-version 2\nwrite",
                "Enforces modern SSH Version 2 ciphers."
            )
            
    elif control_key == "timeout":
        if "cisco" in v:
            return (
                "configure terminal\nline con 0\n exec-timeout 5 0\nline vty 0 15\n exec-timeout 5 0\nexit\nwrite memory",
                "Sets administrative inactivity timeout to 5 minutes (300 seconds) on console and VTY lines."
            )
        elif "juniper" in v:
            return (
                "edit\nset system login idle-timeout 5\ncommit and-quit",
                "Enforces 5-minute inactivity auto-logout across all login classes in JunOS."
            )
        elif "fortinet" in v:
            return (
                "config system global\n set admintimeout 5\nend",
                "Configures FortiOS global admin idle session timeout to 5 minutes."
            )
        elif "palo alto" in v:
            return (
                "configure\nset deviceconfig system idle-timeout 5\ncommit",
                "Sets administrator inactivity logout to 5 minutes."
            )
        else:
            return (
                "session-timeout idle 300\nsave",
                "Terminates abandoned administrative sessions after 5 minutes."
            )
            
    elif control_key == "snmp":
        if "cisco" in v:
            return (
                "configure terminal\nno snmp-server community public\nno snmp-server community private\nsnmp-server group SECURE_V3 v3 priv\nexit\nwrite memory",
                "Purges default public/private strings and migrates SNMP to authenticated/encrypted SNMPv3."
            )
        elif "juniper" in v:
            return (
                "edit\ndelete snmp community public\ndelete snmp community private\ncommit and-quit",
                "Removes default community strings from JunOS SNMP configuration."
            )
        elif "fortinet" in v:
            return (
                "config system snmp community\n delete 1\nend",
                "Deletes legacy SNMP community with default name 'public'."
            )
        else:
            return (
                "no snmp-server community public\nsave",
                "Eliminates default vendor community strings."
            )
            
    elif control_key == "logging":
        if "cisco" in v:
            return (
                "configure terminal\nlogging host 10.10.10.50\nservice timestamps log datetime msec\nexit\nwrite memory",
                "Enables millisecond-accurate log timestamps and redirects audit trails to centralized SIEM."
            )
        elif "juniper" in v:
            return (
                "edit\nset system syslog host 10.10.10.50 any any\nset system syslog host 10.10.10.50 time-format millisecond\ncommit and-quit",
                "Streams security telemetry to central log management with millisecond timestamps."
            )
        elif "fortinet" in v:
            return (
                "config log syslogd setting\n set status enable\n set server \"10.10.10.50\"\nend",
                "Directs FortiGate firewall logs to centralized syslog collector."
            )
        else:
            return (
                "logging host 10.10.10.50\nlogging enable\nsave",
                "Forward audit logs to corporate SIEM collector."
            )
            
    elif control_key == "banner":
        if "cisco" in v:
            return (
                "configure terminal\nbanner motd ^C\n=======================================================\nAUTHORIZED PERSONNEL ONLY. ALL ACTIVITIES ARE MONITORED.\n=======================================================^C\nexit\nwrite memory",
                "Configures legal warning banner for unauthorized access deterrence."
            )
        elif "juniper" in v:
            return (
                "edit\nset system login message \"AUTHORIZED PERSONNEL ONLY. ALL ACTIVITIES ARE MONITORED.\"\ncommit and-quit",
                "Displays pre-login legal warning message."
            )
        else:
            return (
                "banner login \"AUTHORIZED USE ONLY\"\nsave",
                "Enforces legal system notice before shell authorization."
            )
            
    elif control_key == "ntp":
        if "cisco" in v:
            return (
                "configure terminal\nntp server 10.0.0.1\nntp server 10.0.0.2\nexit\nwrite memory",
                "Synchronizes system clock with redundant internal NTP servers."
            )
        else:
            return (
                "ntp server 10.0.0.1\nsave",
                "Ensures accurate clock synchronization for forensic audit logs."
            )
            
    elif control_key == "encryption":
        if "cisco" in v:
            return (
                "configure terminal\nservice password-encryption\nexit\nwrite memory",
                "Encrypts plain-text passwords stored in running configuration."
            )
        else:
            return (
                "password-encryption enable\nsave",
                "Enforces obfuscation or cryptographic hashing of stored credentials."
            )
            
    return ("# Apply hardening according to corporate policy", "Review vendor documentation.")

def evaluate_compliance(csm: CommonSecurityModel, selected_frameworks: List[str] = None) -> AuditResult:
    """Evaluates the normalized Common Security Model against industry frameworks."""
    if not selected_frameworks:
        selected_frameworks = ["CIS", "NIST", "DISA_STIG", "ISO_27001"]
        
    findings: List[ComplianceFinding] = []
    
    # -------------------------------------------------------------
    # 1. CIS BENCHMARKS EVALUATION
    # -------------------------------------------------------------
    if "CIS" in selected_frameworks:
        # CIS 2.1.1: Telnet Disabled
        status = "PASS" if csm.telnet_disabled else "FAIL"
        ev = csm.evidence_map.get("telnet_disabled", {})
        rem_cmd, rem_exp = get_device_remediation(csm.vendor, "telnet")
        findings.append(ComplianceFinding(
            id="CIS-2.1.1",
            framework="CIS Benchmarks v2.0",
            control_id="CIS 2.1.1",
            title="Ensure Insecure Telnet Service Is Disabled",
            description="Telnet transmits authentication credentials and management commands in cleartext, exposing the device to credential sniffing.",
            severity="CRITICAL",
            status=status,
            evidence_line=ev.get("line"),
            evidence_text=ev.get("text", "line vty / transport input not hardened"),
            why_it_matters="Cleartext administrative traffic allows malicious actors on the local network or transit path to capture passwords and hijack sessions.",
            remediation_cmd=rem_cmd,
            remediation_explanation=rem_exp
        ))
        
        # CIS 2.1.2: SSH v2 Enforced
        status = "PASS" if (csm.ssh_version == 2) else "FAIL"
        ev = csm.evidence_map.get("ssh_version", {})
        rem_cmd, rem_exp = get_device_remediation(csm.vendor, "ssh_version")
        findings.append(ComplianceFinding(
            id="CIS-2.1.2",
            framework="CIS Benchmarks v2.0",
            control_id="CIS 2.1.2",
            title="Ensure SSH Version 2 Is Exclusively Configured",
            description="SSH Protocol Version 1 suffers from fundamental cryptographic weaknesses including vulnerability to insertion attacks.",
            severity="CRITICAL",
            status=status,
            evidence_line=ev.get("line"),
            evidence_text=ev.get("text", "ip ssh version missing or version 1"),
            why_it_matters="SSHv1 is susceptible to man-in-the-middle attacks and CRC32 compensation attacks.",
            remediation_cmd=rem_cmd,
            remediation_explanation=rem_exp
        ))
        
        # CIS 2.2.1: Executive Session Timeout
        valid_timeout = csm.inactivity_timeout_seconds is not None and 0 < csm.inactivity_timeout_seconds <= 600
        status = "PASS" if valid_timeout else "FAIL"
        ev = csm.evidence_map.get("inactivity_timeout_seconds", {})
        rem_cmd, rem_exp = get_device_remediation(csm.vendor, "timeout")
        findings.append(ComplianceFinding(
            id="CIS-2.2.1",
            framework="CIS Benchmarks v2.0",
            control_id="CIS 2.2.1",
            title="Enforce Inactivity Session Timeout Under 10 Minutes",
            description="All inactive interactive administrative terminal sessions must terminate within 10 minutes (600 seconds).",
            severity="HIGH",
            status=status,
            evidence_line=ev.get("line"),
            evidence_text=ev.get("text", f"Timeout set to: {csm.inactivity_timeout_seconds}s" if csm.inactivity_timeout_seconds else "No timeout configured"),
            why_it_matters="Unattended open terminal sessions provide unauthorized individuals immediate elevated access to network devices.",
            remediation_cmd=rem_cmd,
            remediation_explanation=rem_exp
        ))
        
        # CIS 2.3.1: SNMP Insecure Community
        status = "FAIL" if csm.insecure_community_detected else "PASS"
        ev = csm.evidence_map.get("snmp_community", {})
        rem_cmd, rem_exp = get_device_remediation(csm.vendor, "snmp")
        findings.append(ComplianceFinding(
            id="CIS-2.3.1",
            framework="CIS Benchmarks v2.0",
            control_id="CIS 2.3.1",
            title="Prohibit Default Public/Private SNMP Community Strings",
            description="Default community strings such as 'public' or 'private' allow trivial reconnaissance and configuration tampering.",
            severity="CRITICAL",
            status=status,
            evidence_line=ev.get("line"),
            evidence_text=ev.get("text", f"Detected: {', '.join(csm.detected_communities)}" if csm.detected_communities else "No default strings"),
            why_it_matters="Attackers can leverage known SNMP community strings to dump routing tables, interface addresses, and internal network architecture.",
            remediation_cmd=rem_cmd,
            remediation_explanation=rem_exp
        ))
        
        # CIS 2.4.1: Login Banner
        status = "PASS" if csm.login_banner_configured else "FAIL"
        ev = csm.evidence_map.get("login_banner_configured", {})
        rem_cmd, rem_exp = get_device_remediation(csm.vendor, "banner")
        findings.append(ComplianceFinding(
            id="CIS-2.4.1",
            framework="CIS Benchmarks v2.0",
            control_id="CIS 2.4.1",
            title="Configure Mandatory Pre-Login Warning Banner",
            description="Present a legal warning notice to users before logging in to warn against unauthorized access.",
            severity="MEDIUM",
            status=status,
            evidence_line=ev.get("line"),
            evidence_text=ev.get("text", "banner motd not configured"),
            why_it_matters="Required for legal prosecution of unauthorized intruders and explicit notification of surveillance.",
            remediation_cmd=rem_cmd,
            remediation_explanation=rem_exp
        ))

    # -------------------------------------------------------------
    # 2. NIST CSF 2.0 / SP 800-53 EVALUATION
    # -------------------------------------------------------------
    if "NIST" in selected_frameworks:
        # NIST PR.AC-3: Insecure Protocol
        status = "PASS" if csm.telnet_disabled else "FAIL"
        ev = csm.evidence_map.get("telnet_disabled", {})
        rem_cmd, rem_exp = get_device_remediation(csm.vendor, "telnet")
        findings.append(ComplianceFinding(
            id="NIST-PR.AC-3",
            framework="NIST CSF 2.0",
            control_id="PR.AC-3",
            title="Remote Access Insecure Channels Restricted",
            description="Remote administrative connections must enforce mutual integrity and encryption.",
            severity="HIGH",
            status=status,
            evidence_line=ev.get("line"),
            evidence_text=ev.get("text", "Insecure access channels open"),
            why_it_matters="NIST mandates confidentiality and integrity of all administrative management sessions.",
            remediation_cmd=rem_cmd,
            remediation_explanation=rem_exp
        ))
        
        # NIST DE.CM-1 / AU-4: Audit Logging
        status = "PASS" if (csm.logging_enabled and len(csm.syslog_servers) > 0) else "FAIL"
        ev = csm.evidence_map.get("logging_enabled", {})
        rem_cmd, rem_exp = get_device_remediation(csm.vendor, "logging")
        findings.append(ComplianceFinding(
            id="NIST-DE.CM-1",
            framework="NIST CSF 2.0",
            control_id="DE.CM-1",
            title="Centralized Security Audit Logging Enabled",
            description="Security-relevant device events must be systematically forwarded to centralized analysis repositories.",
            severity="HIGH",
            status=status,
            evidence_line=ev.get("line"),
            evidence_text=ev.get("text", f"Syslog targets: {', '.join(csm.syslog_servers)}" if csm.syslog_servers else "No remote syslog host"),
            why_it_matters="Local logs can be wiped by intruders; centralized SIEM logging ensures tamper-resistant audit trails.",
            remediation_cmd=rem_cmd,
            remediation_explanation=rem_exp
        ))
        
        # NIST PR.DS-1: Clock Synchronization
        status = "PASS" if csm.ntp_configured else "FAIL"
        ev = csm.evidence_map.get("ntp_configured", {})
        rem_cmd, rem_exp = get_device_remediation(csm.vendor, "ntp")
        findings.append(ComplianceFinding(
            id="NIST-PR.DS-1",
            framework="NIST CSF 2.0",
            control_id="PR.DS-1",
            title="Cryptographic Time Synchronization (NTP)",
            description="System clocks must be synchronized using authorized authoritative NTP time sources.",
            severity="MEDIUM",
            status=status,
            evidence_line=ev.get("line"),
            evidence_text=ev.get("text", f"NTP servers: {', '.join(csm.ntp_servers)}" if csm.ntp_servers else "NTP unconfigured"),
            why_it_matters="Without synchronized clocks, incident timeline reconstruction across multi-vendor fleets is impossible.",
            remediation_cmd=rem_cmd,
            remediation_explanation=rem_exp
        ))

    # -------------------------------------------------------------
    # 3. DISA STIGs EVALUATION
    # -------------------------------------------------------------
    if "DISA_STIG" in selected_frameworks:
        # STIG NET-00012: Approved Ciphers
        status = "PASS" if (csm.ssh_version == 2) else "FAIL"
        ev = csm.evidence_map.get("ssh_version", {})
        rem_cmd, rem_exp = get_device_remediation(csm.vendor, "ssh_version")
        findings.append(ComplianceFinding(
            id="STIG-NET-00012",
            framework="DISA STIGs",
            control_id="NET-00012",
            title="DoD Military FIPS Cryptographic Protocol Enforcement",
            description="The network device must only permit FIPS-validated cryptographic algorithms for remote administration.",
            severity="CRITICAL",
            status=status,
            evidence_line=ev.get("line"),
            evidence_text=ev.get("text", "Non-FIPS compliant protocol allowed"),
            why_it_matters="DoD networks require absolute encryption assurances against nation-state cryptographic attacks.",
            remediation_cmd=rem_cmd,
            remediation_explanation=rem_exp
        ))
        
        # STIG NET-00109: Admin Inactivity Timeout
        status = "PASS" if valid_timeout else "FAIL"
        ev = csm.evidence_map.get("inactivity_timeout_seconds", {})
        rem_cmd, rem_exp = get_device_remediation(csm.vendor, "timeout")
        findings.append(ComplianceFinding(
            id="STIG-NET-00109",
            framework="DISA STIGs",
            control_id="NET-00109",
            title="Administrative Terminal Inactivity Disconnection",
            description="Administrative sessions must be automatically terminated after a maximum of 10 minutes of inactivity.",
            severity="HIGH",
            status=status,
            evidence_line=ev.get("line"),
            evidence_text=ev.get("text", f"Timeout: {csm.inactivity_timeout_seconds}s" if csm.inactivity_timeout_seconds else "Missing"),
            why_it_matters="Precludes physical console or remote terminal hijacking if operator leaves terminal unattended.",
            remediation_cmd=rem_cmd,
            remediation_explanation=rem_exp
        ))

    # -------------------------------------------------------------
    # 4. ISO/IEC 27001 EVALUATION
    # -------------------------------------------------------------
    if "ISO_27001" in selected_frameworks:
        # ISO A.8.20: Network Security Controls
        status = "PASS" if (csm.telnet_disabled and csm.ssh_version == 2) else "FAIL"
        rem_cmd, rem_exp = get_device_remediation(csm.vendor, "telnet")
        findings.append(ComplianceFinding(
            id="ISO-A.8.20",
            framework="ISO/IEC 27001",
            control_id="A.8.20",
            title="Network Management Channel Protection",
            description="Networks must be secured, managed, and controlled to protect information in systems and applications.",
            severity="HIGH",
            status=status,
            evidence_line=csm.evidence_map.get("telnet_disabled", {}).get("line"),
            evidence_text="Insecure transport detected on line vty" if not csm.telnet_disabled else "Protected encrypted transport",
            why_it_matters="Mandatory international baseline for maintaining confidentiality of management traffic.",
            remediation_cmd=rem_cmd,
            remediation_explanation=rem_exp
        ))
        
        # ISO A.8.15: Logging & Monitoring
        status = "PASS" if csm.logging_enabled else "FAIL"
        ev = csm.evidence_map.get("logging_enabled", {})
        rem_cmd, rem_exp = get_device_remediation(csm.vendor, "logging")
        findings.append(ComplianceFinding(
            id="ISO-A.8.15",
            framework="ISO/IEC 27001",
            control_id="A.8.15",
            title="Logging of Security Events & Anomalies",
            description="Logs that record activities, exceptions, faults, and other relevant events must be produced and stored.",
            severity="MEDIUM",
            status=status,
            evidence_line=ev.get("line"),
            evidence_text=ev.get("text", "No remote logging configured"),
            why_it_matters="Essential for forensics and compliance audit certifications.",
            remediation_cmd=rem_cmd,
            remediation_explanation=rem_exp
        ))

    # Calculate Framework-wise and Overall Scores
    framework_scores = []
    total_all = len(findings)
    passed_all = sum(1 for f in findings if f.status == "PASS")
    
    unique_fws = set(f.framework for f in findings)
    for fw in sorted(list(unique_fws)):
        fw_findings = [f for f in findings if f.framework == fw]
        tot = len(fw_findings)
        pas = sum(1 for f in fw_findings if f.status == "PASS")
        score = round((pas / tot * 100), 1) if tot > 0 else 100.0
        
        framework_scores.append(FrameworkScore(
            framework=fw,
            score_percentage=score,
            total_controls=tot,
            passed_controls=pas,
            failed_controls=tot - pas,
            critical_findings=sum(1 for f in fw_findings if f.severity == "CRITICAL" and f.status != "PASS"),
            high_findings=sum(1 for f in fw_findings if f.severity == "HIGH" and f.status != "PASS"),
            medium_findings=sum(1 for f in fw_findings if f.severity == "MEDIUM" and f.status != "PASS"),
            low_findings=sum(1 for f in fw_findings if f.severity == "LOW" and f.status != "PASS")
        ))
        
    overall_score = round((passed_all / total_all * 100), 1) if total_all > 0 else 100.0
    
    device_info = {
        "hostname": csm.hostname,
        "vendor": csm.vendor,
        "model": csm.model,
        "os_version": csm.os_version,
        "serial_number": csm.serial_number
    }
    
    return AuditResult(
        device_info=device_info,
        overall_compliance_score=overall_score,
        framework_scores=framework_scores,
        findings=findings,
        csm=csm,
        unrecognized_gaps=csm.unrecognized_commands
    )
