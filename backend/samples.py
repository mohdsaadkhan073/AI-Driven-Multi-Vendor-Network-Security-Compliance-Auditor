"""Production-realistic multi-vendor configuration files for live demo benchmarking."""

CISCO_SAMPLE = """! Cisco IOS-XE Software, Catalyst L3 Switch
! Version 17.6.3a, RELEASE SOFTWARE (fc1)
hostname Core-Edge-Switch-01
!
no service password-encryption
!
enable secret 9 $9$vW8d$K7/O29348924089248209
!
aaa new-model
!
ip ssh version 1
no ip http server
ip http secure-server
!
banner motd ^C
======================================================
WARNING: Unauthorized access prohibited! All logged.
======================================================
^C
!
snmp-server community public RO
snmp-server location DataCenter-Rack-04
!
ntp server 10.0.0.1
!
line con 0
 exec-timeout 0 0
 stopbits 2
line vty 0 4
 transport input telnet ssh
 exec-timeout 0 0
 login local
line vty 5 15
 transport input telnet ssh
 exec-timeout 0 0
!
end
"""

JUNIPER_SAMPLE = """## Junos OS 21.4R1.12 Hierarchical Configuration
system {
    host-name JunOS-Edge-SRX;
    services {
        ssh {
            protocol-version v1;
        }
        telnet;
        web-management {
            https {
                system-generated-certificate;
            }
        }
    }
    syslog {
        host 10.10.10.50 {
            any any;
        }
    }
    ntp {
        server 10.0.0.1;
    }
}
snmp {
    community public {
        authorization read-only;
    }
}
"""

FORTINET_SAMPLE = """# FortiOS v7.2.4 Configuration File
config system global
    set hostname "FortiGate-Core-FW"
    set admintimeout 0
    set timezone 55
end
config system admin setting
    set admin-telnet enable
    set admin-ssh enable
    set admin-ssh-port 22
end
config log syslogd setting
    set status enable
    set server "10.10.10.50"
end
config system snmp community
    edit 1
        set name "public"
        config hosts
            edit 1
                set ip 10.0.0.0 255.255.255.0
            next
        end
    next
end
"""

PALOALTO_SAMPLE = """set deviceconfig system hostname PA-Edge-Firewall
set deviceconfig system idle-timeout 0
set deviceconfig system service disable-telnet no
set deviceconfig system service ssh yes
set deviceconfig system timezone UTC
set shared log-settings syslog Central-SIEM server 10.10.10.50
set deviceconfig system ntp-servers primary 10.0.0.1
"""

WHITEBOX_SAMPLE = """# Open WhiteBox SONiC Switch Configuration (Custom Firmware v4.9)
device-id WhiteBox-Leaf-01
management-insecure-cli-port 23
session-idle-limit 300
syslog-export-ip 10.10.10.50
telemetry-sync-source 10.0.0.1
crypto-auth-enforce enable
"""

SAMPLES = {
    "cisco": {
        "id": "cisco",
        "name": "Cisco Catalyst 2960 / 9300 (IOS-XE)",
        "vendor": "Cisco",
        "config": CISCO_SAMPLE,
        "description": "Enterprise switch with vulnerable Telnet, SSHv1 fallback, exec-timeout disabled, and default SNMP 'public' community."
    },
    "juniper": {
        "id": "juniper",
        "name": "Juniper SRX / EX Series (Junos OS)",
        "vendor": "Juniper",
        "config": JUNIPER_SAMPLE,
        "description": "Junos router with active Telnet daemon, SSH protocol v1, and default SNMP community strings."
    },
    "fortinet": {
        "id": "fortinet",
        "name": "Fortinet FortiGate 60F (FortiOS)",
        "vendor": "Fortinet",
        "config": FORTINET_SAMPLE,
        "description": "Next-Gen Firewall with admin-telnet enabled, admintimeout set to 0 (never timeout), and public community."
    },
    "paloalto": {
        "id": "paloalto",
        "name": "Palo Alto PA-440 (PAN-OS)",
        "vendor": "Palo Alto",
        "config": PALOALTO_SAMPLE,
        "description": "PAN-OS firewall set-syntax with unhardened idle-timeout and telnet allowed."
    },
    "whitebox": {
        "id": "whitebox",
        "name": "Whitebox SONiC Switch (Adaptive Demo ⭐)",
        "vendor": "Whitebox / SONiC",
        "config": WHITEBOX_SAMPLE,
        "description": "Modern disaggregated whitebox hardware with novel, uncatalogued syntax designed to test the Adaptive Training Loop."
    }
}
