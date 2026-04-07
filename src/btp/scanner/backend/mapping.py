# mapping.py
# service -> attack mapping and vulnerability normalization helpers

ALIASES = {
    # common service aliases to normalized vulnerability keys
    "msrpc": "microsoft windows rpc",
    "ms-wbt-server": "ms-wbt-server",
    "ms-wbt": "ms-wbt-server",
    "microsoft-ds": "microsoft-ds",
    "netbios-ssn": "netbios-ssn",
    "netbios-ns": "netbios-ns",
    "kestrel": "microsoft kestrel httpd",
    "tornado": "tornado httpd",
    "vmware-auth": "vmware authentication daemon",
    "vmware authentication daemon": "vmware authentication daemon",
    "pando-pub": "pando-pub",
    "ici": "ici",
    "ethernetip-1": "ethernetip-1",
    "msrpc": "microsoft windows rpc",
}

# Rough mapping service substring -> Attack_Type
SERVICE_MAPPING = {
    # Web
    "http": "Web Exploit",
    "https": "Web Exploit",
    "apache": "Web Exploit",
    "nginx": "Web Exploit",
    "tomcat": "Web Exploit",
    "iis": "Web Exploit",
    "ajp": "Web Exploit",
    "tornado": "Web Exploit",
    "kestrel": "Web Exploit",

    # Remote / access
    "ssh": "SSH Brute Force",
    "rdp": "Remote Access Abuse",
    "ms-wbt-server": "Remote Access Abuse",
    "telnet": "Credential Sniffing",
    "vnc": "Remote Access Abuse",

    # Lateral movement / files
    "smb": "Lateral Movement",
    "microsoft-ds": "Lateral Movement",
    "netbios": "Lateral Movement",
    "rpc": "Privilege Escalation",
    "msrpc": "Privilege Escalation",

    # DB
    "mysql": "Database Attack",
    "postgres": "Database Attack",
    "mssql": "Database Attack",
    "mongo": "Database Attack",
    "redis": "Database Attack",

    # Mail
    "smtp": "Email Service",
    "imap": "Credential Attack",
    "pop3": "Credential Attack",

    # Infra / misc
    "dns": "DNS Abuse",
    "snmp": "Information Disclosure",
    "ldap": "Directory Attack",
    "kerberos": "Credential Attack",

    # Other
    "docker": "Container Escape",
    "kubernetes": "Cluster Attack",
    "vmware": "Privilege Escalation",
    "rmi": "RCE Exploit",
    "distccd": "RCE Exploit",
    "irc": "Botnet Channel",
    "pando-pub": "Unknown",
    "ici": "Unknown",
    "ethernetip-1": "Remote Access Abuse",
}

def service_to_attack(service_name):
    if not service_name:
        return "Unknown"
    s = service_name.lower().strip()
    # substring matching
    for key, attack in SERVICE_MAPPING.items():
        if key in s:
            return attack
    return "Unknown"

def normalize_vuln(name):
    """
    Normalize a product/service name to a stable vulnerability key used for
    joining with remediation_tools.csv
    """
    if not name:
        return ""
    s = name.lower().strip()

    # exact aliases
    if s in ALIASES:
        return ALIASES[s]

    # substring rules for common vendor strings
    if "kestrel" in s:
        return "microsoft kestrel httpd"
    if "tornado" in s:
        return "tornado httpd"
    if "apache" in s:
        return "apache"
    if "nginx" in s:
        return "nginx"
    if "mysql" in s:
        return "mysql"
    if "microsoft windows rpc" in s or s.startswith("msrpc"):
        return "microsoft windows rpc"

    # fallback to raw lowercased token
    return s
