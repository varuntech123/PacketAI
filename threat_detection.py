import re

def detect_threat(source_ip, dest_ip, protocol, length, info):
    """SIEM-grade heuristic threat detection."""
    threats = []
    severity = "low"
    
    # Rule 1: Cleartext Protocols (Insecure)
    insecure_protos = ['HTTP', 'FTP', 'TELNET', 'SMTP']
    if any(p in protocol.upper() for p in insecure_protos):
        threats.append(f"Insecure cleartext protocol: {protocol}")
        severity = "medium"

    # Rule 2: Anomalous Packet Length (Potential Data Exfiltration or Buffer Overflow)
    if length > 1460: # Typical MTU limit for common TCP segments
        threats.append("Anomalous packet length (Potential tunneling/exfiltration)")
        severity = "medium"
    
    # Rule 3: Potential SQL Injection / Command Injection in Info
    sqli_patterns = [r"SELECT", r"UNION", r"INSERT", r"DROP", r"--", r"1=1"]
    if any(re.search(p, info, re.IGNORECASE) for p in sqli_patterns):
        threats.append("Potential SQL Injection pattern detected in payload")
        severity = "high"

    # Rule 4: Suspicious Scan / Reconnaissance
    if "SYN" in info and "ACK" not in info:
        threats.append("TCP SYN Scan detected (Reconnaissance)")
        severity = "medium"

    is_threat = len(threats) > 0
    summary = "; ".join(threats) if is_threat else "Clean"
    
    return is_threat, severity, summary