from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
import re
from typing import Dict, List
from schemas.rowDTO import RowDTO
from collections import defaultdict
from tools.attack_pattern import *


def apache_ids(rows: List[RowDTO]) -> List[Dict]:

    ip_alert_counter = defaultdict(int)
    ip_timestamps = defaultdict(list)  # For rate-limiting and DoS
    whitelist = {"127.0.0.1", "192.168.8.1"}
    suspicious_requests = []

    for row in rows:
        if row.ip in whitelist:
            continue

        # Parse timestamp for rate-limiting and DoS
        try:
            ts = datetime.strptime(row.timestamp[1:-1], "%d/%b/%Y:%H:%M:%S %z")
            ip_timestamps[row.ip].append(ts)
        except (ValueError, TypeError):
            ts = None

        detected_attacks = []
        severity_score = 0

        # Combine all possible fields to scan
        full_request = f"{row.url or ''} {row.request or ''} {row.user_agent or ''}"

        # Check all attack patterns
        for attack_type, details in access_attack_patterns.items():
            if attack_type == "Unusual HTTP Methods":
                if details["pattern"].search(row.method or ""):
                    detected_attacks.append(attack_type)
                    severity_score = max(severity_score, details["severity"])
            elif attack_type == "LFI/RFI":
                # Scope LFI/RFI to URL and request only
                if details["pattern"].search(f"{row.url or ''} {row.request or ''}"):
                    detected_attacks.append(attack_type)
                    severity_score = max(severity_score, details["severity"])
            elif attack_type == "DoS Attack":
                # Check full request for Slow DoS signatures
                if details["pattern"].search(row.request or row.url or ""):
                    detected_attacks.append("Slow DoS Attack")
                    severity_score = max(severity_score, details["severity"])
            else:
                # Other patterns check full request
                if details["pattern"].search(full_request):
                    detected_attacks.append(attack_type)
                    severity_score = max(severity_score, details["severity"])

        # Rate-limiting check (short-term, e.g., brute force)
        if ts and len(ip_timestamps[row.ip]) > 5:
            timestamps = sorted(ip_timestamps[row.ip])
            short_window = (timestamps[-1] - timestamps[0]).total_seconds()
            if short_window <= 10:  # More than 5 requests in 10 seconds
                detected_attacks.append("Rate Limit Violation (Possible Brute Force)")
                severity_score = max(severity_score, 3)

        # Volume-based DoS check (longer-term)
        if ts and len(ip_timestamps[row.ip]) > 50:
            timestamps = sorted(ip_timestamps[row.ip])
            dos_window = (timestamps[-1] - timestamps[0]).total_seconds()
            if dos_window <= 60:  # More than 50 requests in 60 seconds
                detected_attacks.append("Volume-Based DoS Attack")
                severity_score = max(severity_score, 4)

        if detected_attacks:
            ip_alert_counter[row.ip] += 1
            if ip_alert_counter[row.ip] > 5:
                detected_attacks.append("🚨 IP Suspecte (multiples attaques)")
                severity_score = max(severity_score, 5)

            suspicious_requests.append({
                "ip": row.ip,
                "timestamp": row.timestamp,
                "url": row.url,
                "method": row.method,
                "user_agent": row.user_agent or "Unknown",
                "detected_attacks": detected_attacks,
                "severity_score": severity_score,
                "severity_level": _determine_severity_level(severity_score),
                "alert_count": ip_alert_counter[row.ip]
            })

    if suspicious_requests:
        """
        for req in suspicious_requests:
            print(f"[{req['timestamp']}] 🚨 Suspicious activity from {req['ip']} on {req['url']} ({req['method']}):")
            print(f"   → User-Agent: {req['user_agent']}")
            print(f"   → Detected: {', '.join(req['detected_attacks'])}")
            print(f"   → Severity: {req['severity_level']} (Score: {req['severity_score']}, Alerts: {req['alert_count']})")
        """
        return suspicious_requests
    else:
        print("✅ No suspicious activity detected.")
        return []

def apache_error_ids(rows: List[RowDTO]) -> List[Dict]:
    ip_alert_counter = defaultdict(int)
    ip_timestamps = defaultdict(list)
    whitelist = {"127.0.0.1", "192.168.8.1"}
    suspicious_entries = []

    for row in rows:
        if row.ip in whitelist:
            continue

        # Parse timestamp
        ts = None
        if row.timestamp:
            try:
                # Adjust format based on your error log timestamp, e.g., "[Sun Apr 06 12:00:00.123456 2025]"
                ts = datetime.strptime(row.timestamp[1:-1], "%a %b %d %H:%M:%S.%f %Y")
                ip_timestamps[row.ip].append(ts)
            except (ValueError, TypeError):
                pass

        detected_attacks = []
        severity_score = 0

        # Combine fields to scan (focus on error log specifics)
        scan_content = " ".join(
            filter(None, [row.message, row.request, row.url, row.user_agent, row.referer])
        )

        # Check attack patterns
        for attack_type, details in error_log_attack_patterns.items():
            if details["pattern"].search(scan_content):
                detected_attacks.append(attack_type)
                severity_score = max(severity_score, details["severity"])

        # Rate-limiting check
        if ts and len(ip_timestamps[row.ip]) > 5:
            timestamps = sorted(ip_timestamps[row.ip])
            short_window = (timestamps[-1] - timestamps[0]).total_seconds()
            if short_window <= 10:
                detected_attacks.append("Rate Limit Violation")
                severity_score = max(severity_score, 3)

        if detected_attacks:
            ip_alert_counter[row.ip] += 1
            if ip_alert_counter[row.ip] > 5:
                detected_attacks.append("🚨 IP Suspect (Multiple Incidents)")
                severity_score = max(severity_score, 5)

            suspicious_entries.append({
                "ip": row.ip or "Unknown",
                "timestamp": row.timestamp,
                "message": row.message,
                "level": row.level,
                "module": row.module,
                "detected_attacks": detected_attacks,
                "severity_score": severity_score,
                "severity_level": _determine_severity_level(severity_score),
                "alert_count": ip_alert_counter[row.ip]
            })

    if suspicious_entries:

        return suspicious_entries
    else:
        print("✅ No suspicious activity detected in error logs.")
        return []
    
def _determine_severity_level(score: int) -> str:
    """
    Determines severity level based on score.

    Args:
        score: Integer severity score (1-5)

    Returns:
        String representation of severity level
    """
    if score >= 5:
        return "Critical"
    elif score == 4:
        return "High"
    elif score == 3:
        return "Medium"
    elif score == 2:
        return "Low"
    else:
        return "Info"
    

def syslog_ids(rows: List[RowDTO]) -> List[Dict]:
    ip_alert_counter = defaultdict(int)
    ip_timestamps = defaultdict(list)
    hostname_alert_counter = defaultdict(int)
    whitelist = {"127.0.0.1", "localhost"}
    suspicious_entries = []

    for row in rows:
        if row.ip in whitelist or row.hostname in whitelist:
            continue

        # Parse timestamp (adjust format as needed)
        ts = None
        if row.timestamp:
            try:
                # Syslog format: "Apr  6 12:00:00" (adjust for your data)
                # Assuming year is omitted, prepend current year for parsing
                current_year = datetime.now().year
                ts_str = row.timestamp.strip()
                if len(ts_str.split()) >= 3:  # Ensure enough parts
                    ts = datetime.strptime(f"{ts_str} {current_year}", "%b %d %H:%M:%S %Y")
                    ip_timestamps[row.ip or row.hostname or "unknown"].append(ts)
            except (ValueError, TypeError):
                pass

        detected_attacks = []
        severity_score = 0

        # Combine fields to scan
        scan_content = " ".join(
            filter(None, [row.message, row.request, row.user, row.hostname, row.component])
        )

        # Check attack patterns
        for attack_type, details in syslog_attack_patterns.items():
            if details["pattern"].search(scan_content):
                detected_attacks.append(attack_type)
                severity_score = max(severity_score, details["severity"])

        # Rate-limiting check (e.g., repeated failed logins)
        source_key = row.ip or row.hostname or "unknown"
        if ts and len(ip_timestamps[source_key]) > 5:
            timestamps = sorted(ip_timestamps[source_key])
            short_window = (timestamps[-1] - timestamps[0]).total_seconds()
            if short_window <= 10:
                detected_attacks.append("Rate Limit Violation (Possible Brute Force)")
                severity_score = max(severity_score, 3)

        if detected_attacks:
            ip_alert_counter[source_key] += 1
            hostname_alert_counter[row.hostname or "unknown"] += 1
            if ip_alert_counter[source_key] > 5 or hostname_alert_counter[row.hostname or "unknown"] > 5:
                detected_attacks.append("🚨 Source Suspect (Multiple Incidents)")
                severity_score = max(severity_score, 5)

            suspicious_entries.append({
                "ip": row.ip or "Unknown",
                "hostname": row.hostname or "Unknown",
                "timestamp": row.timestamp,
                "message": row.message,
                "user": row.user,
                "component": row.component,
                "detected_attacks": detected_attacks,
                "severity_score": severity_score,
                "severity_level": _determine_severity_level(severity_score),
                "alert_count": ip_alert_counter[source_key]
            })

    if suspicious_entries:
        """
        for entry in suspicious_entries:
            print(f"[{entry['timestamp']}] 🚨 Suspicious activity from {entry['ip']} ({entry['hostname']}):")
            print(f"   → Message: {entry['message']}")
            print(f"   → User: {entry['user']} | Component: {entry['component']}")
            print(f"   → Detected: {', '.join(entry['detected_attacks'])}")
            print(f"   → Severity: {entry['severity_level']} (Score: {entry['severity_score']}, Alerts: {entry['alert_count']})")
        """
        return suspicious_entries
    else:
        print("✅ No suspicious activity detected in syslog.")
        return []

def windows_security_ids(rows: List[RowDTO]) -> List[Dict]:
    source_alert_counter = defaultdict(int)
    source_timestamps = defaultdict(list)
    whitelist = {"127.0.0.1", "localhost"}
    suspicious_entries = []

    for row in rows:
        source_key = row.ip or row.computer_name or row.account_name or "unknown"
        if source_key in whitelist:
            continue

        # Parse timestamp
        ts = None
        if row.timestamp:
            try:
                # Windows timestamp example: "04/06/2025 12:00:00 PM"
                ts = datetime.strptime(row.timestamp, "%m/%d/%Y %I:%M:%S %p")
                source_timestamps[source_key].append(ts)
            except (ValueError, TypeError):
                pass

        detected_attacks = []
        severity_score = 0

        # Combine fields to scan
        scan_content = " ".join(
            filter(None, [row.message, row.account_name, row.provider_name, row.computer_name, row.task_display_name])
        )

        # Check attack patterns
        for attack_type, details in windows_security_attack_patterns.items():
            event_match = (
                ("event_id" in details and row.event_id == details["event_id"]) or
                ("event_ids" in details and row.event_id in details["event_ids"])
            )
            pattern_match = details["pattern"].search(scan_content)
            if pattern_match and (event_match or "event_id" not in details or "event_ids" not in details):
                detected_attacks.append(attack_type)
                severity_score = max(severity_score, details["severity"])

        # Rate-limiting check (e.g., brute force)
        if ts and len(source_timestamps[source_key]) > 5:
            timestamps = sorted(source_timestamps[source_key])
            short_window = (timestamps[-1] - timestamps[0]).total_seconds()
            if short_window <= 10:
                detected_attacks.append("Rate Limit Violation (Possible Brute Force)")
                severity_score = max(severity_score, 4)

        if detected_attacks:
            source_alert_counter[source_key] += 1
            if source_alert_counter[source_key] > 5:
                detected_attacks.append("🚨 Source Suspect (Multiple Incidents)")
                severity_score = max(severity_score, 5)

            suspicious_entries.append({
                "ip": row.ip or "Unknown",
                "computer_name": row.computer_name or "Unknown",
                "account_name": row.account_name or "Unknown",
                "timestamp": row.timestamp,
                "event_id": row.event_id,
                "message": row.message,
                "provider_name": row.provider_name,
                "detected_attacks": detected_attacks,
                "severity_score": severity_score,
                "severity_level": _determine_severity_level(severity_score),
                "alert_count": source_alert_counter[source_key]
            })

    if suspicious_entries:
        """
        for entry in suspicious_entries:
            print(f"[{entry['timestamp']}] 🚨 Suspicious activity from {entry['ip']} ({entry['computer_name']}):")
            print(f"   → Account: {entry['account_name']}")
            print(f"   → Event ID: {entry['event_id']} | Provider: {entry['provider_name']}")
            print(f"   → Message: {entry['message']}")
            print(f"   → Detected: {', '.join(entry['detected_attacks'])}")
            print(f"   → Severity: {entry['severity_level']} (Score: {entry['severity_score']}, Alerts: {entry['alert_count']})")
        """
        return suspicious_entries
    else:
        print("✅ No suspicious activity detected in Windows Security logs.")
        return []


# Assuming RowDTO and generally_attack_patterns are defined elsewhere
def general_ids(rows: List[RowDTO]) -> List[Dict]:
    source_alert_counter = defaultdict(int)
    source_timestamps = defaultdict(list)
    whitelist = {"127.0.0.1", "localhost"}
    suspicious_entries = []

    for row in rows:
        source_key = row.ip or row.hostname or row.computer_name or row.account_name or "unknown"
        if source_key in whitelist:
            continue

        # Parse timestamp with multiple format attempts
        ts = None
        if row.timestamp:
            timestamp_formats = [
                "%m/%d/%Y %I:%M:%S %p",  # Windows: 04/06/2025 12:00:00 PM
                "%b %d %H:%M:%S",        # Syslog: Apr  6 12:00:00
                "%Y-%m-%d %H:%M:%S",     # ISO: 2025-04-06 12:00:00
                "%d/%b/%Y:%H:%M:%S %z",  # Apache: 06/Apr/2025:12:00:00 +0000
                "%a %b %d %H:%M:%S.%f %Y"  # Apache error: Sun Apr 06 12:00:00.123456 2025
            ]
            for fmt in timestamp_formats:
                try:
                    ts_str = row.timestamp.strip("[]")
                    if fmt == "%b %d %H:%M:%S":
                        ts = datetime.strptime(f"{ts_str} {datetime.now().year}", "%b %d %H:%M:%S %Y")
                    else:
                        ts = datetime.strptime(ts_str, fmt)
                    source_timestamps[source_key].append(ts)
                    break
                except (ValueError, TypeError):
                    continue

        detected_attacks = []
        severity_score = 0

        # Combine all text fields for scanning
        scan_content = " ".join(
            filter(None, [
                row.message, row.request, row.url, row.user_agent, row.referer,
                row.user, row.account_name, row.computer_name, row.hostname,
                row.component, row.module, row.provider_name, row.task_display_name
            ])
        )

        # Check attack patterns
        for attack_type, details in generally_attack_patterns.items():
            if details["pattern"].search(scan_content):
                detected_attacks.append(attack_type)
                severity_score = max(severity_score, details["severity"])

        # Rate-limiting check
        if ts and len(source_timestamps[source_key]) > 5:
            timestamps = sorted(source_timestamps[source_key])
            short_window = (timestamps[-1] - timestamps[0]).total_seconds()
            if short_window <= 10:
                detected_attacks.append("Rate Limit Violation (Dynamic)")
                severity_score = max(severity_score, 4)

        if detected_attacks:
            source_alert_counter[source_key] += 1
            if source_alert_counter[source_key] > 5:
                detected_attacks.append("🚨 Source Suspect (Multiple Incidents)")
                severity_score = max(severity_score, 5)

            suspicious_entries.append({
                "ip": row.ip or source_key if source_key not in {"unknown"} else "Unknown",  # Map to expected 'ip'
                "url": getattr(row, "url", "N/A"),  # Default if not present
                "method": getattr(row, "method", "N/A"),  # Default if not present
                "timestamp": row.timestamp or "N/A",
                "message": row.message or "N/A",
                "event_id": getattr(row, "event_id", None),
                "user_info": row.user or row.account_name or "Unknown",
                "component": row.component or row.module or row.provider_name or "Unknown",
                "detected_attacks": detected_attacks,
                "severity_score": severity_score,
                "severity_level": _determine_severity_level(severity_score),
                "alert_count": source_alert_counter[source_key]
            })

    if suspicious_entries:
        return suspicious_entries
    else:
        print("✅ No suspicious activity detected.")
        return []