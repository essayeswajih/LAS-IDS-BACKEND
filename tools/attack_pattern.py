import re

import re

access_attack_patterns = {
    "SQL Injection": {
        "pattern": re.compile(
            r"""(
                (?:'|")?\s*(?:or|and)\s+['"0-9]+\s*=\s*['"0-9]+  # ' or '1'='1
                |union(?:\s|%20|\+|\*)*select\s+[\w\*\s,]+(?:--)?  # UNION SELECT null--
                |select\s+[\w\*\s,]+\s+from\s+[\w\.]+            # SELECT * FROM
                |insert\s+into\s+\w+\s*\(.*?\)\s*values\s*\(.*?\)  # INSERT INTO ... VALUES
                |drop\s+table\s+\w+                              # DROP TABLE
                |update\s+\w+\s+set\s+\w+\s*=\s*.+               # UPDATE ... SET
                |delete\s+from\s+\w+                             # DELETE FROM
                |(?:--|#|/\*.*?\*/)\s*                           # SQL comments: --, #, /*
                |(?:char|concat|load_file|benchmark|sleep)\([^\)]*\)  # char(), sleep()
                |0x[0-9A-Fa-f]{6,}                               # 0xabcdef
                |information_schema|mysql\.user|pg_catalog\.pg_user  # DB tables
                |'\s*--\s*                                       # '--
            )""",
            re.IGNORECASE
        ),
        "severity": 5
    },
    "XSS Attack": {
        "pattern": re.compile(
            r"""(
                <script.*?>                                     # <script> tags
                |javascript:                                    # javascript: URLs
                |document\.cookie                               # document.cookie
                |on[a-z]+\s*=\s*['"][^'"]+['"]                  # on* event handlers
                |alert\(|confirm\(|prompt\(|eval\(|execScript\(  # alert(), eval()
                |<svg.*?>                                       # <svg> tags
                |<img\s+[^>]*src\s*=\s*['"]?[^'"]*onerror\s*=   # <img src=x onerror=>
                |window\.location\s*=                           # window.location
            )""",
            re.IGNORECASE
        ),
        "severity": 3
    },
    "Directory Traversal": {
        "pattern": re.compile(
            r"""(
                \.\./|\.\.\\|\.\.\/|\.\.\\                      # ../ or ..\
                |%2e%2e[/\\]                                   # URL-encoded ../ or ..\
                |/etc/passwd|/etc/shadow|/proc/self/environ|boot.ini  # Sensitive files
            )""",
            re.IGNORECASE
        ),
        "severity": 4
    },
    "Command Injection": {
        "pattern": re.compile(
            r"(?:;\s*(?:rm|ls|cat|whoami|uname|wget|curl|python|perl|bash|sh|nc|powershell|cmd|echo)\b|"
            r"\|\|\s*(?:rm|ls|cat|whoami|uname|wget|curl|python|perl|bash|sh|nc|powershell|cmd|echo)\b|"
            r"&&\s*(?:rm|ls|cat|whoami|uname|wget|curl|python|perl|bash|sh|nc|powershell|cmd|echo)\b|"
            r"`(?:rm|ls|cat|whoami|uname|wget|curl|python|perl|bash|sh|nc|powershell|cmd|echo)`|"
            r"exec\(|system\(|popen\(|shell_exec\(|bash\s+-c|sh\s+-c|powershell\s+-c|cmd\.exe|nc\s+-e)",
            re.IGNORECASE
        ),
        "severity": 5
    },
    "LFI/RFI": {
        "pattern": re.compile(
            r"""(
                \.\./|\.\.\\                                   # ../ or ..\
                |%2e%2e[/\\]                                   # URL-encoded ../ or ..\
                |/etc/passwd|/etc/shadow|/proc/self/environ|boot.ini  # Sensitive files
                |.git/config|.env|phpinfo.php|.*\.bak           # Common webapp files
                |php://|data://|file://|expect://              # Dangerous protocols
                |(?:[?&](file|include|path|page|redirect)=)?(?:http://|https://)[^\s]*  # RFI: http://evil.com
                |169\.254\.169\.254                            # Metadata service
            )""",
            re.IGNORECASE
        ),
        "severity": 4
    },
    "Unusual HTTP Methods": {
        "pattern": re.compile(r"\b(CONNECT|TRACE|TRACK|OPTIONS|DEBUG|MOVE|COPY)\b", re.IGNORECASE),
        "severity": 2
    },
    "Automated Scanning": {
        "pattern": re.compile(
            r"(nikto|sqlmap|wvs|acunetix|dirb|nmap|zgrab|masscan|hydra|burp|python-requests|libwww-perl|httperf|w3af)",
            re.IGNORECASE
        ),
        "severity": 3
    },
    "Encoded Payloads": {
        "pattern": re.compile(
            r"""(
                (?:%[0-9A-Fa-f]{2}){6,}                      # 6+ URL-encoded chars
                |\b(?:[A-Za-z0-9+/]{40,}={0,2})\b            # Long base64 strings
                |0x[0-9A-Fa-f]{6,}                            # Hex payload: 0xabcdef
                |(?:char|unhex)\([0-9A-Fa-f]{4,}\)            # char(113), unhex('abcd')
                |(?:\\x[0-9A-Fa-f]{2})+
            )""",
            re.IGNORECASE
        ),
        "severity": 3
    },
    "DoS Attack": {
        "pattern": re.compile(
            r"""(
                \bGET\s+[^\s]+\s+HTTP/\d\.\d\s*$              # Incomplete GET
                |\bPOST\s+[^\s]+\s+HTTP/\d\.\d\s+Content-Length:\s*0  # Zero-length POST
                |\bHTTP/\d\.\d\s+[0-9]{3}\s+[-]{0,10}$        # Malformed response
                |[?&][\w]+=[\w\s%]{500,}                      # Long query string (500+ chars)
            )""",
            re.IGNORECASE
        ),
        "severity": 4
    },
    "CMS Probes": {
        "pattern": re.compile(
            r"(wp-admin|admin\.php|install\.php|setup\.php|wp-login\.php|joomla\.php|drupal\.php)",
            re.IGNORECASE
        ),
        "severity": 3
    }
}

error_log_attack_patterns = {
    "SQL Injection": {
        "pattern": re.compile(
            r"(SQL|mysql|pdo|query|database).*?(error|exception|failed|or\s+\d+=\d+|union\s+select)",
            re.IGNORECASE
        ),
        "severity": 5
    },
    "Command Injection": {
        "pattern": re.compile(
            r"(exec|system|shell|cmd|bash|sh|powershell|wget|curl|nc|whoami|uname).*?(error|failed|exception|spawned)",
            re.IGNORECASE
        ),
        "severity": 5
    },
    "LFI/RFI": {
        "pattern": re.compile(
            r"(include|require|file|php://|data://|/etc/passwd|/proc/self/environ|windows/win.ini).*?(failed|error|not found)",
            re.IGNORECASE
        ),
        "severity": 4
    },
    "Segmentation Fault/Crash": {
        "pattern": re.compile(r"(segmentation fault|sigsegv|core dumped|crash)", re.IGNORECASE),
        "severity": 4
    },
    "PHP/Script Error": {
        "pattern": re.compile(
            r"(php|python|perl|ruby).*?(parse error|syntax error|fatal error|exception|traceback)",
            re.IGNORECASE
        ),
        "severity": 3
    },
    "Permission Denied": {
        "pattern": re.compile(r"(permission denied|access denied|forbidden)", re.IGNORECASE),
        "severity": 2
    },
    "Suspicious Module Activity": {
        "pattern": re.compile(r"(mod_security|mod_rewrite|mod_php).*?(triggered|blocked|error)", re.IGNORECASE),
        "severity": 3
    },
    "Encoded Payloads": {
        "pattern": re.compile(
            r"(?:%[0-9A-Fa-f]{2}){6,}|\b(?:[A-Za-z0-9+/]{30,}={0,2})\b|0x[0-9A-Fa-f]{8,}",
            re.IGNORECASE
        ),
        "severity": 3
    }
}
syslog_attack_patterns = {
    "Authentication Failure": {
        "pattern": re.compile(
            r"(failed|invalid|authentication|login|password).*?(attempt|error|fail|denied)",
            re.IGNORECASE
        ),
        "severity": 3
    },
    "Privilege Escalation": {
        "pattern": re.compile(
            r"(sudo|root|admin|privilege|escalation).*?(attempt|success|fail|error)",
            re.IGNORECASE
        ),
        "severity": 4
    },
    "Command Injection": {
        "pattern": re.compile(
            r"(exec|system|bash|sh|cmd|powershell|wget|curl|nc|whoami|uname).*?(executed|spawned|error|failed)",
            re.IGNORECASE
        ),
        "severity": 5
    },
    "Service Crash": {
        "pattern": re.compile(
            r"(segfault|segmentation fault|core dumped|crash|terminated unexpectedly)",
            re.IGNORECASE
        ),
        "severity": 4
    },
    "Suspicious Process": {
        "pattern": re.compile(
            r"(python|perl|ruby|nc|netcat|bash|sh|wget|curl).*?(started|spawned|executed)",
            re.IGNORECASE
        ),
        "severity": 3
    },
    "File Access Violation": {
        "pattern": re.compile(
            r"(permission denied|access denied|forbidden|/etc/passwd|/etc/shadow|/root/)",
            re.IGNORECASE
        ),
        "severity": 3
    },
    "Network Anomaly": {
        "pattern": re.compile(
            r"(connection refused|timeout|dropped|unreachable|port scan|syn flood)",
            re.IGNORECASE
        ),
        "severity": 3
    },
    "Malware Indicators": {
        "pattern": re.compile(
            r"(malware|virus|trojan|backdoor|exploit|payload|botnet)",
            re.IGNORECASE
        ),
        "severity": 5
    },
    "Encoded Payloads": {
        "pattern": re.compile(
            r"(?:%[0-9A-Fa-f]{2}){6,}|\b(?:[A-Za-z0-9+/]{30,}={0,2})\b|0x[0-9A-Fa-f]{8,}",
            re.IGNORECASE
        ),
        "severity": 3
    }
}
windows_security_attack_patterns = {
    "Failed Logon (Event 4625)": {
        "pattern": re.compile(
            r"(logon failure|account.*failed to log on|4625)",
            re.IGNORECASE
        ),
        "event_id": 4625,
        "severity": 3
    },
    "Privilege Escalation (Event 4672/4673)": {
        "pattern": re.compile(
            r"(privilege|elevated|admin|4672|4673)",
            re.IGNORECASE
        ),
        "event_ids": {4672, 4673},
        "severity": 4
    },
    "Process Creation (Event 4688) - Suspicious": {
        "pattern": re.compile(
            r"(cmd\.exe|powershell\.exe|net\.exe|whoami|system32\\.*\.exe|4688).*?(new process|created)",
            re.IGNORECASE
        ),
        "event_id": 4688,
        "severity": 3
    },
    "Account Lockout (Event 4740)": {
        "pattern": re.compile(
            r"(account locked out|4740)",
            re.IGNORECASE
        ),
        "event_id": 4740,
        "severity": 3
    },
    "Security Policy Change (Event 4719/4739)": {
        "pattern": re.compile(
            r"(policy changed|audit policy|4719|4739)",
            re.IGNORECASE
        ),
        "event_ids": {4719, 4739},
        "severity": 4
    },
    "Malware Indicators": {
        "pattern": re.compile(
            r"(malware|virus|trojan|backdoor|exploit|ransomware|powershell.*encodedcommand)",
            re.IGNORECASE
        ),
        "severity": 5
    },
    "Network Connection (Event 5156) - Suspicious": {
        "pattern": re.compile(
            r"(connection.*(445|3389|23|21)|5156|unusual port)",
            re.IGNORECASE
        ),
        "event_id": 5156,
        "severity": 3
    },
    "Brute Force Attempt": {
        "pattern": re.compile(
            r"(multiple.*failed logon|excessive.*attempts)",
            re.IGNORECASE
        ),
        "severity": 4
    },
    "Encoded Payloads": {
        "pattern": re.compile(
            r"(?:[A-Za-z0-9+/]{30,}={0,2})|0x[0-9A-Fa-f]{8,}|base64",
            re.IGNORECASE
        ),
        "severity": 3
    }
}

generally_attack_patterns = {
    "SQL Injection": {
        "pattern": re.compile(
            r"""(
                (?:'|")?\s*(?:or|and)\s+\d+\s*=\s*\d+                           # ' or 1=1
                |union(?:\s|%20|/\*.*?\*/)*all(?:\s|%20|/\*.*?\*/)*select       # UNION ALL SELECT
                |select\s+[\w\*\s,]+\s+from                                     # SELECT * FROM
                |insert\s+into\s+\w+\s*\(.*?\)\s*values\s*\(.*?\)              # INSERT INTO (...) VALUES (...)
                |drop\s+table\s+\w+                                             # DROP TABLE
                |update\s+\w+\s+set\s+\w+\s*=\s*.+                              # UPDATE ... SET
                |delete\s+from\s+\w+                                            # DELETE FROM
                |(?:--|#|/\*.*?\*/)\s*$                                         # SQL comments
                |char\(\d+\)                                                   # char(113)
                |concat\([^)]+\)                                               # concat(...)
                |information_schema|mysql\.user|pg_catalog\.pg_user             # Common SQL targets
                |sleep\(\s*\d+\s*\)|benchmark\(\s*\d+,\s*[^)]+\)               # Time-based SQLi
            )""",
            re.IGNORECASE
        ),
        "severity": 5
    },
    "XSS Attack": {
        "pattern": re.compile(
            r"""(
                <script(?:\s|>).*?>|<\/script\s*>                              # <script> tags
                |javascript:[^\s]+                                             # javascript: URLs
                |document\.(cookie|location|write)                             # DOM manipulation
                |on(?:click|load|error|mouseover|submit)\s*=\s*['"]?.*?['"]?   # Event handlers
                |alert\s*\(|confirm\s*\(|prompt\s*\(                           # Common XSS payloads
                |eval\s*\(|setTimeout\s*\(|setInterval\s*\(                    # Dangerous JS functions
                |<img\s+src=["']?[^>]*onerror=["']?.*?["']?                    # onerror in img tags
                |(?:%3C|<)\s*(?:s|iframe|object|embed)\s*                      # Encoded HTML tags
            )""",
            re.IGNORECASE
        ),
        "severity": 4
    },
    "Other Injection Attempt": {
        "pattern": re.compile(
            r"(exec|system|cmd|powershell|bash|sh|os\..*?execute)",  # Focus on OS/command injection, excluding SQL/XSS
            re.IGNORECASE
        ),
        "severity": 5
    },
    "Authentication Failure": {
        "pattern": re.compile(
            r"(failed|invalid|denied|forbidden|locked out|authentication|login|password).*?(attempt|error|fail)",
            re.IGNORECASE
        ),
        "severity": 3
    },
    "Privilege Escalation": {
        "pattern": re.compile(
            r"(sudo|root|admin|privilege|escalation|elevated).*?(attempt|success|fail)",
            re.IGNORECASE
        ),
        "severity": 4
    },
    "Suspicious Process/Activity": {
        "pattern": re.compile(
            r"(cmd\.exe|powershell\.exe|bash|sh|python|perl|wget|curl|nc|netcat|whoami|uname).*?(started|executed|spawned)",
            re.IGNORECASE
        ),
        "severity": 3
    },
    "File Access Violation": {
        "pattern": re.compile(
            r"(permission denied|access denied|forbidden|/etc/passwd|/etc/shadow|windows\\system32)",
            re.IGNORECASE
        ),
        "severity": 3
    },
    "Network Anomaly": {
        "pattern": re.compile(
            r"(connection.*(refused|timeout|dropped|unreachable)|port scan|syn flood|unusual port)",
            re.IGNORECASE
        ),
        "severity": 3
    },
    "Malware Indicators": {
        "pattern": re.compile(
            r"(malware|virus|trojan|backdoor|exploit|ransomware|payload|botnet)",
            re.IGNORECASE
        ),
        "severity": 5
    },
    "Encoded Payloads": {
        "pattern": re.compile(
            r"(?:%[0-9A-Fa-f]{2}){6,}|\b(?:[A-Za-z0-9+/]{30,}={0,2})\b|0x[0-9A-Fa-f]{8,}",
            re.IGNORECASE
        ),
        "severity": 3
    },
    "Crash or Error": {
        "pattern": re.compile(
            r"(segfault|segmentation fault|core dumped|crash|fatal error|exception|terminated)",
            re.IGNORECASE
        ),
        "severity": 4
    },
    "Rate Limit Violation": {
        "pattern": re.compile(
            r"(multiple|excessive|rapid|repeated).*?(attempts|requests|logons)",
            re.IGNORECASE
        ),
        "severity": 4
    }
}