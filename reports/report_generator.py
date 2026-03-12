def generate_report(target, ports, dirs, subs, xss, sql, missing, tech, robots, score, level):

    report = f"""
===============================
       WAPT Security Report
===============================

Target: {target}

Open Ports:
{ports}

Directories:
{dirs}

Subdomains:
{subs}

XSS Vulnerability:
{xss}

SQL Injection:
{sql}

Missing Security Headers:
{missing}

Technologies Detected:
{tech}

Robots.txt Paths:
{robots}

Risk Score: {score}
Severity Level: {level}

===============================
"""

    with open("reports/security_report.txt", "w") as file:
        file.write(report)