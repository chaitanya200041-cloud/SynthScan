from engine.port_scanner import scan_ports
from engine.dir_scanner import scan_directories
from engine.subdomain_scanner import scan_subdomains
from engine.xss_scanner import scan_xss
from engine.sql_scanner import scan_sql_injection
from engine.header_scanner import scan_security_headers
from engine.technology_scanner import detect_technology
from engine.robots_scanner import scan_robots

from utils.severity_score import calculate_severity
from utils.report_generator import generate_report

from ai.ai_analysis import ai_security_analysis
from ai.ai_fix_generator import generate_fixes


def main():

    print("\n===================================")
    print("        AI Powered WAPT Scanner")
    print("===================================\n")

    target = input("Enter target domain (example.com): ")

    # ---------------------------
    # PORT SCAN
    # ---------------------------
    print("\n[+] Scanning Ports...\n")

    ports = scan_ports(target)

    if ports:
        print("Open Ports Found:")
        for p in ports:
            print(f"  - {p}")
    else:
        print("No common open ports found.")

    # ---------------------------
    # DIRECTORY SCAN
    # ---------------------------
    print("\n[+] Scanning Directories...\n")

    dirs = scan_directories(target, "wordlists/directories.txt")

    if dirs:
        print("Discovered Directories:")
        for d in dirs:
            print(f"  - {d}")
    else:
        print("No directories discovered.")

    # ---------------------------
    # SUBDOMAIN SCAN
    # ---------------------------
    print("\n[+] Scanning Subdomains...\n")

    subs = scan_subdomains(target, "wordlists/subdomains.txt")

    if subs:
        print("Discovered Subdomains:")
        for s in subs:
            print(f"  - {s}")
    else:
        print("No subdomains discovered.")

    # ---------------------------
    # XSS SCAN
    # ---------------------------
    print("\n[+] Testing for XSS Vulnerability...\n")

    xss = scan_xss(target)

    if xss:
        print("⚠ Possible XSS vulnerability detected!")
    else:
        print("No XSS vulnerability detected.")

    # ---------------------------
    # SQL INJECTION SCAN
    # ---------------------------
    print("\n[+] Testing for SQL Injection...\n")

    sql = scan_sql_injection(target)

    if sql:
        print("⚠ Possible SQL Injection vulnerability detected!")
    else:
        print("No SQL Injection vulnerability detected.")

    # ---------------------------
    # SECURITY HEADER ANALYSIS
    # ---------------------------
    print("\n[+] Analyzing Security Headers...\n")

    missing = scan_security_headers(target)

    if missing:
        print("Missing Security Headers:")
        for h in missing:
            print(f"  - {h}")
    else:
        print("All important security headers are present.")

    # ---------------------------
    # TECHNOLOGY DETECTION
    # ---------------------------
    print("\n[+] Detecting Web Technologies...\n")

    tech = detect_technology(target)

    if tech:
        print("Technologies Detected:")
        for t in tech:
            print(f"  - {t}")
    else:
        print("No technologies detected.")

    # ---------------------------
    # ROBOTS.TXT ANALYSIS
    # ---------------------------
    print("\n[+] Analyzing robots.txt...\n")

    robots = scan_robots(target)

    if robots:
        print("Disallowed Paths Found:")
        for r in robots:
            print(f"  - {r}")
    else:
        print("No disallowed paths found in robots.txt.")

    # ---------------------------
    # SEVERITY SCORING
    # ---------------------------
    print("\n[+] Calculating Risk Score...\n")

    score, level = calculate_severity(xss, sql, missing, ports)

    print(f"Risk Score: {score} / 10")
    print(f"Severity Level: {level}")

    # ---------------------------
    # PREPARE RESULTS FOR AI
    # ---------------------------
    results = f"""
Open Ports: {ports}
Directories: {dirs}
Subdomains: {subs}
XSS: {xss}
SQL Injection: {sql}
Missing Headers: {missing}
Technologies: {tech}
Robots Paths: {robots}
Risk Score: {score}
Severity: {level}
"""

    # ---------------------------
    # AI SECURITY ANALYSIS
    # ---------------------------
    print("\n[+] Generating AI Security Analysis...\n")

    try:
        ai_report = ai_security_analysis(results)
        print(ai_report)
    except:
        print("AI analysis failed. Check API key.")

    # ---------------------------
    # AI FIX GENERATOR
    # ---------------------------
    print("\n[+] Generating AI Fix Recommendations...\n")

    try:
        fixes = generate_fixes(results)
        print(fixes)
    except:
        print("AI fix generation failed.")

    # ---------------------------
    # REPORT GENERATION
    # ---------------------------
    print("\n[+] Generating security report...\n")

    generate_report(
        target,
        ports,
        dirs,
        subs,
        xss,
        sql,
        missing,
        tech,
        robots,
        score,
        level
    )

    print("Report saved to reports/security_report.txt")

    print("\n===================================")
    print("           Scan Completed")
    print("===================================\n")


if __name__ == "__main__":
    main()