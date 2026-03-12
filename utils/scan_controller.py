from engine.port_scanner import scan_ports
from engine.dir_scanner import scan_directories
from engine.subdomain_scanner import scan_subdomains
from engine.xss_scanner import scan_xss
from engine.sql_scanner import scan_sql_injection
from engine.header_scanner import scan_security_headers
from engine.technology_scanner import detect_technology
from engine.robots_scanner import scan_robots

from utils.severity_score import calculate_severity


def run_full_scan(target):

    ports = scan_ports(target)

    dirs = scan_directories(target, "wordlists/directories.txt")

    subs = scan_subdomains(target, "wordlists/subdomains.txt")

    xss = scan_xss(target)

    sql = scan_sql_injection(target)

    missing = scan_security_headers(target)

    tech = detect_technology(target)

    robots = scan_robots(target)

    score, level = calculate_severity(xss, sql, missing, ports)

    results = {
        "target": target,
        "ports": ports,
        "directories": dirs,
        "subdomains": subs,
        "xss": xss,
        "sql_injection": sql,
        "missing_headers": missing,
        "technologies": tech,
        "robots_paths": robots,
        "risk_score": score,
        "severity": level
    }

    return results