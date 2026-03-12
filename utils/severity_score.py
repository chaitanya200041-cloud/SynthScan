def calculate_severity(xss, sql, missing_headers, open_ports):

    score = 0

    if xss:
        score += 3

    if sql:
        score += 4

    if missing_headers:
        score += 2

    if open_ports:
        score += 1

    if score >= 7:
        severity = "HIGH"
    elif score >= 4:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return score, severity