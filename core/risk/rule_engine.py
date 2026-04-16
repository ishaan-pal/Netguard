def rule_score(dangerous_ports: list[dict], cves: list, firmware: dict) -> dict:
    """
    Minimal fallback scoring — only used when AI is unavailable.
    Only scores critical, high, and medium severity findings.
    Low severity ports are excluded from scoring entirely.
    """
    score   = 0
    reasons = []

    # Only score critical, high, and medium — low severity excluded
    RISK_POINTS = {"critical": 30, "high": 20, "medium": 10}
    for p in dangerous_ports:
        risk = p.get("risk", "high")
        if risk not in RISK_POINTS:
            continue  # skip low and unknown severity
        pts = RISK_POINTS[risk]
        score += pts
        reasons.append(
            f"Port {p['port']} ({p.get('service','unknown')}) "
            f"— {p.get('reason', 'flagged as dangerous')} (+{pts})"
        )

    # CVEs are objective facts from Shodan — always apply
    if cves:
        pts = min(len(cves) * 10, 30)
        score += pts
        reasons.append(f"{len(cves)} known CVE(s) found via Shodan (+{pts})")

    # Outdated firmware is an objective fact — always apply
    if firmware.get("is_outdated"):
        score += 10
        reasons.append(
            f"Firmware estimated {firmware['age_years']} years old (+10)"
        )

    return {
        "score":   min(score, 100),
        "reasons": reasons
    }
