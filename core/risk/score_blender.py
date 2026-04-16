def blend_scores(ai_result: dict, rule_result: dict) -> dict:
    """
    Final score = (AI score x 0.6) + (Rule score x 0.4)
    AI handles nuanced reasoning, rules handle known bad configs.
    """
    ai_score   = ai_result.get("score", 0)
    rule_score = rule_result.get("score", 0)

    final = round((ai_score * 0.6) + (rule_score * 0.4))

    if final >= 80:   severity = "critical"
    elif final >= 60: severity = "high"
    elif final >= 40: severity = "medium"
    else:             severity = "low"

    return {
        "final_score":  final,
        "ai_score":     ai_score,
        "rule_score":   rule_score,
        "severity":     severity,
        "explanation":  ai_result.get("explanation", ""),
        "remediation":  ai_result.get("remediation", ""),
        "rule_reasons": rule_result.get("reasons", [])
    }
