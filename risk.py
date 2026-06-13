def risk_analysis(score):
    if score > -100:
        return "low", "allow"
    elif score < -0.1 and score > -0.3:
        return "medium", "mfa_required"
    else:
        return "high", "block"

    