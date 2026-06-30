def risk_analysis(score):
    if score > -0.3:
        return "low", "allow"
    elif score < -0.3 and score > -0.6:
        return "medium", "mfa_required"
    else:
        return "high", "block"

    