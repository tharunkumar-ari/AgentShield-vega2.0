def calculate_risk(
    identity_trust,
    device_trust,
    behaviour_risk,
    task_risk,
    resource_sensitivity,
    network_risk
):

    identity_risk = 100 - identity_trust
    device_risk = 100 - device_trust

    risk_score = (
        identity_risk * 0.20 +
        device_risk * 0.15 +
        behaviour_risk * 0.25 +
        task_risk * 0.15 +
        resource_sensitivity * 0.15 +
        network_risk * 0.10
    )

    risk_score = round(risk_score)

    risk_score = max(
        0,
        min(100, risk_score)
    )

    return {
        "identity_risk": identity_risk,
        "device_risk": device_risk,
        "behaviour_risk": behaviour_risk,
        "task_risk": task_risk,
        "resource_sensitivity": resource_sensitivity,
        "network_risk": network_risk,
        "overall_risk": risk_score
    }