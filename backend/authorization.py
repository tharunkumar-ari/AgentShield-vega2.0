def make_authorization_decision(risk_score):

    if risk_score < 30:

        return {
            "decision": "ALLOW",
            "level": "LOW",
            "message": "Access fully permitted.",
            "permissions": [
                "READ_LOGS",
                "READ_MONITORING",
                "READ_DATABASE"
            ]
        }

    elif risk_score < 60:

        return {
            "decision": "RESTRICT",
            "level": "MEDIUM",
            "message": "Access restricted because risk has increased.",
            "permissions": [
                "READ_LOGS",
                "READ_MONITORING"
            ]
        }

    elif risk_score < 80:

        return {
            "decision": "REAUTHENTICATE",
            "level": "HIGH",
            "message": "Additional authentication is required.",
            "permissions": [
                "READ_LOGS"
            ]
        }

    else:

        return {
            "decision": "REVOKE",
            "level": "CRITICAL",
            "message": "Access revoked because the identity is considered high risk.",
            "permissions": []
        }