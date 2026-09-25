from flask import (
    Flask,
    request,
    jsonify
)

from flask_cors import CORS

import requests

import socket

import ipaddress

from urllib.parse import (
    urlparse
)

from datetime import (
    datetime,
    timezone
)


from risk_engine import (
    calculate_risk
)

from authorization import (
    make_authorization_decision
)

from credential_service import (
    issue_credential,
    revoke_credential,
    is_credential_valid
)

from blast_radius import (
    calculate_blast_radius,
    generate_isolation_strategy
)


app = Flask(__name__)

CORS(
    app,
    resources={
        r"/api/*": {
            "origins": "*"
        }
    }
)


# =========================================================
# SESSION
# =========================================================

SESSION = {

    "identity":
        "agent-001",

    "device":
        "robot-17",

    "task":
        "read_logs",

    "resource":
        "production-logs",

    "status":
        "ACTIVE",

    "credential":
        None,

    "last_decision":
        "WAITING"
}


# =========================================================
# AUDIT LOGS
# =========================================================

AUDIT_LOGS = []


def add_audit_log(
    event,
    decision,
    message,
    risk=None,
    resource=None
):

    AUDIT_LOGS.append({

        "timestamp":
            datetime.now(
                timezone.utc
            ).isoformat(),

        "identity":
            SESSION["identity"],

        "device":
            SESSION["device"],

        "event":
            event,

        "decision":
            decision,

        "message":
            message,

        "risk":
            risk,

        "resource":
            resource
    })


# =========================================================
# URL SAFETY
# =========================================================

def is_public_ip(
    hostname
):

    try:

        ip = socket.gethostbyname(
            hostname
        )

        address = ipaddress.ip_address(
            ip
        )

        if (
            address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_multicast
            or address.is_reserved
            or address.is_unspecified
        ):

            return False

        return True

    except Exception:

        return False


def inspect_resource(
    url
):

    parsed = urlparse(
        url
    )

    if parsed.scheme not in (
        "http",
        "https"
    ):

        return {
            "valid": False,
            "reason":
                "Only HTTP and HTTPS URLs are allowed."
        }

    if not parsed.hostname:

        return {
            "valid": False,
            "reason":
                "URL does not contain a valid hostname."
        }

    hostname = parsed.hostname.lower()

    blocked_hosts = [
        "localhost",
        "127.0.0.1",
        "0.0.0.0",
        "::1"
    ]

    if hostname in blocked_hosts:

        return {
            "valid": False,
            "reason":
                "Local resources are blocked."
        }

    if not is_public_ip(
        hostname
    ):

        return {
            "valid": False,
            "reason":
                "Private or restricted network address detected."
        }

    try:

        response = requests.get(

            url,

            timeout=5,

            allow_redirects=False,

            headers={
                "User-Agent":
                    "AgentShield-Security-Scanner/1.0"
            }
        )

        return {

            "valid": True,

            "status_code":
                response.status_code,

            "content_type":
                response.headers.get(
                    "Content-Type",
                    ""
                ),

            "redirect":
                response.headers.get(
                    "Location"
                )
        }

    except requests.RequestException as error:

        return {

            "valid": False,

            "reason":
                str(error)
        }


# =========================================================
# RISK ANALYSIS
# =========================================================

def analyze_request(
    url,
    inspection
):

    identity_trust = 90

    device_trust = 90

    behaviour_risk = 10

    task_risk = 5

    resource_sensitivity = 10

    network_risk = 5


    parsed = urlparse(
        url
    )

    hostname = (
        parsed.hostname or ""
    ).lower()

    path = (
        parsed.path or ""
    ).lower()


    combined_resource = (
        hostname +
        path
    )


    # -----------------------------------------------------
    # HTTPS CHECK
    # -----------------------------------------------------

    if parsed.scheme != "https":

        network_risk = 100


    # -----------------------------------------------------
    # SENSITIVE RESOURCE CHECK
    # -----------------------------------------------------

    sensitive_keywords = [

        "database",

        "customer",

        "transaction",

        "credential",

        "secret",

        "admin",

        "password",

        "backup",

        "configuration"
    ]


    for keyword in sensitive_keywords:

        if keyword in combined_resource:

            resource_sensitivity = 90

            break


    # -----------------------------------------------------
    # TASK / RESOURCE MISMATCH
    # -----------------------------------------------------

    restricted_for_read_logs = [

        "database",

        "customer",

        "transaction",

        "credential",

        "secret",

        "admin"
    ]


    if SESSION["task"] == "read_logs":

        for keyword in restricted_for_read_logs:

            if keyword in combined_resource:

                task_risk = 90

                break


    # -----------------------------------------------------
    # NETWORK FAILURE
    # -----------------------------------------------------

    if not inspection.get(
        "valid",
        False
    ):

        network_risk = 100

        behaviour_risk = 90


    # -----------------------------------------------------
    # HTTP STATUS
    # -----------------------------------------------------

    status_code = inspection.get(
        "status_code"
    )

    if status_code is not None:

        if status_code >= 400:

            behaviour_risk = 70


    # -----------------------------------------------------
    # COMPROMISE INDICATORS
    # -----------------------------------------------------

    severe_conditions = 0


    if resource_sensitivity >= 90:
        severe_conditions += 1


    if task_risk >= 80:
        severe_conditions += 1


    if behaviour_risk >= 70:
        severe_conditions += 1


    if network_risk >= 100:
        severe_conditions += 1


    if severe_conditions >= 3:

        identity_trust = 10

        device_trust = 15

        behaviour_risk = 100

        task_risk = 100

        resource_sensitivity = 90

        network_risk = 100


    return calculate_risk(

        identity_trust,

        device_trust,

        behaviour_risk,

        task_risk,

        resource_sensitivity,

        network_risk
    )


# =========================================================
# AUTHORIZATION
# =========================================================

def authorize_resource(
    url,
    risk
):

    risk_score = risk[
        "overall_risk"
    ]


    authorization = (
        make_authorization_decision(
            risk_score
        )
    )


    # -----------------------------------------------------
    # COMPROMISE
    # -----------------------------------------------------

    if risk_score >= 80:

        SESSION["status"] = "REVOKED"

        SESSION["last_decision"] = "REVOKE"

        SESSION["credential"] = (
            revoke_credential(
                SESSION["credential"]
            )
        )


        isolation = (
            generate_isolation_strategy(
                SESSION["identity"]
            )
        )


        add_audit_log(

            "COMPROMISE_DETECTED",

            "REVOKE",

            "High-risk activity detected. Identity isolated.",

            risk_score,

            url
        )


        return {

            "decision":
                "REVOKE",

            "authorization":
                authorization,

            "risk":
                risk,

            "credential":
                None,

            "isolation":
                isolation
        }


    # -----------------------------------------------------
    # ALLOW
    # -----------------------------------------------------

    if (
        authorization["decision"]
        == "ALLOW"
    ):

        credential = (
            issue_credential(

                SESSION["identity"],

                SESSION["device"],

                SESSION["task"],

                url,

                risk_score,

                authorization[
                    "permissions"
                ]
            )
        )


        SESSION["credential"] = (
            credential
        )

        SESSION["status"] = "ACTIVE"

        SESSION["last_decision"] = "ALLOW"


        add_audit_log(

            "RESOURCE_AUTHORIZED",

            "ALLOW",

            "Resource access granted with an ephemeral credential.",

            risk_score,

            url
        )


        return {

            "decision":
                "ALLOW",

            "authorization":
                authorization,

            "risk":
                risk,

            "credential":
                credential
        }


    # -----------------------------------------------------
    # RESTRICT / REAUTH
    # -----------------------------------------------------

    SESSION["last_decision"] = (
        authorization["decision"]
    )


    add_audit_log(

        "ACCESS_CONTROL",

        authorization["decision"],

        authorization["message"],

        risk_score,

        url
    )


    return {

        "decision":
            authorization["decision"],

        "authorization":
            authorization,

        "risk":
            risk,

        "credential":
            None
    }


# =========================================================
# SESSION API
# =========================================================

@app.route(
    "/api/session",
    methods=["GET"]
)
def get_session():

    credential = (
        SESSION["credential"]
    )

    credential_valid = (
        is_credential_valid(
            credential
        )
        if credential
        else False
    )


    return jsonify({

        "identity":
            SESSION["identity"],

        "device":
            SESSION["device"],

        "task":
            SESSION["task"],

        "resource":
            SESSION["resource"],

        "status":
            SESSION["status"],

        "last_decision":
            SESSION["last_decision"],

        "credential":
            credential,

        "credential_valid":
            credential_valid
    })


# =========================================================
# RESOURCE VERIFICATION API
# =========================================================

@app.route(
    "/api/verify-resource",
    methods=["POST"]
)
def verify_resource():

    data = (
        request.get_json(
            silent=True
        )
        or {}
    )

    url = (
        data.get("url")
        or ""
    ).strip()


    if not url:

        return jsonify({

            "error":
                "URL is required."

        }), 400


    inspection = (
        inspect_resource(
            url
        )
    )


    risk = (
        analyze_request(
            url,
            inspection
        )
    )


    result = (
        authorize_resource(
            url,
            risk
        )
    )


    result["url"] = url

    result["inspection"] = (
        inspection
    )

    result["session"] = {

        "identity":
            SESSION["identity"],

        "device":
            SESSION["device"],

        "task":
            SESSION["task"],

        "status":
            SESSION["status"]
    }


    return jsonify(
        result
    )


# =========================================================
# BLAST RADIUS
# =========================================================

@app.route(
    "/api/blast-radius",
    methods=["GET"]
)
def get_blast_radius():

    result = (
        calculate_blast_radius(
            SESSION["identity"]
        )
    )

    return jsonify(
        result
    )


# =========================================================
# ISOLATION
# =========================================================

@app.route(
    "/api/isolate",
    methods=["POST"]
)
def isolate():

    SESSION["status"] = (
        "ISOLATED"
    )

    SESSION["last_decision"] = (
        "REVOKE"
    )

    SESSION["credential"] = (
        revoke_credential(
            SESSION["credential"]
        )
    )


    result = (
        generate_isolation_strategy(
            SESSION["identity"]
        )
    )


    add_audit_log(

        "ISOLATION_ACTIVATED",

        "REVOKE",

        "Identity isolation activated. Credentials revoked.",

        100,

        SESSION["resource"]
    )


    return jsonify({

        "status":
            "ISOLATED",

        "identity":
            SESSION["identity"],

        "blast_radius":
            result["blast_radius"],

        "isolation_actions":
            result[
                "isolation_actions"
            ]
    })


# =========================================================
# AUDIT LOGS
# =========================================================

@app.route(
    "/api/audit-logs",
    methods=["GET"]
)
def get_audit_logs():

    return jsonify({

        "logs":
            AUDIT_LOGS
    })


# =========================================================
# RESET
# =========================================================

@app.route(
    "/api/reset",
    methods=["POST"]
)
def reset_session():

    SESSION["status"] = "ACTIVE"

    SESSION["last_decision"] = "WAITING"

    SESSION["credential"] = None

    add_audit_log(

        "SESSION_RESET",

        "RESET",

        "Security simulation session reset.",

        0,

        SESSION["resource"]
    )


    return jsonify({

        "message":
            "Session reset.",

        "session":
            SESSION
    })


# =========================================================
# HEALTH
# =========================================================

@app.route(
    "/api/health",
    methods=["GET"]
)
def health():

    return jsonify({

        "status":
            "ONLINE",

        "service":
            "AgentShield Security Engine",

        "timestamp":
            datetime.now(
                timezone.utc
            ).isoformat()
    })


# =========================================================
# ROOT
# =========================================================

@app.route("/")
def home():

    return jsonify({

        "name":
            "AgentShield",

        "status":
            "Security Engine Online",

        "version":
            "1.0"
    })


# =========================================================
# RUN
# =========================================================

if __name__ == "__main__":

    app.run(

        host="0.0.0.0",

        port=5000,

        debug=True
    )