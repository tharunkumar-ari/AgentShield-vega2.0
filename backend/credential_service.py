import secrets

from datetime import (
    datetime,
    timedelta,
    timezone
)


def issue_credential(
    identity,
    device,
    task,
    resource,
    risk_score,
    permissions
):

    credential_id = secrets.token_hex(16)

    issued_at = datetime.now(
        timezone.utc
    )

    expires_at = (
        issued_at +
        timedelta(minutes=5)
    )

    credential = {

        "credential_id":
            credential_id,

        "identity":
            identity,

        "device":
            device,

        "task":
            task,

        "resource":
            resource,

        "risk_at_issuance":
            risk_score,

        "permissions":
            permissions,

        "issued_at":
            issued_at.isoformat(),

        "expires_at":
            expires_at.isoformat(),

        "status":
            "ACTIVE"
    }

    return credential


def revoke_credential(
    credential
):

    if credential is not None:

        credential["status"] = "REVOKED"

    return credential


def is_credential_valid(
    credential
):

    if credential is None:
        return False

    if credential.get(
        "status"
    ) != "ACTIVE":

        return False

    expires_at = datetime.fromisoformat(
        credential["expires_at"]
    )

    current_time = datetime.now(
        timezone.utc
    )

    return current_time < expires_at