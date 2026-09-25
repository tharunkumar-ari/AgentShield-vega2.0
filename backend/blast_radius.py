RESOURCE_GRAPH = {

    "agent-001": [
        "api-gateway",
        "production-logs",
        "monitoring-service"
    ],

    "api-gateway": [
        "production-database",
        "file-storage"
    ],

    "production-database": [
        "customer-data",
        "transaction-data"
    ],

    "file-storage": [
        "backup-files",
        "configuration-files"
    ],

    "monitoring-service": [
        "metrics",
        "system-health"
    ]
}


RESOURCE_SENSITIVITY = {

    "api-gateway":
        "HIGH",

    "production-logs":
        "MEDIUM",

    "monitoring-service":
        "LOW",

    "production-database":
        "CRITICAL",

    "file-storage":
        "HIGH",

    "customer-data":
        "CRITICAL",

    "transaction-data":
        "CRITICAL",

    "backup-files":
        "HIGH",

    "configuration-files":
        "HIGH",

    "metrics":
        "LOW",

    "system-health":
        "LOW"
}


def calculate_blast_radius(
    identity
):

    visited = set()

    queue = [
        identity
    ]

    while queue:

        current = queue.pop(0)

        if current in visited:
            continue

        visited.add(current)

        connected_resources = (
            RESOURCE_GRAPH.get(
                current,
                []
            )
        )

        for resource in connected_resources:

            if resource not in visited:

                queue.append(
                    resource
                )

    reachable_resources = [
        resource
        for resource in visited
        if resource != identity
    ]

    critical_resources = []

    for resource in reachable_resources:

        sensitivity = (
            RESOURCE_SENSITIVITY.get(
                resource,
                "UNKNOWN"
            )
        )

        if sensitivity == "CRITICAL":

            critical_resources.append(
                resource
            )

    return {

        "identity":
            identity,

        "reachable_resources":
            reachable_resources,

        "total_resources":
            len(reachable_resources),

        "critical_resources":
            critical_resources,

        "critical_count":
            len(critical_resources)
    }


def generate_isolation_strategy(
    identity
):

    blast_radius = (
        calculate_blast_radius(
            identity
        )
    )

    isolation_actions = [

        f"Revoke credentials for {identity}",

        f"Block {identity} from API Gateway",

        f"Block access to production database",

        f"Block access to sensitive storage",

        f"Preserve monitoring services",

        f"Preserve unaffected users and services"
    ]

    return {

        "identity":
            identity,

        "blast_radius":
            blast_radius,

        "isolation_actions":
            isolation_actions
    }