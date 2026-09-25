/*
===========================================================
AGENTSHIELD FRONTEND CONTROLLER
===========================================================
*/


/*
IMPORTANT

LOCAL:

http://127.0.0.1:5000

DEPLOYED:

https://agent-shield-backend.onrender.com
*/

const API_BASE =
    "https://agent-shield-backend.onrender.com";


let verifiedResource = null;

let credentialTimer = null;


/*
===========================================================
HELPERS
===========================================================
*/

function escapeHtml(value) {

    return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}


function formatAuditTime(value) {

    if (!value) {
        return "--";
    }

    const date =
        new Date(value);

    if (
        Number.isNaN(
            date.getTime()
        )
    ) {
        return value;
    }

    return date.toLocaleTimeString(
        [],
        {
            hour: "2-digit",
            minute: "2-digit",
            second: "2-digit"
        }
    );
}


/*
===========================================================
SESSION
===========================================================
*/

async function loadSession() {

    try {

        const response =
            await fetch(
                `${API_BASE}/api/session`
            );

        const data =
            await response.json();

        if (!response.ok) {

            throw new Error(
                data.error ||
                "Session unavailable"
            );
        }


        document.getElementById(
            "identity"
        ).textContent =
            data.identity || "--";


        document.getElementById(
            "device"
        ).textContent =
            data.device || "--";


        document.getElementById(
            "task"
        ).textContent =
            data.task || "--";


        document.getElementById(
            "sessionStatus"
        ).textContent =
            data.status || "--";


        const badge =
            document.getElementById(
                "identityBadge"
            );


        if (badge) {

            badge.textContent =
                data.status || "ACTIVE";

            badge.className =
                `badge ${
                    String(
                        data.status || ""
                    ).toLowerCase()
                }`;
        }


        if (
            data.credential &&
            data.credential_valid
        ) {

            showCredential(
                data.credential
            );
        }

    }
    catch (error) {

        console.error(
            "Session error:",
            error
        );
    }
}


/*
===========================================================
RISK
===========================================================
*/

function updateRisk(
    risk
) {

    if (!risk) return;


    const score =
        Number(
            risk.overall_risk ?? 0
        );


    document.getElementById(
        "riskNumber"
    ).textContent =
        score;


    document.getElementById(
        "riskProgress"
    ).style.width =
        `${score}%`;


    document.getElementById(
        "identityRisk"
    ).textContent =
        risk.identity_risk ?? 0;


    document.getElementById(
        "deviceRisk"
    ).textContent =
        risk.device_risk ?? 0;


    document.getElementById(
        "behaviourRisk"
    ).textContent =
        risk.behaviour_risk ?? 0;


    document.getElementById(
        "taskRisk"
    ).textContent =
        risk.task_risk ?? 0;


    document.getElementById(
        "resourceRisk"
    ).textContent =
        risk.resource_sensitivity ?? 0;


    document.getElementById(
        "networkRisk"
    ).textContent =
        risk.network_risk ?? 0;


    const level =
        document.getElementById(
            "riskLevel"
        );


    if (score < 30) {

        level.textContent =
            "LOW";

        level.className =
            "risk-level low";

    }

    else if (score < 60) {

        level.textContent =
            "MEDIUM";

        level.className =
            "risk-level medium";

    }

    else if (score < 80) {

        level.textContent =
            "HIGH";

        level.className =
            "risk-level high";

    }

    else {

        level.textContent =
            "CRITICAL";

        level.className =
            "risk-level critical";
    }
}


/*
===========================================================
AUTHORIZATION
===========================================================
*/

function updateAuthorization(
    authorization
) {

    if (!authorization) return;


    const decision =
        authorization.decision ||
        "WAITING";


    const element =
        document.getElementById(
            "authorizationDecision"
        );


    element.textContent =
        decision;


    element.className =
        `authorization-decision ${
            decision.toLowerCase()
        }`;


    document.getElementById(
        "authorizationMessage"
    ).textContent =
        authorization.message ||
        "No message";


    const permissions =
        document.getElementById(
            "permissions"
        );


    permissions.innerHTML = "";


    if (
        authorization.permissions &&
        authorization.permissions.length
    ) {

        authorization.permissions
            .forEach(
                permission => {

                    const item =
                        document.createElement(
                            "span"
                        );

                    item.textContent =
                        permission;

                    permissions.appendChild(
                        item
                    );
                }
            );

    }

    else {

        const item =
            document.createElement(
                "span"
            );

        item.textContent =
            "No permissions issued";

        permissions.appendChild(
            item
        );
    }
}


/*
===========================================================
URL VERIFICATION
===========================================================
*/

async function verifyResource() {

    const input =
        document.getElementById(
            "resourceUrl"
        );


    const result =
        document.getElementById(
            "resourceResult"
        );


    const openButton =
        document.getElementById(
            "openResourceButton"
        );


    const url =
        input.value.trim();


    if (!url) {

        result.innerHTML = `
            <div class="resource-danger">
                ⚠ Enter a URL first.
            </div>
        `;

        openButton.disabled =
            true;

        return;
    }


    result.innerHTML = `
        <div class="resource-checking">
            ◌ Inspecting URL with security engine...
        </div>
    `;


    openButton.disabled =
        true;


    /*
    -------------------------------------------------------
    TIMEOUT CONTROLLER
    -------------------------------------------------------
    */

    const controller =
        new AbortController();


    const timeout =
        setTimeout(
            () => {
                controller.abort();
            },
            15000
        );


    try {

        /*
        ---------------------------------------------------
        SEND URL TO FLASK BACKEND
        ---------------------------------------------------
        */

        const response =
            await fetch(
                `${API_BASE}/api/verify-resource`,
                {
                    method: "POST",

                    headers: {
                        "Content-Type":
                            "application/json"
                    },

                    body: JSON.stringify({
                        url: url
                    }),

                    signal:
                        controller.signal
                }
            );


        clearTimeout(
            timeout
        );


        /*
        ---------------------------------------------------
        READ BACKEND RESPONSE
        ---------------------------------------------------
        */

        const data =
            await response.json();


        console.log(
            "AgentShield verification response:",
            data
        );


        if (!response.ok) {

            throw new Error(
                data.error ||
                `Backend returned HTTP ${response.status}`
            );
        }


        verifiedResource =
            data;


        /*
        ---------------------------------------------------
        UPDATE DASHBOARD
        ---------------------------------------------------
        */

        updateRisk(
            data.risk
        );


        updateAuthorization(
            data.authorization
        );


        const decision =
            data.authorization?.decision ||
            data.decision ||
            "UNKNOWN";


        /*
        ===================================================
        ALLOW
        ===================================================
        */

        if (
            decision === "ALLOW"
        ) {

            result.innerHTML = `

                <div class="resource-success">

                    <div class="resource-title">
                        ✓ RESOURCE VERIFIED
                    </div>

                    <div class="resource-row">
                        <span>URL</span>

                        <strong>
                            ${escapeHtml(url)}
                        </strong>
                    </div>

                    <div class="resource-row">
                        <span>DECISION</span>

                        <strong>
                            ALLOW
                        </strong>
                    </div>

                    <div class="resource-row">
                        <span>RISK</span>

                        <strong>
                            ${data.risk?.overall_risk ?? "--"}/100
                        </strong>
                    </div>

                    <div class="resource-row">
                        <span>HTTP</span>

                        <strong>
                            ${data.inspection?.status_code ?? "REACHABLE"}
                        </strong>
                    </div>

                </div>

            `;


            /*
            Only ALLOW can enable
            Open Verified Resource.
            */

            openButton.disabled =
                false;


            showBotMessage(
                "Resource verified. The security engine returned ALLOW. The resource can now be opened."
            );


            if (
                data.credential
            ) {

                showCredential(
                    data.credential
                );
            }


            floatingAgent.classList.remove(
                "toy-warning",
                "toy-danger"
            );
        }


        /*
        ===================================================
        BLOCKED
        ===================================================
        */

        else {

            result.innerHTML = `

                <div class="resource-danger">

                    <div class="resource-title">
                        ✕ ACCESS BLOCKED
                    </div>

                    <div class="resource-row">
                        <span>DECISION</span>

                        <strong>
                            ${escapeHtml(decision)}
                        </strong>
                    </div>

                    <div class="resource-row">
                        <span>RISK</span>

                        <strong>
                            ${data.risk?.overall_risk ?? "--"}/100
                        </strong>
                    </div>

                    <div class="warning-text">
                        The resource will NOT be opened.
                    </div>

                    <div class="session-box">

                        <strong>
                            Current Session
                        </strong>

                        <br>

                        Identity:
                        ${escapeHtml(
                            data.session?.identity ||
                            "agent-001"
                        )}

                        <br>

                        Device:
                        ${escapeHtml(
                            data.session?.device ||
                            "robot-17"
                        )}

                        <br>

                        Task:
                        ${escapeHtml(
                            data.session?.task ||
                            "read_logs"
                        )}

                    </div>

                </div>

            `;


            /*
            Never allow opening a blocked resource.
            */

            openButton.disabled =
                true;


            showBotMessage(
                `Access blocked. Security decision: ${escapeHtml(decision)}.`
            );


            /*
            ------------------------------------------------
            WARNING STATE
            ------------------------------------------------
            */

            if (
                decision === "RESTRICT" ||
                decision === "REAUTHENTICATE"
            ) {

                floatingAgent.classList.remove(
                    "toy-danger"
                );

                floatingAgent.classList.add(
                    "toy-warning"
                );

            }

            /*
            ------------------------------------------------
            DANGER STATE
            ------------------------------------------------
            */

            else {

                floatingAgent.classList.remove(
                    "toy-warning"
                );

                floatingAgent.classList.add(
                    "toy-danger"
                );
            }


            /*
            ------------------------------------------------
            ISOLATION PREVIEW
            ------------------------------------------------
            */

            if (
                decision === "REVOKE" &&
                data.isolation
            ) {

                renderIsolationPreview(
                    data.isolation
                );
            }
        }


        /*
        ---------------------------------------------------
        REFRESH SECURITY INFORMATION
        ---------------------------------------------------
        */

        await loadBlastRadius();

        await loadAuditLogs();

    }

    catch (error) {

        clearTimeout(
            timeout
        );


        console.error(
            "AgentShield verification error:",
            error
        );


        let message =
            "Security engine request failed.";


        if (
            error.name === "AbortError"
        ) {

            message =
                "The security engine took too long to respond.";

        }

        else {

            message =
                error.message ||
                message;
        }


        result.innerHTML = `

            <div class="resource-danger">

                <div class="resource-title">
                    ⚠ SECURITY ENGINE ERROR
                </div>

                <p>
                    ${escapeHtml(message)}
                </p>

                <small>
                    Backend:
                    ${escapeHtml(API_BASE)}
                </small>

            </div>

        `;


        openButton.disabled =
            true;


        showBotMessage(
            `Security engine error: ${escapeHtml(message)}`
        );
    }
}


/*
===========================================================
OPEN VERIFIED RESOURCE
===========================================================
*/

function openVerifiedResource() {

    if (!verifiedResource) {

        showBotMessage(
            "No resource has been verified."
        );

        return;
    }


    const authorization =
        verifiedResource.authorization;


    /*
    SECURITY CHECK

    Only ALLOW can open the resource.
    */

    if (
        !authorization ||
        authorization.decision !== "ALLOW"
    ) {

        showBotMessage(
            "The resource is not authorized and will not be opened."
        );

        return;
    }


    const url =
        verifiedResource.url;


    if (!url) return;


    window.open(
        url,
        "_blank",
        "noopener,noreferrer"
    );
}


/*
===========================================================
CREDENTIAL
===========================================================
*/

function showCredential(
    credential
) {

    if (!credential) return;


    const status =
        document.getElementById(
            "credentialStatus"
        );


    const id =
        document.getElementById(
            "credentialId"
        );


    if (status) {

        status.textContent =
            credential.status;

        status.className =
            `badge ${
                String(
                    credential.status || ""
                ).toLowerCase()
            }`;
    }


    if (id) {

        id.textContent =
            credential.credential_id;
    }


    startCredentialTimer(
        credential.expires_at
    );
}


function startCredentialTimer(
    expiresAt
) {

    if (credentialTimer) {

        clearInterval(
            credentialTimer
        );
    }


    function update() {

        const expires =
            new Date(
                expiresAt
            ).getTime();


        const now =
            Date.now();


        const remaining =
            Math.max(
                0,
                expires - now
            );


        const seconds =
            Math.floor(
                remaining / 1000
            );


        const minutes =
            Math.floor(
                seconds / 60
            );


        const secs =
            seconds % 60;


        const timer =
            document.getElementById(
                "credentialTimer"
            );


        if (timer) {

            timer.textContent =
                `${minutes}:${String(secs).padStart(2, "0")}`;
        }


        if (
            remaining <= 0
        ) {

            clearInterval(
                credentialTimer
            );


            const status =
                document.getElementById(
                    "credentialStatus"
                );


            if (status) {

                status.textContent =
                    "EXPIRED";
            }
        }
    }


    update();


    credentialTimer =
        setInterval(
            update,
            1000
        );
}


/*
===========================================================
BLAST RADIUS
===========================================================
*/

async function loadBlastRadius() {

    const graph =
        document.getElementById(
            "blastRadiusGraph"
        );


    if (!graph) return;


    try {

        const response =
            await fetch(
                `${API_BASE}/api/blast-radius`
            );


        const data =
            await response.json();


        if (!response.ok) {

            throw new Error(
                data.error ||
                "Blast radius failed."
            );
        }


        const totalResources =
            document.querySelector(
                ".total-resources"
            );


        const criticalCount =
            document.querySelector(
                ".critical-count"
            );


        if (totalResources) {

            totalResources.textContent =
                data.total_resources ?? 0;
        }


        if (criticalCount) {

            criticalCount.textContent =
                data.critical_count ?? 0;
        }


        renderBlastGraph(
            data
        );

    }

    catch (error) {

        console.error(
            "Blast radius:",
            error
        );


        graph.innerHTML = `

            <div class="graph-error">
                Blast radius service unavailable.
            </div>

        `;
    }
}


function renderBlastGraph(
    data
) {

    const graph =
        document.getElementById(
            "blastRadiusGraph"
        );


    if (!graph) return;


    graph.innerHTML = "";


    const root =
        createGraphNode(
            data.identity,
            "identity",
            false
        );


    graph.appendChild(
        root
    );


    const line =
        document.createElement(
            "div"
        );


    line.className =
        "graph-line";


    graph.appendChild(
        line
    );


    const layer =
        document.createElement(
            "div"
        );


    layer.className =
        "graph-resource-layer";


    (data.reachable_resources || [])
        .forEach(
            resource => {

                const critical =
                    data.critical_resources?.includes(
                        resource
                    );


                layer.appendChild(
                    createGraphNode(
                        resource,
                        critical
                            ? "critical"
                            : "resource",
                        critical
                    )
                );
            }
        );


    graph.appendChild(
        layer
    );
}


function createGraphNode(
    name,
    type,
    critical
) {

    const node =
        document.createElement(
            "div"
        );


    node.className =
        `graph-node ${type}`;


    node.innerHTML = `

        <div class="node-icon">

            ${
                type === "identity"
                    ? "◉"
                    : critical
                    ? "!"
                    : "◆"
            }

        </div>

        <div class="node-name">

            ${escapeHtml(name)}

        </div>

        ${
            critical
                ? `
                    <div class="node-label">
                        CRITICAL
                    </div>
                `
                : ""
        }

    `;


    return node;
}


/*
===========================================================
ISOLATION
===========================================================
*/

function renderIsolationPreview(
    isolation
) {

    if (!isolation) return;


    const container =
        document.querySelector(
            ".isolation-actions"
        );


    if (!container) return;


    container.innerHTML = "";


    (isolation.isolation_actions || [])
        .forEach(
            action => {

                const item =
                    document.createElement(
                        "div"
                    );


                item.className =
                    "isolation-action";


                item.textContent =
                    `✓ ${action}`;


                container.appendChild(
                    item
                );
            }
        );
}


async function activateIsolation() {

    try {

        const response =
            await fetch(
                `${API_BASE}/api/isolate`,
                {
                    method: "POST",

                    headers: {
                        "Content-Type":
                            "application/json"
                    }
                }
            );


        const data =
            await response.json();


        if (!response.ok) {

            throw new Error(
                data.error ||
                "Isolation failed."
            );
        }


        const status =
            document.querySelector(
                ".isolation-status"
            );


        if (status) {

            status.textContent =
                "ISOLATION ACTIVE";

            status.classList.add(
                "active"
            );
        }


        const container =
            document.querySelector(
                ".isolation-actions"
            );


        if (container) {

            container.innerHTML = "";


            (data.isolation_actions || [])
                .forEach(
                    action => {

                        const item =
                            document.createElement(
                                "div"
                            );


                        item.className =
                            "isolation-action";


                        item.innerHTML = `
                            <span>✓</span>
                            ${escapeHtml(action)}
                        `;


                        container.appendChild(
                            item
                        );
                    }
                );
        }


        const sessionStatus =
            document.getElementById(
                "sessionStatus"
            );


        if (sessionStatus) {

            sessionStatus.textContent =
                "ISOLATED";
        }


        const identityBadge =
            document.getElementById(
                "identityBadge"
            );


        if (identityBadge) {

            identityBadge.textContent =
                "ISOLATED";

            identityBadge.className =
                "badge revoked";
        }


        floatingAgent.classList.remove(
            "toy-warning"
        );


        floatingAgent.classList.add(
            "toy-danger"
        );


        await loadBlastRadius();

        await loadAuditLogs();


        showBotMessage(
            "Isolation activated. The compromised identity has been contained."
        );

    }

    catch (error) {

        console.error(
            "Isolation:",
            error
        );


        showBotMessage(
            `Isolation failed: ${escapeHtml(
                error.message || "Backend error."
            )}`
        );
    }
}


/*
===========================================================
AUDIT LOGS
===========================================================
*/

async function loadAuditLogs() {

    const container =
        document.getElementById(
            "auditLogs"
        );


    if (!container) return;


    try {

        const response =
            await fetch(
                `${API_BASE}/api/audit-logs`
            );


        const data =
            await response.json();


        if (!response.ok) {

            throw new Error(
                "Audit logs unavailable."
            );
        }


        const logs =
            data.logs || [];


        if (!logs.length) {

            container.innerHTML = `

                <div class="audit-empty">
                    No security events recorded yet.
                </div>

            `;

            return;
        }


        container.innerHTML = "";


        [...logs]
            .reverse()
            .forEach(
                log => {

                    const decision =
                        String(
                            log.decision ||
                            log.event ||
                            "EVENT"
                        ).toUpperCase();


                    let severity =
                        "normal";


                    if (
                        decision.includes(
                            "REVOKE"
                        ) ||
                        decision.includes(
                            "ISOLATION"
                        )
                    ) {

                        severity =
                            "danger";

                    }

                    else if (
                        decision.includes(
                            "RESTRICT"
                        ) ||
                        decision.includes(
                            "REAUTH"
                        )
                    ) {

                        severity =
                            "warning";

                    }

                    else if (
                        decision.includes(
                            "ALLOW"
                        )
                    ) {

                        severity =
                            "success";
                    }


                    const row =
                        document.createElement(
                            "div"
                        );


                    row.className =
                        `audit-row ${severity}`;


                    row.innerHTML = `

                        <div class="audit-indicator"></div>

                        <div class="audit-time">
                            ${formatAuditTime(
                                log.timestamp
                            )}
                        </div>

                        <div class="audit-event">

                            <strong>
                                ${escapeHtml(
                                    decision
                                )}
                            </strong>

                            <span>
                                ${escapeHtml(
                                    log.message ||
                                    log.resource ||
                                    "Security event"
                                )}
                            </span>

                        </div>

                        <div class="audit-identity">

                            ${escapeHtml(
                                log.identity ||
                                "agent-001"
                            )}

                        </div>

                    `;


                    container.appendChild(
                        row
                    );
                }
            );

    }

    catch (error) {

        console.error(
            "Audit:",
            error
        );


        container.innerHTML = `

            <div class="audit-empty">
                Audit service unavailable.
            </div>

        `;
    }
}


/*
===========================================================
CLEAR DISPLAY
===========================================================
*/

document
    .getElementById(
        "clearLogsButton"
    )
    ?.addEventListener(
        "click",
        function () {

            document.getElementById(
                "auditLogs"
            ).innerHTML = `

                <div class="audit-empty">
                    Display cleared.
                    Backend audit history remains available.
                </div>

            `;
        }
    );


/*
===========================================================
CHATBOT
===========================================================
*/

const floatingAgent =
    document.getElementById(
        "floatingAgent"
    );


const floatingAgentButton =
    document.getElementById(
        "floatingAgentButton"
    );


const closeAgentChat =
    document.getElementById(
        "closeAgentChat"
    );


const chatInput =
    document.getElementById(
        "chatInput"
    );


const sendChat =
    document.getElementById(
        "sendChat"
    );


const chatMessages =
    document.getElementById(
        "chatMessages"
    );


function showBotMessage(
    message
) {

    if (!chatMessages) return;


    const div =
        document.createElement(
            "div"
        );


    div.className =
        "bot-message";


    div.innerHTML =
        message;


    chatMessages.appendChild(
        div
    );


    chatMessages.scrollTop =
        chatMessages.scrollHeight;
}


function showUserMessage(
    message
) {

    if (!chatMessages) return;


    const div =
        document.createElement(
            "div"
        );


    div.className =
        "user-message";


    div.textContent =
        message;


    chatMessages.appendChild(
        div
    );


    chatMessages.scrollTop =
        chatMessages.scrollHeight;
}


function answerQuestion(
    question
) {

    const q =
        question.toLowerCase();


    if (
        q.includes("risk")
    ) {

        return `

            <b>Risk Engine</b><br><br>

            AgentShield combines identity,
            device, behaviour, task,
            resource and network signals.

            The result is a score from 0 to 100.

        `;
    }


    if (
        q.includes("blast")
    ) {

        return `

            <b>Blast Radius</b><br><br>

            It shows what resources the
            current identity can potentially
            reach if it is compromised.

            Red nodes represent critical resources.

        `;
    }


    if (
        q.includes("isolation")
    ) {

        return `

            <b>Isolation</b><br><br>

            Isolation revokes the identity's
            active credential and applies the
            containment strategy while preserving
            unaffected services.

        `;
    }


    if (
        q.includes("credential")
    ) {

        return `

            <b>Ephemeral Credential</b><br><br>

            A temporary credential is issued
            only after authorization.

            It expires automatically after
            a short period.

        `;
    }


    if (
        q.includes("authorization") ||
        q.includes("allow")
    ) {

        return `

            <b>Authorization</b><br><br>

            ALLOW grants the requested permissions.

            RESTRICT reduces permissions.

            REAUTHENTICATE requires additional verification.

            REVOKE removes access.

        `;
    }


    if (
        q.includes("zero trust")
    ) {

        return `

            <b>Zero Trust</b><br><br>

            AgentShield does not permanently trust
            an identity.

            Every resource request is evaluated
            using its current context and risk.

        `;
    }


    if (
        q.includes("url")
    ) {

        return `

            <b>URL Verification</b><br><br>

            The backend inspects the resource first.

            Only an ALLOW decision enables the
            Open Verified Resource button.

        `;
    }


    return `

        I can explain <b>risk</b>,
        <b>authorization</b>,
        <b>credentials</b>,
        <b>blast radius</b>,
        <b>isolation</b> or
        <b>Zero Trust</b>.

    `;
}


function sendChatMessage() {

    if (!chatInput) return;


    const message =
        chatInput.value.trim();


    if (!message) return;


    showUserMessage(
        message
    );


    chatInput.value = "";


    setTimeout(
        () => {

            showBotMessage(
                answerQuestion(
                    message
                )
            );

        },
        250
    );
}


sendChat?.addEventListener(
    "click",
    sendChatMessage
);


chatInput?.addEventListener(
    "keydown",
    event => {

        if (
            event.key === "Enter"
        ) {

            sendChatMessage();
        }
    }
);


/*
===========================================================
DRAGGABLE CHATBOT
===========================================================
*/

let dragging =
    false;


let moved =
    false;


let startX =
    0;


let startY =
    0;


let startLeft =
    0;


let startTop =
    0;


floatingAgentButton?.addEventListener(
    "pointerdown",
    event => {

        event.preventDefault();


        dragging =
            true;


        moved =
            false;


        startX =
            event.clientX;


        startY =
            event.clientY;


        const rect =
            floatingAgent.getBoundingClientRect();


        startLeft =
            rect.left;


        startTop =
            rect.top;


        floatingAgent.classList.add(
            "dragging"
        );


        floatingAgentButton.setPointerCapture(
            event.pointerId
        );
    }
);


floatingAgentButton?.addEventListener(
    "pointermove",
    event => {

        if (!dragging) return;


        const dx =
            event.clientX -
            startX;


        const dy =
            event.clientY -
            startY;


        if (
            Math.abs(dx) > 5 ||
            Math.abs(dy) > 5
        ) {

            moved =
                true;
        }


        let left =
            startLeft + dx;


        let top =
            startTop + dy;


        left =
            Math.max(
                0,
                Math.min(
                    left,
                    window.innerWidth -
                    floatingAgent.offsetWidth
                )
            );


        top =
            Math.max(
                0,
                Math.min(
                    top,
                    window.innerHeight -
                    floatingAgent.offsetHeight
                )
            );


        floatingAgent.style.left =
            `${left}px`;


        floatingAgent.style.top =
            `${top}px`;


        floatingAgent.style.right =
            "auto";


        floatingAgent.style.bottom =
            "auto";
    }
);


floatingAgentButton?.addEventListener(
    "pointerup",
    event => {

        if (!dragging) return;


        dragging =
            false;


        floatingAgent.classList.remove(
            "dragging"
        );


        if (!moved) {

            floatingAgent.classList.toggle(
                "chat-open"
            );
        }


        try {

            floatingAgentButton.releasePointerCapture(
                event.pointerId
            );

        }

        catch (error) {

            console.warn(
                "Pointer capture release:",
                error
            );
        }
    }
);


floatingAgentButton?.addEventListener(
    "pointercancel",
    () => {

        dragging =
            false;


        floatingAgent.classList.remove(
            "dragging"
        );
    }
);


closeAgentChat?.addEventListener(
    "click",
    () => {

        floatingAgent.classList.remove(
            "chat-open"
        );
    }
);


/*
===========================================================
BUTTONS
===========================================================
*/

document
    .getElementById(
        "verifyButton"
    )
    ?.addEventListener(
        "click",
        verifyResource
    );


document
    .getElementById(
        "openResourceButton"
    )
    ?.addEventListener(
        "click",
        openVerifiedResource
    );


document
    .getElementById(
        "isolateButton"
    )
    ?.addEventListener(
        "click",
        activateIsolation
    );


/*
===========================================================
INITIALIZE
===========================================================
*/

async function initialize() {

    console.log(
        "AgentShield frontend started."
    );

    console.log(
        "Backend:",
        API_BASE
    );


    await loadSession();

    await loadBlastRadius();

    await loadAuditLogs();
}


initialize();
