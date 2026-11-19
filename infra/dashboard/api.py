# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""The read API behind the dashboard.

The browser cannot call the Registry directly: every agent-registry-control
API is SigV4/IAM-authenticated, and a browser holds a Cognito JWT, not IAM
credentials. So this Lambda is the bridge. It authenticates the caller with the
same Cognito user pool the Gateway uses, then reads the Registry with its own
IAM role.

WHAT THIS IS AND IS NOT

It is a *catalogue* view: what assets exist, who owns them, whether a human
signed them off. It is NOT a view of what anyone is allowed to call. Those are
different questions with different answers, and conflating them is the easiest
mistake to make here — the Gateway does not consult the Registry, so an
APPROVED record here says nothing about reachability. The response includes a
`caveat` field saying so, because a dashboard is the easiest place in this whole
platform to accidentally imply enforcement.

TENANT SCOPING, AND WHY IT IS DELIBERATELY NOT CEDAR

A reviewer needs to see the whole catalogue — that is the point of an asset
register. But a *tenant admin* should arguably see only their own assets. This
API reads the caller's custom:tenant claim and filters unless they are a
platform reviewer, and it does that filtering HERE, in application code.

That is worth being explicit about: this is NOT Cedar, and it is not the same
enforcement the Gateway does. The Registry has no policy engine, so there is no
managed control available to borrow. Authorisation on the catalogue is
application logic; authorisation on tool calls is Cedar. They are two
mechanisms, not one.

WHY GET, AND NOT WRITE, IN v1 OF THIS FILE

Approve/reject is implemented (POST /records/{id}/status) because the whole
value of the status machine is that a human acts on it. But note the asymmetry:
reads are open to any authenticated user in the pool, writes require the
reviewer group. A dashboard where anyone can approve their own asset would be
worse than no dashboard, because it would look like governance.

THE TWO ASYMMETRIES, BECAUSE THEY ARE EASY TO CONFLATE

  · registering an asset (POST /api/records) is open to any authenticated user,
    but the tenant and owner are taken from the CALLER'S TOKEN, never from the
    form. A tenant cannot register into another tenant's namespace.
  · acting on the review queue (POST /api/records/{id}/status) requires the
    reviewer group. So anyone can propose; only a reviewer can approve.

That is the shape of every real intake process, and it is the reason the register
form does not need to be locked down to reviewers to be safe.

THE PUBLISH-TIME SCAN

POST /api/records runs the submitted description through a Bedrock guardrail
(PROMPT_ATTACK) before the record is created. A description that trips the scan
is refused and no record exists afterwards.

This is a genuinely different control from the call-time scan, at a different
moment, and the difference matters when describing it:

  · the policy engine's guardrail rules score tool ARGUMENTS at call time, and a
    refusal stops a call that is happening now.
  · this scans DESCRIPTORS at publish time, and a refusal stops a poisoned tool
    description from entering the catalogue at all.

A tool description is a prompt. The model reads it to decide whether to call the
tool, so an instruction hidden in a description is an injection with a much
longer reach than one in a single request — it affects every future call by every
user. Scanning at publish time is the cheaper place to catch it, and it is the
only one of the two that leaves nothing behind to clean up.
"""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Any

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

REGISTRY_ID = os.environ.get("REGISTRY_ID", "")
GATEWAY_URL = os.environ.get("GATEWAY_URL", "")
ENFORCEMENT_MODE = os.environ.get("ENFORCEMENT_MODE", "")
SCAN_MODE = os.environ.get("SCAN_MODE", "")
TENANT_CLAIM = os.environ.get("TENANT_CLAIM", "custom:tenant")
DECISION_LOG_GROUP = os.environ.get("DECISION_LOG_GROUP", "")

# 30 days, matching the decision log group's retention (observability.py sets
# ONE_MONTH). Asking for a wider window than the retention would return a
# confidently empty-looking early period that is really just expired data.
MAX_WINDOW_MINUTES = 30 * 24 * 60

# Read bounds for one request. See _log_events — the event bound keeps the
# NEWEST events, not the oldest.
MAX_EVENTS = 5000
MAX_PAGES = 25

# The guardrail that scans descriptions at registration. Call-time scanning of
# tool arguments is done by guardrail rules in the policy engine, with the same
# PROMPT_ATTACK filter, so "the scan" means the same check at both moments.
GUARDRAIL_ID = os.environ.get("GUARDRAIL_ID", "")
GUARDRAIL_VERSION = os.environ.get("GUARDRAIL_VERSION", "DRAFT")

# The server.json description limit — see infra/registry/construct.py. Violating
# it is reported as "mcp.server data does not match any supported
# version", a message about versions for a length problem, so the truncation
# happens here rather than being discovered at the API boundary.
MAX_SERVER_DESCRIPTION = 100

# The MCP registry schema, pinned to the same URL the CDK construct pins. If
# these two ever disagree, records created by the form and records created by the
# deploy would validate against different schemas — which would surface as a
# random-looking failure on one path only.
MCP_SERVER_SCHEMA = (
    "https://static.modelcontextprotocol.io/schemas/2025-09-29/server.schema.json"
)

# A Cognito group whose members may act on the review queue. Membership is the
# whole access control story for writes, so it is named rather than implied.
REVIEWER_GROUP = os.environ.get("REVIEWER_GROUP", "platform-reviewers")

# The statuses a reviewer may move a record to. DEPRECATED is included; CREATING
# and the failure states are not — those are the service's to set, and offering
# them as buttons would imply this API can fake a lifecycle it does not own.
SETTABLE = {"APPROVED", "REJECTED", "DEPRECATED"}

_control = boto3.client("agent-registry-control")
_bedrock = boto3.client("bedrock-runtime")
_logs = boto3.client("logs")

CAVEAT = (
    "An APPROVED record is a review record, not a gate. The Gateway does not "
    "consult the Registry — Cedar decides what is reachable. Editing an "
    "approved record drops it back to DRAFT, so an approval cannot outlive "
    "the content it approved."
)


def handler(event: dict, context: Any) -> dict:
    """HTTP API v2 payload in, JSON out."""
    route = event.get("routeKey", "")
    claims = _claims(event)
    caller = claims.get("email") or claims.get("cognito:username") or "unknown"
    tenant = claims.get(TENANT_CLAIM, "")
    groups = _groups(claims)

    logger.info(
        "route=%s caller=%s tenant=%s reviewer=%s",
        route, caller, tenant, REVIEWER_GROUP in groups,
    )

    if not REGISTRY_ID:
        # Fail loudly rather than returning an empty catalogue. An empty table
        # and a misconfigured table look identical on screen, and the first
        # build's central defect was exactly that class of silent default.
        return _json(500, {"error": "REGISTRY_ID is not set — the API cannot "
                                    "read the catalogue. Check the deployment."})

    wrong_token = _wrong_token_type(claims)
    if wrong_token:
        return _json(401, {"error": wrong_token})

    try:
        if route == "GET /api/summary":
            return _json(200, _summary(claims, tenant, groups))
        if route == "GET /api/records":
            return _json(200, _records(tenant, groups))
        if route == "GET /api/decisions":
            return _json(200, _decisions(event, claims, tenant, groups))
        # Exact match, not a prefix: "POST /api/records/{id}/status" also starts
        # with "POST /api/records", so a startswith here would swallow it.
        if route == "POST /api/records":
            return _register(event, caller, tenant)
        if route.startswith("POST /api/records/"):
            return _set_status(event, caller, groups)
    except ClientError as exc:
        logger.exception("registry call failed")
        return _json(502, {"error": f"the Registry rejected the call: {exc}"})

    return _json(404, {"error": f"no such route: {route}"})


# ------------------------------------------------------------------ reads


def _summary(claims: dict, tenant: str, groups: list[str]) -> dict:
    """Everything the dashboard header needs, in one call.

    Deliberately one round trip: the header shows platform-wide modes, and a
    second fetch would let the page render half-configured for a moment, which
    reads as a bug.
    """
    records = _records(tenant, groups)["records"]
    counts: dict[str, int] = {}
    for r in records:
        counts[r["status"]] = counts.get(r["status"], 0) + 1

    return {
        "records": records,
        "counts": counts,
        "viewer": {
            "email": claims.get("email", ""),
            "tenant": tenant,
            "isReviewer": REVIEWER_GROUP in groups,
        },
        "platform": {
            # These come from the stack, not from a live API call, and are
            # labelled in the UI as the deployed configuration. Reading them
            # live would be better and is a v2 note, not a pretence here.
            "gatewayUrl": GATEWAY_URL,
            "enforcementMode": ENFORCEMENT_MODE,
            "scanMode": SCAN_MODE,
        },
        # What this deployment can actually do, so the UI hides what is not
        # wired rather than offering a button that 503s. A greyed-out feature
        # with a reason is honest; a button that fails looks like a bug.
        "capabilities": {
            "register": bool(GUARDRAIL_ID),
            "registerDisabledBecause": "" if GUARDRAIL_ID else (
                "Registration is not available in this deployment."
            ),
            "auditTrail": bool(DECISION_LOG_GROUP),
            "auditDisabledBecause": "" if DECISION_LOG_GROUP else (
                "The audit trail is not available in this deployment."
            ),
        },
        "caveat": CAVEAT,
    }


def _records(tenant: str, groups: list[str]) -> dict:
    """Every record the caller may see.

    ListRegistryRecords returns "registryRecords", NOT "items" — the wrong key
    yields None, which reads as "the registry is empty" rather than "you asked
    for the wrong thing". That mistake is easy to make, so it is worth a
    comment at every call site.

    statusReason is NOT in the list response; only GetRegistryRecord has it. The
    reason a thing was approved is the entire audit value of the workflow, so it
    is fetched per record. Fine at this size, wrong for thousands — noted rather
    than pretended away.
    """
    visible = [_shape(r) for r in _all_records()]
    if not _may_see_everything(groups):
        visible = [r for r in visible if r["tenant"] == tenant]

    visible.sort(key=lambda r: r["name"])
    return {
        "records": visible,
        "scopedToTenant": None if _may_see_everything(groups) else tenant,
    }


def _all_records() -> list[dict]:
    """Every record in the registry, unfiltered and unshaped.

    Shared by the catalogue read and the duplicate-name check on register, so
    there is one place that knows the response key is "registryRecords" and NOT
    "items" — the wrong key returns None, which reads as "the registry is empty"
    rather than "you asked for the wrong thing".
    """
    items: list[dict] = []
    token = None
    while True:
        kwargs: dict[str, Any] = {"registryId": REGISTRY_ID, "maxResults": 50}
        if token:
            kwargs["nextToken"] = token
        page = _control.list_registry_records(**kwargs)
        items.extend(page.get("registryRecords") or [])
        token = page.get("nextToken")
        if not token:
            return items


def _shape(record: dict) -> dict:
    """One record, flattened for the browser.

    The tenant and owner live inside the description as "[tenant: x, owner: y]"
    because a registry record has no structured field for either — see
    infra/registry/construct.py. Parsing them back out here is the cost of that,
    and it is better done in one place than in the UI.
    """
    description = record.get("description") or ""
    tenant, owner, clean = _split_annotation(description)

    reason = record.get("statusReason")
    if reason is None:
        try:
            full = _control.get_registry_record(
                registryId=REGISTRY_ID, recordId=record["recordId"]
            )
            reason = full.get("statusReason")
        except ClientError:
            reason = None  # cosmetic; never fail the listing over a reason

    return {
        "id": record["recordId"],
        "name": record.get("name", ""),
        "description": clean,
        "tenant": tenant,
        "owner": owner,
        "type": record.get("recordType", ""),
        "status": record.get("status", ""),
        "statusReason": reason or "",
        "createdAt": _iso(record.get("createdAt")),
        "updatedAt": _iso(record.get("updatedAt")),
    }


def _split_annotation(description: str) -> tuple[str, str, str]:
    """Pull "[tenant: x, owner: y]" back off the end of a description."""
    if not description.endswith("]") or "[tenant:" not in description:
        return "", "", description
    head, _, annotation = description.rpartition("[tenant:")
    tenant = owner = ""
    for part in annotation.rstrip("]").split(","):
        key, _, value = part.partition(":")
        key, value = key.strip(), value.strip()
        if not value and not owner:
            tenant = key  # the first fragment has no key, it IS the tenant
        elif key == "owner":
            owner = value
    return tenant, owner, head.strip()


# -------------------------------------------------------------- the audit trail


def _decisions(event: dict, claims: dict, tenant: str, groups: list[str]) -> dict:
    """Recent policy decisions, joined into one row per request.

    This is the other half of the governance question. The catalogue answers
    "what do we have and who signed it off". This answers "what actually
    happened" — who called what, and whether Cedar allowed it.

    WHY IT IS NOT ONE LOG LINE PER DECISION

    A single tools/call emits SEVERAL records, and the decision and the outcome
    are in different ones. That is not an inconvenience, it is the most valuable
    thing in the log: under LOG_ONLY a DENY sits next to a successful response,
    so the trail shows calls the policy would have refused and did not. Grouping
    by request_id is what makes that contradiction visible. The same grouping
    logic lives in scripts/decisions.py.

    TWO LIMITS, BOTH REPORTED TO THE BROWSER RATHER THAN HIDDEN

    · tools/list produces NO policy record. It IS still enforced — Cedar filters
      the listing, verified — so this is a logging gap, not a security one. But
      it means there is no trail of what each user could SEE, only of what they
      called. Under ENFORCE the interesting denials mostly disappear, because a
      model that cannot see a tool never calls it. Which is the real argument for
      running LOG_ONLY first.
    · delivery lags 30-60 seconds. An empty trail immediately after a call is
      normal, and the response says so, because "no decisions" on a screen looks
      like a broken feature rather than a pending delivery.

    Tenant scoping matches the catalogue: reviewers see every decision, everyone
    else sees only their own. Application logic, not Cedar — same caveat as
    _records(). Note that a non-reviewer sees decisions about THEMSELVES rather
    than about their tenant, which is stricter: the log identifies the caller by
    Cognito sub and carries no tenant, so scoping by tenant is not expressible
    without a second lookup that could get it wrong.
    """
    params = event.get("queryStringParameters") or {}
    try:
        minutes = max(1, min(int(params.get("minutes", 60)), MAX_WINDOW_MINUTES))
    except (TypeError, ValueError):
        minutes = 60

    if not DECISION_LOG_GROUP:
        unavailable = (
            "no decision log group is configured. AgentCore creates none by "
            "default — CloudWatch log delivery has to be set up explicitly "
            "(infra/gateway/observability.py). Without it an account with a "
            "fully-enforcing Gateway records nothing at all."
        )
        return {
            "decisions": [],
            "unavailable": unavailable,
            **_decision_notes(minutes, groups),
        }

    try:
        events, truncated = _log_events(minutes)
    except _logs.exceptions.ResourceNotFoundException:
        unavailable = (
            f"the log group {DECISION_LOG_GROUP} does not exist yet. It is "
            "created on deploy but only appears once the first record is "
            "delivered — make a tool call and wait a minute."
        )
        return {
            "decisions": [],
            "unavailable": unavailable,
            **_decision_notes(minutes, groups),
        }

    rows = _group_by_request(events)
    people = _principals()

    decisions = []
    for row in sorted(rows, key=lambda r: r["ts"], reverse=True):
        policy = row["policy"]
        principal = policy.get("principal", {}).get("entityId", "")
        email = people.get(principal, "")

        # Scoped by identity, not tenant — see the docstring. A reviewer sees
        # everything; anyone else sees only decisions about their own sub. The
        # comparison is against the token's sub, so it cannot be spoofed by a
        # query parameter.
        if REVIEWER_GROUP not in groups and principal != claims.get("sub", ""):
            continue

        decision = policy.get("decision", "")
        decisions.append({
            "requestId": row["requestId"],
            "at": row["ts"],
            "tool": (row.get("tool") or "").split("___")[-1],
            "decision": decision,
            "principal": email or principal[:8],
            "determiningPolicies": policy.get("determiningPolicies") or [],
            "reason": policy.get("reason", ""),
            # The contradiction only LOG_ONLY can produce: the policy said DENY
            # and the caller got their data anyway. Named explicitly rather than
            # left for the UI to infer, so both surfaces agree on what it means.
            "succeededDespiteDeny": decision == "DENY" and bool(row.get("succeeded")),
            "blocked": bool(row.get("blocked")),
        })

    notes = _decision_notes(minutes, groups)
    if truncated:
        # Say it rather than let a capped read look like a complete one.
        truncation_note = (
            f"This window holds more than {MAX_EVENTS} log events, so only the "
            "most recent are shown. Narrow the window to see a complete period."
        )
        notes["limits"] = notes["limits"] + [truncation_note]
        notes["truncated"] = True

    return {
        "decisions": decisions,
        "scopedTo": None if REVIEWER_GROUP in groups else (claims.get("email") or "you"),
        **notes,
    }


def _decision_notes(minutes: int, groups: list[str]) -> dict:
    """The caveats that must travel with the trail wherever it is rendered."""
    return {
        "minutes": minutes,
        "tenant": None if REVIEWER_GROUP in groups else "self",
        "limits": [
            "tools/list produces no policy record. It is still enforced — Cedar "
            "filters the listing — so this is a logging gap, not a security one. "
            "There is no trail of what a user could see, only of what they called.",
            "Delivery lags roughly 30-60 seconds, so a call made just now will "
            "not be here yet.",
            f"Enforcement mode is {ENFORCEMENT_MODE}. Under ENFORCE most denials "
            "vanish from this list, because a model that cannot see a tool never "
            "calls it — which is the argument for running LOG_ONLY first.",
        ],
    }


def _log_events(minutes: int) -> tuple[list[dict], bool]:
    """Read the window. Returns (events, truncated).

    filter_log_events pages OLDEST FIRST, so the bound below keeps a sliding
    TAIL rather than stopping early. Stopping early would keep the oldest events
    and silently drop the newest — the exact opposite of what an audit trail is
    read for, and invisible in the UI because the rows are sorted descending
    afterwards either way. It only shows up once the window is wide enough to
    exceed the cap, which is why widening the window to 15 days surfaced it.
    """
    start = int((time.time() - minutes * 60) * 1000)
    events: list[dict] = []
    token = None
    truncated = False
    # Page bound as well as an event bound: an unbounded scan over a busy log
    # group would blow the Lambda timeout and the page would show nothing at
    # all, which is a worse answer than a subset clearly labelled as one.
    for _ in range(MAX_PAGES):
        kwargs: dict[str, Any] = {
            "logGroupName": DECISION_LOG_GROUP,
            "startTime": start,
            "limit": 1000,
        }
        if token:
            kwargs["nextToken"] = token
        page = _logs.filter_log_events(**kwargs)
        events.extend(page.get("events") or [])
        if len(events) > MAX_EVENTS:
            events = events[-MAX_EVENTS:]
            truncated = True
        token = page.get("nextToken")
        if not token:
            return events, truncated
    return events, True


def _group_by_request(events: list[dict]) -> list[dict]:
    """One row per request id, assembled from the several records each call emits.

    Only rows carrying a policy decision are returned — the rest are the request
    and response halves, which are useful only as context for a decision.
    """
    requests: dict[str, dict] = {}
    for event in events:
        try:
            payload = json.loads(event["message"])
        except (json.JSONDecodeError, KeyError):
            continue
        rid = payload.get("request_id", "")
        body = payload.get("body") or {}
        row = requests.setdefault(
            rid, {"requestId": rid, "ts": payload.get("event_timestamp", 0)}
        )

        if body.get("policy"):
            row["policy"] = body["policy"]
        request_body = str(body.get("requestBody", ""))
        if "tools/call" in request_body and "name=" in request_body:
            row["tool"] = request_body.split("name=")[1].split(",")[0].split("}")[0]
        if "result={content" in str(body.get("responseBody", "")):
            row["succeeded"] = True
        if "Denied" in str(body.get("log", "")):
            row["blocked"] = True

    return [r for r in requests.values() if r.get("policy")]


def _principals() -> dict[str, str]:
    """Cognito sub -> email, so the trail names people rather than UUIDs.

    The raw log identifies the caller by sub only. Without this join every row
    reads as an 8-character hex fragment, which is useless to the people the
    audit trail exists for. Failure here is cosmetic and never fails the trail.
    """
    pool_id = os.environ.get("USER_POOL_ID", "")
    if not pool_id:
        return {}
    mapping: dict[str, str] = {}
    try:
        idp = boto3.client("cognito-idp")
        paginator = idp.get_paginator("list_users")
        for page in paginator.paginate(UserPoolId=pool_id):
            for user in page.get("Users") or []:
                attrs = {a["Name"]: a["Value"] for a in user.get("Attributes", [])}
                if "sub" in attrs:
                    mapping[attrs["sub"]] = attrs.get("email", user.get("Username", ""))
    except ClientError:
        logger.warning("could not resolve principals to emails", exc_info=True)
    return mapping


# ------------------------------------------------------------------ writes


def _set_status(event: dict, caller: str, groups: list[str]) -> dict:
    """Approve, reject or deprecate one record.

    Two things are enforced here and both matter:

    · reviewer group membership. Without it a tenant could approve its own
      asset, which would make the dashboard a rubber stamp with a nicer font.
    · a non-empty reason. The API requires statusReason, and that requirement
      is the audit trail — it is the difference between a status flag and a
      record of a decision. Rejecting an empty reason here gives a clearer
      message than letting the service do it.
    """
    if REVIEWER_GROUP not in groups:
        return _json(403, {
            "error": (
                f"only members of the {REVIEWER_GROUP!r} Cognito group may act on "
                "the review queue. Reading the catalogue is open to any "
                "authenticated user; acting on it is not."
            )
        })

    record_id = (event.get("pathParameters") or {}).get("id", "")
    if not record_id:
        return _json(400, {"error": "no record id in the path"})

    try:
        body = json.loads(event.get("body") or "{}")
    except json.JSONDecodeError:
        return _json(400, {"error": "body is not valid JSON"})

    status = str(body.get("status", "")).upper()
    reason = str(body.get("reason", "")).strip()

    if status not in SETTABLE:
        return _json(400, {
            "error": f"status must be one of {sorted(SETTABLE)}; got {status!r}. "
                     "CREATING and the failure states belong to the service."
        })
    if not reason:
        return _json(400, {
            "error": "a reason is required. The API demands it, and it is what "
                     "makes this an audit trail rather than a status flag."
        })

    result = _control.update_registry_record_status(
        registryId=REGISTRY_ID,
        recordId=record_id,
        status=status,
        statusReason=f"{reason} — {caller}",
    )
    logger.info("STATUS CHANGE record=%s -> %s by=%s", record_id, status, caller)
    return _json(200, {
        "id": record_id,
        "status": result.get("status", status),
        "statusReason": f"{reason} — {caller}",
    })


# -------------------------------------------------------- register a new asset


def _register(event: dict, caller: str, tenant: str) -> dict:
    """Add an asset to the catalogue, scanning its description first.

    The order of operations is the whole point: the
    description is scanned BEFORE the record is created, so a refused submission
    leaves nothing behind. There is no poisoned record sitting in DRAFT for
    someone to find later and wonder about.

    Open to any authenticated user — a platform where only reviewers can propose
    an asset is a platform where nobody registers anything. But note what is NOT
    taken from the form:

      · tenant comes from the caller's token, so a tenant cannot register into
        another tenant's namespace.
      · owner comes from the caller's email, so ownership cannot be assigned to
        someone else to dodge a review conversation.

    And the record is created in DRAFT and immediately submitted, which lands it
    in PENDING_APPROVAL. It is NOT approved. Registering a tool is a request for
    review, not an act of governance, and that distinction is enforced by the
    service — DRAFT cannot jump to APPROVED, verified by trying.
    """
    if not tenant:
        # Fail loudly. Without a tenant claim there is nothing to scope the asset
        # to, and creating it unscoped would put a record in the catalogue that
        # no tenant view will ever show — invisible, and indistinguishable from a
        # failed create.
        return _json(403, {
            "error": (
                f"your token carries no {TENANT_CLAIM} claim, so there is no "
                "tenant to register this asset to. Ask an administrator to set "
                "it — the same claim is what Cedar scopes tool calls on."
            )
        })

    try:
        body = json.loads(event.get("body") or "{}")
    except json.JSONDecodeError:
        return _json(400, {"error": "body is not valid JSON"})

    name = str(body.get("name", "")).strip()
    description = str(body.get("description", "")).strip()

    problem = _validate_new_asset(name, description)
    if problem:
        return _json(400, {"error": problem})

    # Checked before the scan so a duplicate gets a clear answer without spending
    # a Guardrails call. The Registry also enforces unique names itself and
    # refuses a duplicate with ConflictException (handled below), so this is a
    # friendlier message, not the guarantee.
    existing = next(
        (r for r in _all_records() if r.get("name") == name), None
    )
    if existing:
        return _json(409, {
            "error": (
                f"an asset named {name!r} is already in the catalogue "
                f"(status {existing.get('status')})."
            )
        })

    # ---- the publish-time scan -------------------------------------------
    verdict = _scan_descriptor(name, description)
    if verdict["blocked"]:
        logger.warning(
            "REGISTRATION REFUSED name=%s by=%s reasons=%s",
            name, caller, verdict["reasons"],
        )
        return _json(422, {
            "error": (
                "This description was flagged as a possible prompt injection, "
                "so the asset was not registered."
            ),
            "scan": verdict,
        })

    if verdict["failed"]:
        # The scan could not run. Fail closed, and say which it was: "refused"
        # and "could not check" are different facts and collapsing them would
        # make an outage look like a detection.
        return _json(503, {
            "error": (
                "The description could not be checked, so nothing was "
                "registered. Please try again later."
            ),
            "scan": verdict,
        })

    # ---- create, then submit for review ---------------------------------
    annotated = f"{description} [tenant: {tenant}, owner: {caller}]"
    try:
        created = _control.create_registry_record(
            registryId=REGISTRY_ID,
            name=name,
            displayName=name,
            description=annotated,
            recordType="MCP",
            descriptors={
                "mcpServer": {
                    # No dataSchemaVersion: the service detects it from the
                    # document — see infra/registry/construct.py.
                    "data": _server_json(name, description),
                    "additionalData": {
                        "tools": {"data": _tools_json(name, description)}
                    },
                }
            },
        )
    except ClientError as exc:
        # Two registrations of the same name racing past the check above: the
        # Registry refuses the second one.
        if exc.response["Error"]["Code"] == "ConflictException":
            return _json(409, {
                "error": f"an asset named {name!r} is already in the catalogue."
            })
        # The 100-character server.json limit reports itself as a version error.
        # Descriptions are truncated for server.json before we get here, so this
        # should not fire — but if it does, saying so beats echoing the API.
        return _json(502, {
            "error": f"the Registry refused the record: {exc}",
            "hint": "if this mentions 'supported version', it is usually the "
                    "100-character server.json description limit, not a version "
                    "problem.",
        })

    # CreateRegistryRecord returns exactly two fields, "recordArn" and "status".
    # There is NO recordId, and the id is the last segment of the ARN.
    #
    # Getting this wrong was the more expensive of the two bugs found testing this
    # endpoint live, because it does not look like a bug: the create succeeded, the
    # response was 201, and record_id was silently "" — so the submit was skipped
    # and the record sat in DRAFT. On screen that reads as "the service left it in
    # draft", which is a plausible thing for a status machine to do. Only counting
    # records in the Registry showed what had actually happened.
    record_id = created.get("recordArn", "").rsplit("/", 1)[-1]

    if not record_id:
        # Never silently skip the submit. If the ARN shape changes again, say so.
        logger.error("no recordArn in create response: %s", sorted(created))
        return _json(502, {
            "error": (
                f"{name} was created but its id could not be read from the "
                "response, so it was not submitted for review. It is in DRAFT — "
                "submit it with scripts/catalogue.py --submit."
            )
        })

    # A newly created record is in CREATING for a few seconds, and submitting
    # during that window is refused with:
    #
    #   ConflictException: Registry record cannot be modified while in CREATING
    #
    # Found live. Note how it presented: the create succeeded, the response said
    # 200, and the record simply sat in DRAFT with a warning — which reads as "the
    # service chose to leave it in draft", a completely plausible thing for a
    # status machine to do. Waiting is the fix, not retrying blindly.
    _wait_out_creating(record_id)

    try:
        submitted = _control.submit_registry_record_for_approval(
            registryId=REGISTRY_ID, recordId=record_id
        ).get("status", "")
    except ClientError as exc:
        # The record exists; only the submit failed. Report both facts rather
        # than a bare error, or the caller retries and hits the name clash.
        logger.warning("created %s but could not submit: %s", record_id, exc)
        return _json(200, {
            "id": record_id,
            "name": name,
            "status": "DRAFT",
            "scan": verdict,
            "warning": (
                "The asset was registered but could not be submitted for "
                "review. It is saved as a draft."
            ),
        })

    logger.info("REGISTERED name=%s by=%s tenant=%s status=%s",
                name, caller, tenant, submitted)
    return _json(201, {
        "id": record_id,
        "name": name,
        "tenant": tenant,
        "owner": caller,
        "status": submitted or "DRAFT",
        "scan": verdict,
        "note": "Submitted for review. It is waiting for a reviewer.",
    })


def _wait_out_creating(record_id: str, *, tries: int = 12, pause: float = 1.0) -> str:
    """Block until a new record leaves CREATING, so it can be submitted.

    Bounded deliberately at ~12 seconds. The Lambda has 60, and a wait that could
    consume all of it would turn a slow registry into a timeout with no response
    at all — worse than the DRAFT-plus-warning this replaces, because at least
    that says what happened. If the wait runs out, the caller still gets a 200
    naming the record and telling them how to submit it by hand.

    Observed settling time is 2-4 seconds. Polling rather than sleeping a fixed
    interval so the common case stays fast.
    """
    status = "CREATING"
    for _ in range(tries):
        try:
            status = _control.get_registry_record(
                registryId=REGISTRY_ID, recordId=record_id
            ).get("status", "")
        except ClientError:
            # Cosmetic: if the Get fails, let the submit below produce the real
            # error rather than inventing one here.
            return status
        if status not in ("CREATING", "UPDATING"):
            return status
        time.sleep(pause)  # nosemgrep: arbitrary-sleep  # bounded poll
    return status


def _validate_new_asset(name: str, description: str) -> str:
    """Reject what the Registry would reject, but with a message that helps.

    Every rule here mirrors one the service enforces. The point is not to add
    policy in the browser — it is that the service's messages for these cases are
    poor, and a form that echoes them teaches nobody anything.
    """
    if not name:
        return "a name is required"
    if not description:
        return (
            "a description is required. It is not a label — it is what the model "
            "reads to decide whether to call this tool, and it is what a reviewer "
            "and the scan both inspect."
        )
    if len(name) > 64:
        return f"the name is {len(name)} characters; the Registry allows 64"
    if not name[0].isalnum() or not all(c.isalnum() or c in "-_" for c in name):
        return (
            f"the name {name!r} must start with a letter or digit and use only "
            "letters, digits, dashes or underscores. "
            "It becomes part of an MCP server identifier, so spaces and "
            "punctuation are not allowed."
        )
    if len(description) > 1024:
        return (
            f"the description is {len(description)} characters; keep it under "
            "1024. The server.json summary is truncated to "
            f"{MAX_SERVER_DESCRIPTION} anyway, and the full text goes in the tools descriptor."
        )
    return ""


def _scan_descriptor(name: str, description: str) -> dict:
    """Run a proposed descriptor through Guardrails. Returns a verdict, never raises.

    source="INPUT" is not incidental and this is the trap worth knowing: the
    PROMPT_ATTACK filter is only evaluated on INPUT. Verified by
    sending a payload Guardrails blocks with HIGH confidence at source=INPUT and
    getting action=NONE for the identical text at source=OUTPUT. No error, no
    warning — the filter simply does not run. A descriptor scan using OUTPUT
    would report clean forever, which is worse than having no scan, because it
    would be reported as a control that works.

    Both the name and the description are scanned together. A payload can hide in
    either, and scanning only the description would leave the obvious gap.
    """
    if not GUARDRAIL_ID:
        return _scan_unavailable("no guardrail is configured for the dashboard")

    try:
        response = _bedrock.apply_guardrail(
            guardrailIdentifier=GUARDRAIL_ID,
            guardrailVersion=GUARDRAIL_VERSION,
            source="INPUT",
            content=[{"text": {"text": f"{name}: {description}"}}],
        )
    except ClientError as exc:
        logger.exception("publish-time guardrail call failed")
        return _scan_unavailable(f"guardrails error: {exc.response['Error']['Code']}")
    except Exception as exc:  # noqa: BLE001 — a timeout must not become a 500
        logger.exception("publish-time guardrail call failed")
        return _scan_unavailable(f"guardrails unavailable: {type(exc).__name__}")

    assessments = response.get("assessments") or []
    latency = None
    if assessments:
        latency = (assessments[0].get("invocationMetrics") or {}).get(
            "guardrailProcessingLatency"
        )

    return {
        "blocked": response.get("action") == "GUARDRAIL_INTERVENED",
        "reasons": _scan_reasons(assessments),
        "latencyMs": latency,
        "failed": False,
        "guardrailId": GUARDRAIL_ID,
    }


def _scan_unavailable(why: str) -> dict:
    """A scan that could not run. Fail closed.

    blocked is False and failed is True, deliberately: the caller then reports
    "could not check" rather than "refused", which are different facts. The
    refusal still happens — _register() turns failed into a 503 — but the message
    says an outage rather than a detection. Collapsing the two is how a control
    that switched itself off gets reported as a control that worked.
    """
    return {
        "blocked": False,
        "reasons": [f"scan could not run ({why})"],
        "latencyMs": None,
        "failed": True,
        "guardrailId": GUARDRAIL_ID,
    }


def _scan_reasons(assessments: list[dict]) -> list[str]:
    """Readable reasons for a refused registration."""
    reasons: list[str] = []
    for assessment in assessments:
        for f in (assessment.get("contentPolicy") or {}).get("filters") or []:
            if f.get("detected"):
                reasons.append(f"{f.get('type')} ({f.get('confidence')} confidence)")
        for t in (assessment.get("topicPolicy") or {}).get("topics") or []:
            if t.get("detected"):
                reasons.append(f"denied topic: {t.get('name')}")
        for w in (assessment.get("wordPolicy") or {}).get("customWords") or []:
            if w.get("match"):
                reasons.append(f"blocked word: {w.get('match')}")
    return reasons


def _server_json(name: str, description: str) -> str:
    """An MCP server.json document, matching infra/registry/construct.py exactly.

    Duplicated rather than shared because this runs in a Lambda and that runs at
    synth time, and importing CDK into a Lambda bundle to share forty lines would
    be the worse trade. The values are pinned identically, and the module
    constants carry the same comments so they cannot drift silently.
    """
    return json.dumps({
        "$schema": MCP_SERVER_SCHEMA,
        "name": f"com.example/{name}",
        "description": _truncate(description, MAX_SERVER_DESCRIPTION),
        "version": "1.0.0",
    })


def _tools_json(name: str, description: str) -> str:
    """The tool list, in the shape an MCP server returns from tools/list.

    The form does not collect an input schema. An empty properties object is
    honest — the asset is a catalogue entry awaiting review, not a wired-up
    target — and inventing arguments would put a descriptor in the catalogue that
    does not match any real tool.
    """
    return json.dumps({
        "tools": [{
            "name": name,
            "description": description,
            "inputSchema": {"type": "object", "properties": {}, "required": []},
        }]
    })


def _truncate(text: str, limit: int) -> str:
    """Shorten to limit characters, breaking on a word where possible.

    Only the server.json summary is truncated; the full description survives in
    the tools descriptor, which has no limit and is the copy a reviewer reads.
    """
    if len(text) <= limit:
        return text
    cut = text[: limit - 1]
    if " " in cut:
        cut = cut.rsplit(" ", 1)[0]
    return cut + "…"


# ------------------------------------------------------------------ helpers


def _claims(event: dict) -> dict:
    """The JWT claims the HTTP API authorizer already validated.

    No token parsing here: API Gateway's JWT authorizer has verified the
    signature, issuer and audience before this Lambda runs. Re-parsing would
    invite the mistake of trusting an unverified token.
    """
    authorizer = (event.get("requestContext") or {}).get("authorizer") or {}
    return (authorizer.get("jwt") or {}).get("claims") or {}


def _wrong_token_type(claims: dict) -> str:
    """Refuse an access token, loudly, and say which token to send instead.

    Tested live, and this is the failure worth guarding: the JWT authorizer
    ACCEPTS a Cognito access token — right issuer, right audience, valid
    signature — but an access token carries no email and no custom:tenant. The
    request therefore sailed through and returned an empty table with a blank
    viewer and no error, which reads as "the catalogue is empty" or "my account
    has no assets". Both are wrong and both send you debugging the Registry.

    The Gateway already refuses access tokens (403 insufficient_scope, because
    Cedar cannot find a tenant to scope on), so ONE rule holds platform-wide:
    send the ID token. This makes the dashboard say that in the same terms
    rather than degrading quietly.
    """
    if claims.get("token_use") == "access":
        return (
            "this is a Cognito ACCESS token; send the ID token. An access token "
            "passes signature and audience checks but carries no email and no "
            f"{TENANT_CLAIM} claim, so there is nothing to scope the catalogue "
            "to. The Gateway refuses access tokens for the same reason — one "
            "rule, both surfaces."
        )
    if not claims:
        return (
            "no verified claims on the request. The JWT authorizer admitted it, "
            "which should not happen — check the Authorization header format "
            "(it must be 'Bearer <token>')."
        )
    return ""


def _groups(claims: dict) -> list[str]:
    """cognito:groups arrives as a JSON array OR a bracketed string.

    Both shapes are real depending on how the token is minted, and assuming one
    means group membership silently evaluates false — which fails CLOSED here
    (no writes), so it would look like a permissions bug rather than a parsing
    bug. Handle both.
    """
    raw = claims.get("cognito:groups", "")
    if isinstance(raw, list):
        return raw
    return [g for g in str(raw).strip("[]").replace(",", " ").split() if g]


def _may_see_everything(groups: list[str]) -> bool:
    """Reviewers see the whole catalogue; everyone else sees their tenant.

    A platform reviewer needs the full inventory or the asset register is
    pointless. This is application logic, not Cedar — see the module docstring.
    """
    return REVIEWER_GROUP in groups


def _iso(value: Any) -> str:
    return value.isoformat() if hasattr(value, "isoformat") else str(value or "")


def _json(status: int, body: dict) -> dict:
    return {
        "statusCode": status,
        "headers": {"content-type": "application/json"},
        "body": json.dumps(body, default=str),
    }
