# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""jira-search tool — a stand-in for a real Jira integration.

The sample's second tenant. Deliberately the sort of tool a developer's agent
would reach for, because that is the kind of access this sample governs.

See the note in finance_reports/handler.py on why there is no tools/list here.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ISSUES: list[dict[str, Any]] = [
    {"key": "PLAT-418", "summary": "Gateway returns 403 on token refresh", "status": "In Progress"},
    {"key": "PLAT-402", "summary": "Add tenant claim to CI service account", "status": "Done"},
    {"key": "DATA-77", "summary": "Nightly warehouse load times out", "status": "Open"},
]


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Return Jira issues matching a substring query."""
    logger.info("invoked: %s", json.dumps(event)[:600])

    args = _arguments(event)
    query = str(args.get("query", "")).lower().strip()
    # "*" lists everything. An empty string would too, but the prompt-injection
    # guardrail rule cannot score an empty argument and refuses the call, so
    # callers are told to send "*" instead (see governance.yaml).
    if query == "*":
        query = ""

    matches = [
        i for i in ISSUES
        if not query or query in i["summary"].lower() or query in i["key"].lower()
    ]

    return _text({
        "query": query or "(all)",
        "count": len(matches),
        "issues": matches,
        "source": "jira-search",
        "generated_at": datetime.now(timezone.utc).isoformat(),
    })


def _arguments(event: dict[str, Any]) -> dict[str, Any]:
    """Pull tool arguments out of the event. See finance_reports for rationale."""
    if isinstance(event.get("arguments"), dict):
        return event["arguments"]
    params = event.get("params")
    if isinstance(params, dict) and isinstance(params.get("arguments"), dict):
        return params["arguments"]
    return {k: v for k, v in event.items() if k not in {"method", "params"}}


def _text(payload: dict[str, Any]) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": json.dumps(payload, indent=2)}]}
