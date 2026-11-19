# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""finance-reports tool — a stand-in for a real finance system.

Reached only through the AgentCore Gateway. Cedar decides whether the caller
is allowed here; by the time this runs, that decision has been made.

Note on the MCP protocol: with a LAMBDA gateway target, the Gateway holds the
tool schema itself (declared inline in the CDK) and only ever invokes us for
tools/call. There is no tools/list branch here because it would be dead code.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Stand-in data. A real implementation would query a warehouse.
REPORTS: dict[str, dict[str, Any]] = {
    "q1": {"period": "Q1 2026", "revenue_gbp": 4_210_000, "opex_gbp": 3_050_000},
    "q2": {"period": "Q2 2026", "revenue_gbp": 4_780_000, "opex_gbp": 3_120_000},
}


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Return a finance report for the requested quarter."""
    logger.info("invoked: %s", json.dumps(event)[:600])

    args = _arguments(event)
    quarter = str(args.get("quarter", "q2")).lower().strip()

    report = REPORTS.get(quarter)
    if report is None:
        return _error(
            f"No report for {quarter!r}. Available: {', '.join(sorted(REPORTS))}."
        )

    payload = {
        **report,
        "margin_gbp": report["revenue_gbp"] - report["opex_gbp"],
        "source": "finance-reports",
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    return _text(payload)


def _arguments(event: dict[str, Any]) -> dict[str, Any]:
    """Pull tool arguments out of the event.

    The Gateway's invocation shape is not contractually pinned, so accept both
    a bare argument dict and a params/arguments envelope rather than assuming.
    """
    if isinstance(event.get("arguments"), dict):
        return event["arguments"]
    params = event.get("params")
    if isinstance(params, dict) and isinstance(params.get("arguments"), dict):
        return params["arguments"]
    return {k: v for k, v in event.items() if k not in {"method", "params"}}


def _text(payload: dict[str, Any]) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": json.dumps(payload, indent=2)}]}


def _error(message: str) -> dict[str, Any]:
    return {"isError": True, "content": [{"type": "text", "text": message}]}
