#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Show what the policy engine decided.

    export AWS_PROFILE=<your-profile>
    python3 scripts/decisions.py                 # last 15 minutes
    python3 scripts/decisions.py --minutes 60
    python3 scripts/decisions.py --denied-only

Run it under LOG_ONLY and the output is the whole argument for the mode:

    23:51:44  finance-reports   DENY   sarah@company.com   ← BUT THE CALL SUCCEEDED

The policy said no. Nothing was blocked. It was written down anyway. That is a
platform team's dry run — you learn exactly who a new policy would break before
it breaks them, and the answer is evidence rather than a guess.

Flip to ENFORCE, run again, and the same line reads `DENY ... blocked`.

WHY THIS SCRIPT EXISTS AT ALL: nothing is recorded by default. AgentCore creates
no log groups; an account with a fully-enforcing Gateway has zero of them until
CloudWatch log *delivery* is configured. infra/gateway/observability.py does
that, and this reads the result.

Two honest limits, both visible in the output:

  · `tools/list` produces NO policy record. It is still ENFORCED — Cedar filters
    the listing, verified — so this is a logging gap, not a security one. But it
    means there is no audit trail of what each user could SEE, only of what they
    called. Under ENFORCE the interesting denials mostly vanish from the log,
    because a model that can't see a tool never calls it. Which is the real
    argument for running LOG_ONLY first.

  · The log identifies the caller by Cognito `sub` UUID, not email and not
    tenant. This script joins against the user pool to make it readable; the raw
    record does not.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import boto3
import yaml

REGION = "us-east-1"
STACK = "AiGovernanceGateway"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--minutes", type=int, default=15)
    ap.add_argument("--region", default=REGION)
    ap.add_argument("--denied-only", action="store_true")
    args = ap.parse_args()

    cf = boto3.client("cloudformation", region_name=args.region)
    outputs = {
        o["OutputKey"]: o["OutputValue"]
        for o in cf.describe_stacks(StackName=STACK)["Stacks"][0].get("Outputs", [])
    }
    log_group = outputs.get("DecisionLogGroup")
    mode = outputs.get("EnforcementMode", "?")
    if not log_group:
        print(f"stack {STACK} has no DecisionLogGroup output; is decision log delivery deployed?")
        return 1

    print(f"mode : {mode}")
    print(f"log  : {log_group}\n")

    people = _principals(args.region)
    events = _events(args.region, log_group, args.minutes)

    # Group by request id. A single tools/call emits several records, and the
    # decision and the outcome are in DIFFERENT ones — which is the whole point
    # under LOG_ONLY, where a DENY sits alongside a successful response.
    requests: dict[str, dict] = {}
    for e in events:
        try:
            payload = json.loads(e["message"])
        except json.JSONDecodeError:
            continue
        rid = payload.get("request_id", "")
        body = payload.get("body", {})
        rec = requests.setdefault(rid, {"ts": payload.get("event_timestamp", 0)})

        if body.get("policy"):
            rec["policy"] = body["policy"]
        request_body = str(body.get("requestBody", ""))
        if "tools/call" in request_body and "name=" in request_body:
            rec["tool"] = request_body.split("name=")[1].split(",")[0].split("}")[0]
        if "result={content" in str(body.get("responseBody", "")):
            rec["succeeded"] = True
        if "Denied" in str(body.get("log", "")):
            rec["blocked"] = True

    decided = sorted(
        (r for r in requests.values() if r.get("policy")),
        key=lambda r: r["ts"],
    )
    if not decided:
        print(f"No policy decisions in the last {args.minutes} minutes.")
        print("Note: only tools/call is evaluated, and delivery lags ~30-60s.")
        return 0

    shown = 0
    contradictions = 0
    for rec in decided:
        policy = rec["policy"]
        decision = policy["decision"]
        if args.denied_only and decision != "DENY":
            continue

        when = time.strftime("%H:%M:%S", time.localtime(rec["ts"] / 1000))
        tool = (rec.get("tool") or "?").split("___")[-1]
        who = people.get(policy["principal"]["entityId"], policy["principal"]["entityId"][:8])
        by = ", ".join(policy.get("determiningPolicies") or [])

        # The contradiction that only LOG_ONLY can produce: policy says DENY,
        # and the caller got their data anyway.
        if decision == "DENY" and rec.get("succeeded"):
            outcome = "← BUT THE CALL SUCCEEDED"
            contradictions += 1
        elif decision == "DENY":
            outcome = "blocked"
        else:
            outcome = "allowed"

        print(f"  {when}  {tool:<16} {decision:<5}  {who:<22} {outcome}")
        if by:
            print(f"            {'':16} permitted by {by}")
        elif decision == "DENY":
            print(f"            {'':16} {policy.get('reason', '')}")
        shown += 1

    print(f"\n{shown} decision(s) in the last {args.minutes} minutes.")
    if contradictions:
        print(
            f"\n{contradictions} call(s) the policy would have REFUSED were allowed "
            f"through and recorded.\nThat is LOG_ONLY doing its job: this is the "
            f"list of people a switch to ENFORCE\nwould affect, known before "
            f"anyone's work breaks."
        )
    return 0


def _principals(region: str) -> dict[str, str]:
    """Map Cognito sub -> email, so the output names people rather than UUIDs."""
    cfg = yaml.safe_load((Path(__file__).parent.parent / "governance.yaml").read_text())
    idp = boto3.client("cognito-idp", region_name=region)
    mapping: dict[str, str] = {}
    try:
        paginator = idp.get_paginator("list_users")
        for page in paginator.paginate(UserPoolId=cfg["cognito"]["user_pool_id"]):
            for user in page["Users"]:
                attrs = {a["Name"]: a["Value"] for a in user.get("Attributes", [])}
                if "sub" in attrs:
                    mapping[attrs["sub"]] = attrs.get("email", user["Username"])
    except Exception as exc:  # noqa: BLE001 — cosmetic; never fail the report
        print(f"(could not resolve principals to emails: {exc})\n")
    return mapping


def _events(region: str, log_group: str, minutes: int) -> list[dict]:
    cw = boto3.client("logs", region_name=region)
    start = int((time.time() - minutes * 60) * 1000)
    events: list[dict] = []
    token = None
    while True:
        kwargs = {"logGroupName": log_group, "startTime": start, "limit": 1000}
        if token:
            kwargs["nextToken"] = token
        try:
            resp = cw.filter_log_events(**kwargs)
        except cw.exceptions.ResourceNotFoundException:
            print(f"log group {log_group} does not exist yet — deploy the stack, then make a tool call")
            return []
        events.extend(resp.get("events", []))
        token = resp.get("nextToken")
        if not token:
            return events


if __name__ == "__main__":
    sys.exit(main())
