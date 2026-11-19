#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""The catalogue, and the review queue.

    .venv/bin/python scripts/catalogue.py                    # what have we got?
    .venv/bin/python scripts/catalogue.py --submit finance-reports
    .venv/bin/python scripts/catalogue.py --approve finance-reports \
        --reason "Descriptions clean, owner confirmed"
    .venv/bin/python scripts/catalogue.py --reject jira-search \
        --reason "Tool description reads like an instruction to the model"

WHAT THIS DOES AND DOES NOT PROVE

Be careful how you read this. The Gateway does not consult the Registry —
there is no registry field on CreateGatewayTarget, and both targets on this
platform served traffic for three days before the registry existed. So a
REJECTED record does not make a tool unreachable. Cedar does that.

What this genuinely shows is the thing customers currently do in a spreadsheet:
every AI asset, its owner, and whether a human signed it off — with the
sign-off enforced by the service rather than by convention. Three properties
below are real, server-side, and were each verified by trying to violate them:

  · DRAFT cannot jump to APPROVED
  · REJECTED is terminal and cannot be resubmitted
  · editing an APPROVED record silently drops it back to DRAFT

The third is the one worth pausing on. An approval cannot outlive the content it
approved, which is exactly the failure mode a spreadsheet has.
"""

from __future__ import annotations

import argparse
import json
import sys
import time

import boto3
from botocore.exceptions import ClientError

STACK = "AiGovernanceGateway"

# Status -> how it reads in the queue. The point of the symbols is that a
# reviewer should be able to see what needs them at a glance.
MARKS = {
    "APPROVED": "OK  ",
    "PENDING_APPROVAL": "WAIT",
    "DRAFT": "draft",
    "REJECTED": "NO  ",
    "DEPRECATED": "old ",
    "CREATING": "... ",
    "UPDATING": "... ",
    "CREATE_FAILED": "FAIL",
}


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--region", default="us-east-1")
    p.add_argument("--submit", metavar="RECORD", help="send a DRAFT record for review")
    p.add_argument("--approve", metavar="RECORD")
    p.add_argument("--reject", metavar="RECORD")
    p.add_argument("--deprecate", metavar="RECORD")
    p.add_argument(
        "--reason",
        help="required by the API for approve/reject/deprecate — it becomes the audit trail",
    )
    p.add_argument("--show", metavar="RECORD", help="print one record's full descriptor")
    args = p.parse_args()

    session = boto3.Session(region_name=args.region)
    control = session.client("agent-registry-control")

    registry_id = _registry_id(session, args.region)
    if registry_id is None:
        return 1

    records = _records(control, registry_id)
    if records is None:
        return 1

    action = _requested_action(args)
    if action:
        verb, name = action
        if not _apply(control, registry_id, records, verb, name, args.reason):
            return 1
        # Status changes are quick but not instant, and showing a stale queue
        # right after acting on it is worse than a short pause.
        time.sleep(3)  # nosemgrep: arbitrary-sleep  # deliberate pause, see above
        records = _records(control, registry_id) or records

    if args.show:
        return _show(control, registry_id, records, args.show)

    _report(_with_reasons(control, registry_id, records))
    return 0


def _requested_action(args) -> tuple[str, str] | None:
    for verb in ("submit", "approve", "reject", "deprecate"):
        name = getattr(args, verb)
        if name:
            return verb, name
    return None


def _registry_id(session, region: str) -> str | None:
    """Find the registry from the deployed stack's output.

    Read from CloudFormation rather than governance.yaml so this reports on what
    is actually deployed. A name in the config file that was never deployed
    would otherwise produce a confident, wrong, empty catalogue.
    """
    cfn = session.client("cloudformation")
    try:
        outputs = cfn.describe_stacks(StackName=STACK)["Stacks"][0].get("Outputs", [])
    except ClientError as exc:
        print(f"could not read stack {STACK}: {exc}", file=sys.stderr)
        return None

    arn = next((o["OutputValue"] for o in outputs if o["OutputKey"] == "RegistryArn"), None)
    if not arn:
        print(
            f"stack {STACK} has no RegistryArn output — deploy the registry, or add a "
            "registry section to governance.yaml.",
            file=sys.stderr,
        )
        return None
    return arn.rsplit("/", 1)[-1]


def _records(control, registry_id: str) -> list[dict] | None:
    """Every record in the registry.

    ListRegistryRecords returns every record regardless of status, which is what
    a reviewer needs. For discovery of approved records, AWS Agent Registry also
    offers hybrid semantic and keyword search (SearchDiscoverableRegistryRecords)
    and an MCP endpoint; this sample does not use them.

    The response key is "registryRecords", NOT "items" — worth stating because
    the failure is silent and misleading. `--query 'items[]'` returns null, which
    reads as "the registry is empty" rather than "you asked for the wrong key",
    and it briefly convinced me a cleanup had succeeded when a record was still
    sitting there.
    """
    try:
        items: list[dict] = []
        token = None
        while True:
            kwargs = {"registryId": registry_id, "maxResults": 50}
            if token:
                kwargs["nextToken"] = token
            page = control.list_registry_records(**kwargs)
            items.extend(page.get("registryRecords") or [])
            token = page.get("nextToken")
            if not token:
                return items
    except ClientError as exc:
        print(f"could not list records: {exc}", file=sys.stderr)
        return None


def _with_reasons(control, registry_id: str, records: list[dict]) -> list[dict]:
    """Fill in statusReason, which ListRegistryRecords does not return.

    The list response carries status but NOT statusReason — only
    GetRegistryRecord does. So the reason a thing was approved or rejected, which
    is the entire audit value of the workflow, is invisible in the listing. One
    Get per record is fine for a catalogue this size and would need revisiting
    for a large one.
    """
    filled = []
    for record in records:
        if record.get("statusReason"):
            filled.append(record)
            continue
        try:
            full = control.get_registry_record(
                registryId=registry_id, recordId=record["recordId"]
            )
            filled.append({**record, "statusReason": full.get("statusReason")})
        except ClientError:
            # Cosmetic only — never fail the report over a missing reason.
            filled.append(record)
    return filled


def _find(records: list[dict], name: str) -> dict | None:
    for r in records:
        if r.get("name") == name or r.get("recordId") == name:
            return r
    return None


def _apply(control, registry_id: str, records: list[dict], verb: str,
           name: str, reason: str | None) -> bool:
    record = _find(records, name)
    if record is None:
        known = ", ".join(sorted(r.get("name", "?") for r in records)) or "none"
        print(f"no record named {name!r}. Records in this registry: {known}", file=sys.stderr)
        return False

    record_id = record["recordId"]
    status = record.get("status")

    if verb == "submit":
        try:
            result = control.submit_registry_record_for_approval(
                registryId=registry_id, recordId=record_id
            )
        except ClientError as exc:
            # The common case is a REJECTED record, which is terminal. Say so,
            # rather than echoing the API's own wording and leaving the reader
            # to work out that retrying will never help.
            print(f"cannot submit {name!r} (status {status}): {exc}", file=sys.stderr)
            if status == "REJECTED":
                print(
                    "  REJECTED is terminal — a rejected record cannot be "
                    "resubmitted. Create a new record instead.",
                    file=sys.stderr,
                )
            return False

        new = result.get("status")
        print(f"{name}: {status} -> {new}")
        if new == "APPROVED":
            print(
                "  Approved on submit, because this registry has "
                "auto_approval: true. No human looked at it."
            )
        else:
            print("  Waiting for a human. Nothing approved it automatically.")
        return True

    target = {"approve": "APPROVED", "reject": "REJECTED", "deprecate": "DEPRECATED"}[verb]

    if not reason:
        print(
            f"--reason is required to {verb} — the API demands it, and it is what "
            "makes the record an audit trail rather than a status flag.",
            file=sys.stderr,
        )
        return False

    try:
        result = control.update_registry_record_status(
            registryId=registry_id,
            recordId=record_id,
            status=target,
            statusReason=reason,
        )
    except ClientError as exc:
        print(f"cannot {verb} {name!r} (status {status}): {exc}", file=sys.stderr)
        if status == "DRAFT" and target == "APPROVED":
            print(
                "  The status machine is enforced by the service: DRAFT cannot go "
                "straight to APPROVED. Submit it for approval first.",
                file=sys.stderr,
            )
        return False

    print(f"{name}: {status} -> {result.get('status')}")
    print(f"  reason recorded: {reason}")
    return True


def _show(control, registry_id: str, records: list[dict], name: str) -> int:
    record = _find(records, name)
    if record is None:
        print(f"no record named {name!r}", file=sys.stderr)
        return 1

    full = control.get_registry_record(registryId=registry_id, recordId=record["recordId"])
    print(f"{full['name']}  [{full['status']}]")
    print(f"  {full.get('description', '')}")
    if full.get("statusReason"):
        print(f"  reason: {full['statusReason']}")
    print(f"  created {full['createdAt']:%Y-%m-%d %H:%M}  updated {full['updatedAt']:%Y-%m-%d %H:%M}")

    server = (full.get("descriptors") or {}).get("mcpServer") or {}
    tools = (server.get("additionalData") or {}).get("tools") or {}
    for part, section in (("server", server), ("tools", tools)):
        if not section:
            continue
        version = section.get("dataSchemaVersion")
        print(f"\n  {part}  (version {version} — assigned by the service, not by us)")
        try:
            body = json.loads(section.get("data") or "{}")
            for line in json.dumps(body, indent=2).splitlines():
                print(f"    {line}")
        except json.JSONDecodeError:
            print(f"    {section.get('data')}")
    return 0


def _report(records: list[dict]) -> None:
    if not records:
        print("The catalogue is empty.")
        return

    print(f"\n  {'ASSET':<18} {'':<5} {'STATUS':<17} REVIEWED BECAUSE")
    print(f"  {'-' * 18} {'-' * 5} {'-' * 17} {'-' * 30}")

    for r in sorted(records, key=lambda x: x.get("name", "")):
        status = r.get("status", "?")
        reason = r.get("statusReason") or ""
        if len(reason) > 44:
            reason = reason[:41] + "..."
        print(f"  {r.get('name', '?'):<18} {MARKS.get(status, '?'):<5} {status:<17} {reason}")

    counts: dict[str, int] = {}
    for r in records:
        counts[r.get("status", "?")] = counts.get(r.get("status", "?"), 0) + 1

    waiting = counts.get("PENDING_APPROVAL", 0)
    drafts = counts.get("DRAFT", 0)
    print()
    if waiting:
        print(f"{waiting} asset(s) waiting on a human. Nothing approves itself.")
    if drafts:
        print(f"{drafts} asset(s) in DRAFT — never submitted for review.")
    if not waiting and not drafts:
        print("Nothing waiting for review.")

    print(
        "\nNote: an APPROVED record is a review record, not a gate. The Gateway "
        "does not\nconsult the Registry — Cedar decides what is reachable. "
        "Editing an approved\nrecord does drop it back to DRAFT, so an approval "
        "cannot outlive its content."
    )


if __name__ == "__main__":
    sys.exit(main())
