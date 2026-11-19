#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Put the registry records back to their starting state.

    .venv/bin/python scripts/reset-registry.py --dry-run     # what would change
    .venv/bin/python scripts/reset-registry.py               # do it

WHY THIS EXISTS

Trying the sample changes registry state. Approving the pending record leaves
nothing in the review queue, and registering a tool through the dashboard leaves
a record behind, so a second registration with the same name is refused as a
duplicate.

So this restores two things:

  · one asset back in PENDING_APPROVAL, so the review queue is not empty
  · any record NOT declared in governance.yaml is DELETED, so the registration
    can be tried again with the same tool name. Use --dry-run first.

THE PART THAT IS NOT OBVIOUS

There is no "reset" in the Registry API, and the status machine refuses every
shortcut. Both of these were tried on the live service and both are refused
server-side:

    update-registry-record-status --status PENDING_APPROVAL
      -> ValidationException: Invalid target status: PENDING_APPROVAL
    submit-registry-record-for-approval  (from APPROVED)
      -> ValidationException: Cannot submit the record for approval in current
         status: APPROVED

The only route back is a service behaviour: editing an APPROVED record drops it
to DRAFT and NULLs its statusReason. A DRAFT record can then be submitted. So
_nudge_to_draft() writes the description, waits for UPDATING to clear, writes
the ORIGINAL description back, and submits.

Two details in that which cost time:

  · the edit must be a REAL change. Writing the identical description back is
    accepted — HTTP 200, no error — and the status does not move. So the nudge
    appends a space first, then restores. A no-op write looks like a working
    reset that quietly did nothing.
  · UpdateRegistryRecord takes a different parameter shape from create:
    description={"optionalValue": "..."} rather than a plain string. And the AWS
    CLI cannot send these descriptions at all, because "[tenant: finance, owner:
    x]" parses as CLI shorthand syntax. Hence boto3, not `aws`.

That the reset has to go the long way round is itself the point: an approval
cannot be conjured, un-conjured, or back-dated. The service
holds the lifecycle, not this script.
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

import boto3
import yaml
from botocore.exceptions import ClientError

STACK = "AiGovernanceGateway"

# The starting state. Deliberately a MIX rather than everything
# pending: the screen is more honest and more interesting when it shows one asset
# a human has signed off next to one still waiting, because that is what a real
# register looks like. jira-search is the one left waiting because it belongs to
# sarah@company.com, who is NOT in the reviewer group — so the sample can also show
# that an owner cannot approve their own asset.
STARTING_STATE = {
    "finance-reports": "APPROVED",
    "jira-search": "PENDING_APPROVAL",
}

# The reason written when this script approves something, marked so nobody
# mistakes it for a human's words in the audit trail.
RESET_REASON = "Reviewed at deployment — restored by scripts/reset-registry.py"

# Statuses the service will not move a record out of. Reported rather than
# retried, because retrying a terminal status forever is how a reset script
# becomes the thing you debug instead of the real problem.
TERMINAL = {"REJECTED"}


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--region", default="us-east-1")
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="say what would change and change nothing",
    )
    p.add_argument(
        "--keep-extras",
        action="store_true",
        help="leave records that governance.yaml does not declare (default: delete them)",
    )
    args = p.parse_args()

    session = boto3.Session(region_name=args.region)
    control = session.client("agent-registry-control")

    registry_id = _registry_id(session)
    if registry_id is None:
        return 1

    declared = _declared_tools()
    records = _records(control, registry_id)
    if records is None:
        return 1

    print(f"registry : {registry_id}")
    print(f"records  : {len(records)}")
    print(f"mode     : {'DRY RUN — nothing will change' if args.dry_run else 'applying'}\n")

    failures = 0

    for name, want in STARTING_STATE.items():
        record = _find(records, name)
        if record is None:
            print(f"  ! {name}: not in the registry — deploy the stack first")
            failures += 1
            continue
        if not _drive(control, registry_id, record, want, dry_run=args.dry_run):
            failures += 1

    extras = [
        r for r in records
        if r.get("name") not in declared and r.get("name") not in STARTING_STATE
    ]
    if extras and args.keep_extras:
        print(f"\n  {len(extras)} undeclared record(s) left in place (--keep-extras):")
        for r in extras:
            print(f"      {r.get('name')}  [{r.get('status')}]")
    elif extras:
        print()
        for r in extras:
            failures += 0 if _delete(control, registry_id, r, dry_run=args.dry_run) else 1

    print()
    if failures:
        print(f"{failures} item(s) could not be reset — see above.")
        return 1

    print("Starting state restored. The review queue has something in it again.")
    print(
        "Reminder: this moved records through the SERVICE's status machine, the "
        "long way round.\nThere is no API that sets PENDING_APPROVAL directly, "
        "which is why an approval here\ncannot be faked or back-dated."
    )
    return 0


# ------------------------------------------------------------- the state machine


def _drive(control, registry_id: str, record: dict, want: str, *, dry_run: bool) -> bool:
    """Move one record to the wanted status, using only routes the service allows."""
    name = record.get("name", "?")
    record_id = record["recordId"]
    status = record.get("status", "?")

    if status == want:
        print(f"  = {name}: already {status}")
        return True

    if status in TERMINAL:
        print(
            f"  ! {name}: {status} is terminal and enforced server-side. A rejected "
            f"record cannot be revived — delete it and redeploy the stack."
        )
        return False

    if dry_run:
        print(f"  ~ {name}: {status} -> {want} (would use {_route(status, want)})")
        return True

    print(f"  · {name}: {status} -> {want}")

    try:
        # APPROVED is a dead end for anything except deprecation, so the first
        # move is always back to DRAFT via an edit. See the module docstring.
        if status == "APPROVED":
            status = _nudge_to_draft(control, registry_id, record)

        if status == "DRAFT":
            result = control.submit_registry_record_for_approval(
                registryId=registry_id, recordId=record_id
            )
            status = _settle(control, registry_id, record_id, result.get("status", status))
            print(f"      submitted -> {status}")

        if status == "PENDING_APPROVAL" and want == "APPROVED":
            control.update_registry_record_status(
                registryId=registry_id,
                recordId=record_id,
                status="APPROVED",
                statusReason=RESET_REASON,
            )
            status = _settle(control, registry_id, record_id, "APPROVED")
            print(f"      approved -> {status}")
    except ClientError as exc:
        print(f"      failed: {exc}")
        return False

    if status != want:
        print(f"      ended at {status}, wanted {want}")
        return False
    return True


def _route(status: str, want: str) -> str:
    """What _drive would do, for --dry-run to print."""
    steps = []
    if status == "APPROVED":
        steps.append("edit (drops to DRAFT)")
        status = "DRAFT"
    if status == "DRAFT":
        steps.append("submit")
        status = "PENDING_APPROVAL"
    if status == "PENDING_APPROVAL" and want == "APPROVED":
        steps.append("approve with a reason")
    return " then ".join(steps) or "nothing"


def _nudge_to_draft(control, registry_id: str, record: dict) -> str:
    """Edit an APPROVED record so the service drops it to DRAFT, then undo the edit.

    The edit has to be real — writing the same description back returns 200 and
    leaves the status alone. So this appends a space, waits for the status to
    settle, then writes the original text back. Both writes go through UPDATING,
    and the record lands on DRAFT with statusReason NULLed, which is precisely
    what a reviewable record should look like.

    The description is verified afterwards rather than assumed: if the restore
    failed the record would carry a trailing space forever, which is invisible on
    screen and would quietly diverge the catalogue from what the Gateway
    advertises.
    """
    record_id = record["recordId"]
    original = control.get_registry_record(
        registryId=registry_id, recordId=record_id
    )["description"]

    control.update_registry_record(
        registryId=registry_id,
        recordId=record_id,
        description={"optionalValue": original + " "},
    )
    _settle(control, registry_id, record_id, "UPDATING")

    control.update_registry_record(
        registryId=registry_id,
        recordId=record_id,
        description={"optionalValue": original},
    )
    status = _settle(control, registry_id, record_id, "UPDATING")

    final = control.get_registry_record(registryId=registry_id, recordId=record_id)
    if final["description"] != original:
        print(
            "      ! the description was not restored exactly. The catalogue has "
            "drifted from what\n        the Gateway advertises — check the record "
            "before relying on it."
        )
    print(f"      edited -> {status} (approval dropped, statusReason cleared)")
    return status


def _settle(control, registry_id: str, record_id: str, seen: str,
            *, tries: int = 20, pause: float = 2.0) -> str:
    """Wait out UPDATING/CREATING and return the status the record landed on.

    Registry status changes are quick but not synchronous, and acting on a record
    mid-transition gets a ValidationException naming a status that has already
    changed — which reads as a logic bug rather than a timing one.
    """
    status = seen
    for _ in range(tries):
        status = control.get_registry_record(
            registryId=registry_id, recordId=record_id
        )["status"]
        if status not in ("UPDATING", "CREATING"):
            return status
        time.sleep(pause)  # nosemgrep: arbitrary-sleep  # bounded poll
    return status


def _delete(control, registry_id: str, record: dict, *, dry_run: bool) -> bool:
    """Remove a record governance.yaml does not declare.

    These are what the register form created. Deleting them is the point of the
    reset — registration is by name, and a leftover
    record with that name makes the second run fail for a reason that has nothing
    to do with governance.

    Only undeclared records are touched. Anything in governance.yaml belongs to
    CloudFormation, and deleting it out from under the stack would leave the next
    `cdk deploy` trying to update a record that no longer exists.
    """
    name = record.get("name", "?")
    if dry_run:
        print(f"  ~ {name}: undeclared, would DELETE (created by the register form)")
        return True
    try:
        control.delete_registry_record(registryId=registry_id, recordId=record["recordId"])
    except ClientError as exc:
        print(f"  ! {name}: could not delete: {exc}")
        return False
    print(f"  - {name}: deleted (undeclared — created by the register form)")
    return True


# -------------------------------------------------------------------- lookups


def _registry_id(session) -> str | None:
    """The deployed registry, read from the stack output rather than the config.

    Same reasoning as scripts/catalogue.py: a registry name that exists in
    governance.yaml but was never deployed would otherwise produce a confident
    reset of nothing.
    """
    cfn = session.client("cloudformation")
    try:
        outputs = cfn.describe_stacks(StackName=STACK)["Stacks"][0].get("Outputs", [])
    except ClientError as exc:
        print(f"could not read stack {STACK}: {exc}", file=sys.stderr)
        return None
    arn = next((o["OutputValue"] for o in outputs if o["OutputKey"] == "RegistryArn"), None)
    if not arn:
        print(f"stack {STACK} has no RegistryArn output — deploy the stack.", file=sys.stderr)
        return None
    return arn.rsplit("/", 1)[-1]


def _declared_tools() -> set[str]:
    """Tool names governance.yaml declares — i.e. the ones CloudFormation owns."""
    cfg = yaml.safe_load((Path(__file__).parent.parent / "governance.yaml").read_text())
    return {t["name"] for t in cfg.get("tools") or []}


def _records(control, registry_id: str) -> list[dict] | None:
    """Every record. The key is "registryRecords", not "items" — see catalogue.py."""
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


def _find(records: list[dict], name: str) -> dict | None:
    for r in records:
        if r.get("name") == name:
            return r
    return None


if __name__ == "__main__":
    sys.exit(main())
