# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Make the Gateway's policy decisions visible.

Without this, there is no record of anything. AgentCore creates no log groups of
its own: an account with a busy, fully-enforcing Gateway has zero log groups
until someone wires up CloudWatch Logs *delivery* (the "vended logs" mechanism —
a delivery source, a delivery destination, and a delivery joining them).

That matters more than it sounds, because `LOG_ONLY` mode is worthless without
it. The whole point of LOG_ONLY is to answer "what would this policy have
blocked?" before it can break anyone's day — and if nothing is being delivered,
the answer is silently "we have no idea".

Verified by experiment on 2026-08-05:

  · Log types the Gateway accepts: TRACES, APPLICATION_LOGS, USAGE_LOGS.
    Policy decisions arrive in APPLICATION_LOGS. There is no dedicated
    POLICY_DECISIONS or AUDIT_LOGS type — those names are rejected outright.

  · The policy engine is NOT a valid delivery source. Only
    [code-interpreter, memory, payment-manager, workload-identity,
    code-interpreter-custom, runtime, gateway] are, so decisions can only be
    observed through the Gateway that consults the engine.

  · TRACES to a log group is rejected ("Invalid destination type provided for
    this resource and log type") — traces want X-Ray. USAGE_LOGS is not
    supported for gateways at all despite being listed by the validator, which
    lists the union across resource types. Hence APPLICATION_LOGS only.

  · Delivery takes ~30-60s to begin flowing after creation. Expect an empty log
    group on the first look; that is not a misconfiguration.

A decision record looks like this (a real DENY, reformatted):

    "log": "Policy evaluation denied request",
    "policy": {
      "decision": "DENY",
      "reason": "No policy applies to the request (denied by default).",
      "determiningPolicies": [],
      "principal": {"entityType": "AgentCore::OAuthUser", "entityId": "c4e8..."},
      "latencyMs": 49
    }

`determiningPolicies` is the audit trail: on an ALLOW it names the exact policy
that permitted the call. On a default-deny it is empty, which is itself the
finding — nothing matched.

Two limits worth knowing before promising anything:

  · `tools/list` produces NO policy record — but it IS enforced. Worth stating
    precisely, because the loose version ("only tools/call is evaluated") is
    wrong and reads as a security hole rather than a logging one. Cedar filters
    the listing: verified, a finance user calling tools/list under ENFORCE gets
    back only the finance tool. AWS documents this as a "meta action" evaluated
    without argument context — a tool is listed if ANY call to it could be
    permitted, so appearing in the list does not guarantee a call succeeds.
    What is missing is the record. The log answers "who called what", not "who
    could see what", and the list filtering leaves no audit trail at all.

  · The principal is a Cognito `sub` UUID, not an email and not the tenant.
    Attributing a decision to a person means joining against the user pool.
"""

from __future__ import annotations

import aws_cdk as cdk
from aws_cdk import aws_logs as logs
from constructs import Construct

# The only log type that carries policy decisions. See the module docstring —
# POLICY_DECISIONS and AUDIT_LOGS do not exist, and TRACES/USAGE_LOGS cannot be
# delivered to a log group from a Gateway.
LOG_TYPE = "APPLICATION_LOGS"


class GatewayObservability(Construct):
    """Deliver the Gateway's application logs — including policy decisions.

    Ordering is enforced with explicit dependencies rather than left to
    CloudFormation. The delivery references both the source and the destination
    *by name and ARN* (strings, not object references), so CloudFormation cannot
    infer the dependency and will happily try to create the join first.
    """

    def __init__(
        self,
        scope: Construct,
        id: str,
        *,
        gateway_arn: str,
        platform_name: str,
        retention_days: logs.RetentionDays = logs.RetentionDays.ONE_MONTH,
    ) -> None:
        super().__init__(scope, id)

        # The /aws/vendedlogs/ prefix is a convention with teeth: CloudWatch
        # grants delivery services write access to it without a resource policy.
        self.log_group = logs.LogGroup(
            self,
            "PolicyDecisionLogs",
            log_group_name=f"/aws/vendedlogs/bedrock-agentcore/{platform_name}/{LOG_TYPE}",
            retention=retention_days,
            removal_policy=cdk.RemovalPolicy.DESTROY,
        )

        source = logs.CfnDeliverySource(
            self,
            "Source",
            name=f"{platform_name}-gateway-{LOG_TYPE.lower()}",
            log_type=LOG_TYPE,
            resource_arn=gateway_arn,
        )

        destination = logs.CfnDeliveryDestination(
            self,
            "Destination",
            name=f"{platform_name}-gateway-{LOG_TYPE.lower()}-dest",
            destination_resource_arn=self.log_group.log_group_arn,
        )

        delivery = logs.CfnDelivery(
            self,
            "Delivery",
            delivery_source_name=source.name,
            delivery_destination_arn=destination.attr_arn,
        )
        delivery.add_resource_dependency(source)
        delivery.add_resource_dependency(destination)
