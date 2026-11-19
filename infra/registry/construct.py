# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""The catalogue: what AI assets exist, who owns them, and whether a
human reviewed them before they were published.

Built on AWS Agent Registry, with the native CloudFormation resources
AWS::AgentRegistry::Registry and AWS::AgentRegistry::RegistryRecord.

READ THIS FIRST, because the obvious reading of "registry + approval" is wrong.

    The Gateway does not consult the Registry.

There is no registry field on CreateGateway or CreateGatewayTarget, so an
APPROVED record is NOT a technical precondition for a tool being callable.
Registry and Gateway are parallel systems: the Registry records intent and
review, Cedar enforces access.

That matters for how this gets described. "Nothing reaches the request path
without an APPROVED record" would be a false claim. The true claim is narrower
and still worth making: the Registry is where an organisation answers "what
have we got, who owns it, and who signed it off" — the question that today is
answered by a spreadsheet, if at all.

WHAT THE REGISTRY GENUINELY ENFORCES

Each of these was verified against the live service by trying to break it:

  1. The status machine is server-side. UpdateRegistryRecordStatus on a DRAFT
     record fails with "Invalid status transition from DRAFT to APPROVED".
     Approval is not a label a caller can set at will.
  2. REJECTED is terminal. A rejected record cannot be resubmitted; getting a
     rejection reversed needs a new record, which is auditable.
  3. Editing an APPROVED record drops it to DRAFT and clears statusReason, so an
     approval cannot be outlived by the thing it approved.
  4. Record names are unique within a registry. A second record with the same
     name is refused with ConflictException.
  5. An empty autoApprovalRules list means every submitted record needs a human
     reviewer. It is set explicitly here so the repo states its own posture.

Records are created in DRAFT. Nothing here submits or approves them: doing that
from CloudFormation would defeat the point, because the value of the workflow is
that a human looks at the descriptor before it is published.
scripts/catalogue.py and the dashboard are how a reviewer moves a record along.

THE DESCRIPTOR CONTENT

The mcpServer descriptor's data must be an MCP *registry* server.json document,
not an initialize result or a bare serverInfo block. Both of those are rejected
with "mcp.server data does not match any supported version", a message that
sounds like a version problem and is actually a schema problem. The same message
is returned when the server.json description is longer than 100 characters; see
MAX_SERVER_DESCRIPTION. DataSchemaVersion is left unset: the service detects the
version from the document.
"""

from __future__ import annotations

import json

from aws_cdk import aws_agentregistry as agentregistry
from constructs import Construct

from infra.config import Config, Tool

# The MCP registry server.json schema. Pinned rather than tracking "latest"
# because the service validates against it and a silent upstream change would
# break deploys for reasons invisible in this repo.
MCP_SERVER_SCHEMA = (
    "https://static.modelcontextprotocol.io/schemas/2025-09-29/server.schema.json"
)

# The server.json description field takes at most 100 characters, and a longer
# one is reported as "does not match any supported version" — a message about
# versions, for a length problem. Found by bisection: 100 passes, 101 fails.
#
# This platform's real tool descriptions are longer than that, and they must stay
# long, because the description is what the model reads to decide whether to call
# a tool. So the server.json summary is truncated while the full text goes in the
# tools descriptor, which has no such limit.
MAX_SERVER_DESCRIPTION = 100


class AssetRegistry(Construct):
    """The registry and one record per tool."""

    def __init__(self, scope: Construct, id: str, *, config: Config) -> None:
        super().__init__(scope, id)

        if config.registry is None:
            raise ValueError("AssetRegistry requires a registry section in governance.yaml")

        self.config = config
        self.registry_config = config.registry

        self.registry = self._create_registry()
        self.records = [self._create_record(tool) for tool in config.tools]

    # -------------------------------------------------------------- registry

    def _create_registry(self) -> agentregistry.CfnRegistry:
        rules = ["APPROVE_ALL"] if self.registry_config.auto_approval else []
        # Logical IDs differ from the earlier custom-resource versions
        # ("Registry", "Record<Tool>") because CloudFormation does not allow a
        # resource to change type in place.
        return agentregistry.CfnRegistry(
            self,
            "AgentRegistry",
            name=self.registry_config.name,
            description=(
                f"AI asset catalogue for {self.config.platform_name}. "
                "What exists, who owns it, and who approved it."
            ),
            approval_configuration=agentregistry.CfnRegistry.ApprovalConfigurationProperty(
                auto_approval_rules=rules
            ),
        )

    @property
    def registry_arn(self) -> str:
        return self.registry.attr_registry_arn

    @property
    def registry_id(self) -> str:
        return self.registry.attr_registry_id

    # ---------------------------------------------------------------- records

    def _create_record(self, tool: Tool) -> agentregistry.CfnRegistryRecord:
        """One catalogue entry for one tool.

        The descriptor carries the same description string the Gateway
        advertises in tools/list. That is deliberate: it is what a human
        reviewer should be looking at, so the catalogue must not drift from what
        the model actually sees.

        The tenant and owner go at the end of the description because the
        record has no structured field for them; infra/dashboard/api.py reads
        them back from there.
        """
        record_cls = agentregistry.CfnRegistryRecord
        return record_cls(
            self,
            f"AgentRegistryRecord{_pascal(tool.name)}",
            registry_id=self.registry_id,
            name=tool.name,
            display_name=tool.name,
            description=f"{tool.description} [tenant: {tool.tenant}, owner: {tool.owner}]",
            record_type="MCP",
            descriptors=record_cls.DescriptorsProperty(
                mcp_server=record_cls.McpServerDescriptorProperty(
                    data=_server_json(tool),
                    additional_data=record_cls.McpServerAdditionalDataProperty(
                        tools=record_cls.McpToolsDescriptorProperty(data=_tools_json(tool))
                    ),
                )
            ),
        )


def _server_json(tool: Tool) -> str:
    """An MCP registry server.json document for one tool.

    The reverse-DNS name is a namespace requirement of the MCP registry schema,
    not an AWS one. com.example is honest for a reference architecture; a real
    deployment would use the organisation's own domain.
    """
    return json.dumps(
        {
            "$schema": MCP_SERVER_SCHEMA,
            "name": f"com.example/{tool.name}",
            "description": _truncate(tool.description, MAX_SERVER_DESCRIPTION),
            "version": "1.0.0",
        }
    )


def _truncate(text: str, limit: int) -> str:
    """Shorten to limit characters, breaking on a word where possible.

    Only the server.json summary is truncated. The full description survives
    untouched in the tools descriptor, which is the copy a reviewer reads.
    """
    if len(text) <= limit:
        return text
    cut = text[: limit - 1]
    if " " in cut:
        cut = cut.rsplit(" ", 1)[0]
    return cut + "…"


def _tools_json(tool: Tool) -> str:
    """The tool list, in the shape an MCP server returns from tools/list."""
    properties = {
        arg.name: {"type": arg.type, "description": arg.description}
        for arg in tool.arguments
    }
    return json.dumps(
        {
            "tools": [
                {
                    "name": tool.name,
                    "description": tool.description,
                    "inputSchema": {
                        "type": "object",
                        "properties": properties,
                        "required": [a.name for a in tool.arguments if a.required],
                    },
                }
            ]
        }
    )


def _pascal(value: str) -> str:
    """finance-reports -> FinanceReports, for CDK logical IDs."""
    return "".join(part.capitalize() for part in value.replace("_", "-").split("-"))
