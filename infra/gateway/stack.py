# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""One governed door, the policy that decides who gets in, and the record of
what it decided.

This stack creates:
  · a Lambda per tool declared in governance.yaml
  · a Cedar policy engine, with one tenant policy per tool and, when
    admission_scan is configured, one prompt-injection guardrail rule per tool
  · an AgentCore Gateway with CUSTOM_JWT auth pointed at Cognito
  · one Gateway target per tool, schema declared inline
  · CloudWatch log delivery, so policy decisions are actually recorded

Authentication comes from Cognito: is this a real user? Authorization comes from
Cedar: may THIS user call THIS tool? They are separate questions and separate
mechanisms — everyone who logs in gets through the door, and Cedar decides what
they find on the other side. The same policy engine also scores each call's
arguments for prompt injection, so one decision covers both questions.

Two decisions worth knowing about:

CfnGateway, not the L2 Gateway. The L2 has no policy_engine_configuration
property, which attaching the Cedar policy engine needs.

The authorize IAM actions are matched to this stack's policy engine and Gateway
by name, because neither ARN exists yet when the grant must be in place — see
_grant_policy_engine_access.
"""

from __future__ import annotations

from pathlib import Path

import aws_cdk as cdk
from aws_cdk import aws_bedrockagentcore as agentcore
from aws_cdk import aws_iam as iam
from aws_cdk import aws_lambda as lambda_
from aws_cdk import aws_logs as logs
from constructs import Construct

from infra.config import LAMBDA_RESERVED_CONCURRENCY, Config, Tool
from infra.dashboard.construct import Dashboard
from infra.gateway.observability import GatewayObservability
from infra.guardrail.construct import PromptAttackGuardrail
from infra.registry.construct import AssetRegistry

TOOLS_DIR = Path(__file__).resolve().parent.parent / "tools"


class GatewayStack(cdk.Stack):
    """The Gateway, its targets, and the Lambdas behind them."""

    def __init__(self, scope: Construct, id: str, *, config: Config, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        self.config = config

        self.gateway_role = self._create_gateway_role()
        self.tool_functions = {t.name: self._create_tool_lambda(t) for t in config.tools}

        # The guardrail the dashboard uses to scan tool descriptions at
        # registration. Tool arguments are scanned by guardrail rules in the
        # policy engine instead (_create_guardrail_policies), which call Bedrock
        # Guardrails directly and do not need this resource.
        self.guardrail = (
            PromptAttackGuardrail(self, "DescriptionGuardrail", config=self.config)
            if self.config.admission_scan
            else None
        )

        # Order matters and is not arbitrary. The engine must exist before the
        # Gateway can reference its ARN; the policies need the Gateway ARN in
        # their `resource ==` clause. Engine -> Gateway -> policies is the only
        # ordering that avoids a circular dependency.
        self.policy_engine = self._create_policy_engine()
        self.gateway = self._create_gateway()
        self._create_policies()
        self._create_guardrail_policies()
        self._create_targets()

        # Decision logs. Without this the account has no AgentCore log groups at
        # all and LOG_ONLY mode records nothing observable — see observability.py.
        self.observability = GatewayObservability(
            self,
            "Observability",
            gateway_arn=self.gateway.attr_gateway_arn,
            platform_name=self.config.platform_name,
        )

        # The registry. Deliberately NOT a dependency of anything above: the
        # Gateway does not consult the Registry, and wiring a fake dependency here
        # would misrepresent the architecture in the one artefact people read most
        # carefully. See infra/registry/construct.py.
        self.registry = (
            AssetRegistry(self, "Registry", config=self.config)
            if self.config.registry
            else None
        )

        # The dashboard. Constructed last because it reads from three things
        # above: the Registry (the catalogue), the guardrail (the publish-time
        # scan) and the decision log group (the audit trail).
        #
        # It is still NOT in the request path, and that has not changed by giving
        # it more to show. A viewer looking at APPROVED rows learns nothing about
        # what is callable, and the API says so in every response.
        #
        # The guardrail and the log group are passed rather than looked up, so a
        # deployment without an admission_scan section gets a dashboard whose
        # register feature is visibly unavailable with a stated reason — instead
        # of a button that fails when clicked.
        self.dashboard = (
            Dashboard(
                self,
                "Dashboard",
                config=self.config,
                registry_id=self.registry.registry_id,
                gateway_url=self.gateway.attr_gateway_url,
                guardrail_arn=self.guardrail.guardrail_arn if self.guardrail else None,
                guardrail_id=self.guardrail.guardrail_id if self.guardrail else None,
                decision_log_group=self.observability.log_group,
            )
            if self.registry is not None and self.config.dashboard
            else None
        )

        self._outputs()

    # ------------------------------------------------------------------ role

    def _create_gateway_role(self) -> iam.Role:
        role = iam.Role(
            self,
            "GatewayRole",
            assumed_by=iam.ServicePrincipal("bedrock-agentcore.amazonaws.com"),
            description="Execution role for the AI Governance AgentCore Gateway",
        )
        self._grant_policy_engine_access(role)
        return role

    def _grant_policy_engine_access(self, role: iam.Role) -> None:
        """Grant the authorization actions the Gateway needs at decision time.

        The Service Authorization Reference lists BOTH the gateway and the
        policy-engine resource types for AuthorizeAction and
        PartiallyAuthorizeActions. An earlier version scoped them to the engine ARN
        alone, got AccessDeniedException, and fell back to "*"; naming both is
        what makes ARN scoping work.

        Granted now, before the engine and Gateway exist, because the role must
        already hold them when the engine is attached. Neither ARN is known yet,
        so each is matched by its name: the service appends a random suffix
        ("<name>-a1b2c3d4e5") to both.
        """
        prefix = (
            f"arn:{cdk.Aws.PARTITION}:bedrock-agentcore:{self.config.region}:"
            f"{cdk.Stack.of(self).account}"
        )
        engine_arn = f"{prefix}:policy-engine/{self.config.policy_engine_name}-*"
        gateway_arn = f"{prefix}:gateway/{self.config.platform_name}-gateway-*"
        role.add_to_policy(
            iam.PolicyStatement(
                sid="AgentCorePolicyEngineAuthorization",
                actions=[
                    "bedrock-agentcore:AuthorizeAction",
                    "bedrock-agentcore:PartiallyAuthorizeActions",
                ],
                resources=[engine_arn, gateway_arn],
            )
        )
        role.add_to_policy(
            iam.PolicyStatement(
                sid="AgentCorePolicyEngineRead",
                actions=["bedrock-agentcore:GetPolicyEngine"],
                resources=[engine_arn],
            )
        )

        # The guardrail rules call Bedrock Guardrails using credentials derived
        # from this role. Resource is "*" because the Service Authorization
        # Reference defines no resource type for InvokeGuardrailChecks. Without
        # the grant, every call to a tool with a guardrail rule is refused with
        # "Insufficient Permissions for Policy Evaluation" (verified).
        if self.config.admission_scan is not None:
            role.add_to_policy(
                iam.PolicyStatement(
                    sid="BedrockGuardrailChecks",
                    actions=["bedrock:InvokeGuardrailChecks"],
                    resources=["*"],
                )
            )

    # --------------------------------------------------------------- lambdas

    def _create_tool_lambda(self, tool: Tool) -> lambda_.Function:
        handler_dir = TOOLS_DIR / tool.handler
        if not handler_dir.is_dir():
            raise FileNotFoundError(
                f"tool {tool.name!r} declares handler {tool.handler!r} but "
                f"{handler_dir} does not exist"
            )

        # An explicit LogGroup, not the log_retention property. log_retention is
        # deprecated and provisions a custom-resource Lambda per function, which
        # would put more Lambdas in this stack than there are tools.
        log_group = logs.LogGroup(
            self,
            f"Tool{_pascal(tool.name)}Logs",
            log_group_name=f"/aws/lambda/{self.config.platform_name}-{tool.name}",
            retention=logs.RetentionDays.ONE_MONTH,
            removal_policy=cdk.RemovalPolicy.DESTROY,
        )

        fn = lambda_.Function(
            self,
            f"Tool{_pascal(tool.name)}",
            function_name=f"{self.config.platform_name}-{tool.name}",
            runtime=lambda_.Runtime.PYTHON_3_14,
            architecture=lambda_.Architecture.ARM_64,
            handler="handler.handler",
            code=lambda_.Code.from_asset(str(handler_dir)),
            timeout=cdk.Duration.seconds(30),
            memory_size=256,
            description=f"{tool.name} — governed tool for tenant {tool.tenant}",
            log_group=log_group,
            reserved_concurrent_executions=LAMBDA_RESERVED_CONCURRENCY,
        )
        # source_account stops a Gateway in another account invoking this
        # function through the shared service principal (confused deputy).
        fn.add_permission(
            "AgentCoreInvoke",
            principal=iam.ServicePrincipal("bedrock-agentcore.amazonaws.com"),
            source_account=cdk.Stack.of(self).account,
        )
        fn.grant_invoke(self.gateway_role)
        return fn

    # ---------------------------------------------------------- policy engine

    def _create_policy_engine(self) -> agentcore.CfnPolicyEngine:
        """The thing that answers 'may this caller use this tool?'.

        An engine on its own denies everything: Cedar is default-deny, so the
        absence of a matching permit IS a denial. The policies created below are
        what let anyone through.
        """
        return agentcore.CfnPolicyEngine(
            self,
            "PolicyEngine",
            name=self.config.policy_engine_name,
            description=(
                "Cedar authorization for the AI Governance Gateway. One policy "
                "per tool, keyed on the caller's custom:tenant claim."
            ),
        )

    def _create_policies(self) -> None:
        """One Cedar policy per tool: this tenant may call this tool.

        The syntax here is load-bearing and every part of it was established by
        experiment against the live service. Three traps, all of which fail silently:

        1. The action name is PREFIXED — "<targetName>___<toolName>" with three
           underscores. tools/list advertises that same prefixed form, but the
           bare tool name is what appears in governance.yaml, so it must be
           built here. A wrong name is not an error; the policy simply never
           matches and the tool is invisible to everyone.

        2. The tenant claim is reachable ONLY via principal.getTag(). Both
           principal["custom:tenant"] and context[...] pass validation, reach
           ACTIVE, and enforce nothing whatsoever.

        3. Only Gateways are Cedar resources. Tools are ACTIONS, not resources.

        validation_mode is FAIL_ON_ANY_FINDINGS so a malformed policy fails the
        deploy. That is worth having, but it is NOT a safety net: testing
        showed all three claim syntaxes above pass validation, including the two
        that do nothing. Only a runtime negative control tells the truth, which
        is what scripts/verify.py exists for.
        """
        gateway_arn = self.gateway.attr_gateway_arn

        for tool in self.config.tools:
            action = f"{tool.name}___{tool.name}"
            claim = self.config.cognito.tenant_claim

            statement = (
                f'permit(\n'
                f'  principal,\n'
                f'  action in [AgentCore::Action::"{action}"],\n'
                f'  resource == AgentCore::Gateway::"{gateway_arn}"\n'
                f') when {{\n'
                f'  principal.hasTag("{claim}") &&\n'
                f'  principal.getTag("{claim}") == "{tool.tenant}"\n'
                f'}};'
            )

            policy = agentcore.CfnPolicy(
                self,
                f"Policy{_pascal(tool.name)}",
                name=f"{tool.tenant}_may_use_{tool.name.replace('-', '_')}",
                policy_engine_id=self.policy_engine.attr_policy_engine_id,
                description=f"Tenant {tool.tenant!r} may call {tool.name!r}",
                definition=agentcore.CfnPolicy.PolicyDefinitionProperty(
                    cedar=agentcore.CfnPolicy.CedarPolicyProperty(statement=statement)
                ),
                # ACTIVE means "this policy participates in decisions". It is
                # NOT the same knob as the Gateway's LOG_ONLY/ENFORCE mode,
                # which decides whether decisions are acted on. Per-policy
                # LOG_ONLY exists but this sample switches the Gateway, so every
                # policy moves together.
                enforcement_mode="ACTIVE",
                validation_mode="FAIL_ON_ANY_FINDINGS",
            )
            policy.add_resource_dependency(self.policy_engine)
            policy.add_resource_dependency(self.gateway)

    def _create_guardrail_policies(self) -> None:
        """One guardrail rule per tool: refuse a call whose arguments look like
        a prompt injection.

        The policy engine scores the named argument fields through Bedrock
        Guardrails (PROMPT_ATTACK, category PROMPT_INJECTION) while it makes the
        decision, so the refusal, the score and the tenant decision all land in
        the same decision log record. Arguments are scanned rather than the tool
        description: the description is fixed, human-reviewed and already
        scanned at registration, while arguments are attacker-controlled and
        arrive fresh on every call.

        Four things about this syntax were established against the live service
        and are not obvious from the documentation:

        1. It must be a `policy` definition, not `cedar`. The Cedar parser
           rejects `when guardrails` as an unexpected token.

        2. validation_mode must be IGNORE_ALL_FINDINGS. With FAIL_ON_ANY_FINDINGS
           the policy is accepted and then fails asynchronously as "Overly
           Restrictive", because the analyser cannot evaluate a guardrail score
           ahead of time and treats the rule as one that could deny everything.
           The tenant policies above keep strict validation.

        3. Each argument must be named (context.input.<name>); there is no
           wildcard over all arguments. They are generated from the tool's
           arguments in governance.yaml, so a new argument is covered on the
           next deploy.

        4. The rule does not affect tools/list. A tenant still sees its own
           tools; only the call is scored.

        5. Every scored field must be present and non-empty. A missing field is
           refused ("request missing field(s) required for guardrail
           evaluation"), and an empty string fails with "Policy Evaluation
           Internal Failure", also a refusal. infra/config.py therefore requires
           every string argument to be required.

        If the guardrail check cannot run, the call is refused ("Insufficient
        Permissions for Policy Evaluation" when the role lacks the grant). There
        is no fail-open option.
        """
        scan = self.config.admission_scan
        if scan is None:
            return

        gateway_arn = self.gateway.attr_gateway_arn
        for tool in self.config.tools:
            fields = [a.name for a in tool.arguments if a.type == "string"]
            if not fields:
                continue  # nothing an injection could be carried in

            action = f"{tool.name}___{tool.name}"
            paths = ", ".join(f"context.input.{f}" for f in fields)
            statement = (
                f'forbid(\n'
                f'  principal,\n'
                f'  action == AgentCore::Action::"{action}",\n'
                f'  resource == AgentCore::Gateway::"{gateway_arn}"\n'
                f') when guardrails {{\n'
                f'  BedrockGuardrails::PromptAttack(["PROMPT_INJECTION"], [{paths}])'
                f'["PROMPT_INJECTION"]\n'
                f'    .confidenceScore.greaterThan(decimal("{scan.threshold}"))\n'
                f'}};'
            )

            policy = agentcore.CfnPolicy(
                self,
                f"GuardrailPolicy{_pascal(tool.name)}",
                name=f"{tool.name.replace('-', '_')}_prompt_injection_scan",
                policy_engine_id=self.policy_engine.attr_policy_engine_id,
                description=(
                    f"Refuse {tool.name!r} calls whose arguments look like a "
                    "prompt injection"
                ),
                definition=agentcore.CfnPolicy.PolicyDefinitionProperty(
                    policy=agentcore.CfnPolicy.PolicyStatementProperty(statement=statement)
                ),
                # OBSERVE runs the rule in LOG_ONLY: the score and whether it
                # would have flipped the decision are recorded, nothing is
                # refused. This is per rule, so tenant isolation stays enforced.
                enforcement_mode="ACTIVE" if scan.mode == "ENFORCE" else "LOG_ONLY",
                validation_mode="IGNORE_ALL_FINDINGS",
            )
            policy.add_resource_dependency(self.policy_engine)
            policy.add_resource_dependency(self.gateway)
            # The rule refuses every call if the role cannot reach Guardrails,
            # so make sure the grant exists before the rule does.
            policy.node.add_dependency(self.gateway_role)

    # --------------------------------------------------------------- gateway

    def _create_gateway(self) -> agentcore.CfnGateway:
        """Create the Gateway with CUSTOM_JWT auth.

        Not IAM auth, which cannot work here: a developer's coding assistant holds
        a Cognito token, not SigV4 credentials, and IAM auth surfaces no
        custom:tenant claim for Cedar to read.
        """
        cognito = self.config.cognito

        gateway = agentcore.CfnGateway(
            self,
            "Gateway",
            name=f"{self.config.platform_name}-gateway",
            role_arn=self.gateway_role.role_arn,
            protocol_type="MCP",
            authorizer_type="CUSTOM_JWT",
            authorizer_configuration=agentcore.CfnGateway.AuthorizerConfigurationProperty(
                custom_jwt_authorizer=agentcore.CfnGateway.CustomJWTAuthorizerConfigurationProperty(
                    discovery_url=cognito.discovery_url,
                    allowed_audience=[cognito.app_client_id],
                )
            ),
            policy_engine_configuration=agentcore.CfnGateway.GatewayPolicyEngineConfigurationProperty(
                arn=self.policy_engine.attr_policy_engine_arn,
                mode=self.config.enforcement_mode,
            ),
            description=(
                "Single governed MCP endpoint. Cognito authenticates the caller; "
                "Cedar decides which tools they can see and call."
            ),
        )
        return gateway

    def _create_targets(self) -> None:
        """One target per tool, with the schema declared inline.

        The Gateway owns the schema, so the tool Lambdas are only ever invoked
        for tools/call — they need no tools/list branch.

        Target name matters: Cedar addresses a tool as
        AgentCore::Action::"<targetName>___<toolName>" (triple underscore). Using
        the tool name for both keeps the generated policies readable.
        """
        for tool in self.config.tools:
            fn = self.tool_functions[tool.name]

            target = agentcore.CfnGatewayTarget(
                self,
                f"Target{_pascal(tool.name)}",
                gateway_identifier=self.gateway.attr_gateway_identifier,
                name=tool.name,
                description=tool.description,
                target_configuration=agentcore.CfnGatewayTarget.TargetConfigurationProperty(
                    mcp=agentcore.CfnGatewayTarget.McpTargetConfigurationProperty(
                        lambda_=agentcore.CfnGatewayTarget.McpLambdaTargetConfigurationProperty(
                            lambda_arn=fn.function_arn,
                            tool_schema=agentcore.CfnGatewayTarget.ToolSchemaProperty(
                                inline_payload=[_tool_schema(tool)]
                            ),
                        )
                    )
                ),
                credential_provider_configurations=[
                    # Outbound identity: the target is called with the Gateway's
                    # own role. This is the simplest of five credential provider
                    # types; OAUTH (per-user tokens from the AgentCore Identity
                    # token vault) is the intended next step, and is a change to
                    # this block rather than a redesign.
                    agentcore.CfnGatewayTarget.CredentialProviderConfigurationProperty(
                        credential_provider_type="GATEWAY_IAM_ROLE"
                    )
                ],
            )
            target.add_resource_dependency(self.gateway)

    # --------------------------------------------------------------- outputs

    def _outputs(self) -> None:
        cdk.CfnOutput(
            self,
            "GatewayUrl",
            value=self.gateway.attr_gateway_url,
            description="The single MCP endpoint. This is the only URL a client needs.",
        )
        cdk.CfnOutput(self, "GatewayId", value=self.gateway.attr_gateway_identifier)
        cdk.CfnOutput(self, "GatewayArn", value=self.gateway.attr_gateway_arn)
        cdk.CfnOutput(
            self,
            "EnforcementMode",
            value=self.config.enforcement_mode,
            description="LOG_ONLY records decisions; ENFORCE acts on them",
        )
        cdk.CfnOutput(
            self,
            "PolicyEngineArn",
            value=self.policy_engine.attr_policy_engine_arn,
            description="Cedar policy engine attached to the Gateway",
        )
        cdk.CfnOutput(
            self,
            "DecisionLogGroup",
            value=self.observability.log_group.log_group_name,
            description="Where every ALLOW and DENY is recorded",
        )
        if self.registry is not None:
            cdk.CfnOutput(
                self,
                "RegistryArn",
                value=self.registry.registry_arn,
                description="Asset catalogue. Records land in DRAFT for review.",
            )
        if self.config.admission_scan is not None:
            cdk.CfnOutput(
                self,
                "AdmissionScanMode",
                value=self.config.admission_scan.mode,
                description=(
                    "OBSERVE logs guardrail scores in the decision log; ENFORCE "
                    "refuses the call"
                ),
            )
        if self.guardrail is not None:
            cdk.CfnOutput(
                self,
                "GuardrailId",
                value=self.guardrail.guardrail_id,
                description="Bedrock guardrail that scans tool descriptions at registration",
            )
        if self.dashboard is not None:
            cdk.CfnOutput(
                self,
                "DashboardUrl",
                value=self.dashboard.url,
                description="The asset register. Sign in with a platform account.",
            )
            cdk.CfnOutput(
                self,
                "DashboardApiUrl",
                value=self.dashboard.api_url,
                description="Read API behind the dashboard, JWT-authorised by Cognito",
            )
            cdk.CfnOutput(
                self,
                "DashboardReviewerGroup",
                value=self.dashboard.reviewer_group,
                # Output rather than left implicit so scripts/verify.py can check
                # the DEPLOYED group instead of assuming a name. A verifier that
                # hardcodes the group would pass against a stack that enforces a
                # different one, which is the class of defect this repo exists
                # to avoid.
                description="Cognito group whose members may act on the review queue",
            )
        cdk.CfnOutput(
            self,
            "CognitoDiscoveryUrl",
            value=self.config.cognito.discovery_url,
            description="OIDC discovery endpoint the Gateway validates tokens against",
        )


def _tool_schema(tool: Tool) -> agentcore.CfnGatewayTarget.ToolDefinitionProperty:
    """Build the MCP tool definition the Gateway advertises in tools/list."""
    properties = {
        arg.name: agentcore.CfnGatewayTarget.SchemaDefinitionProperty(
            type=arg.type,
            description=arg.description,
        )
        for arg in tool.arguments
    }
    return agentcore.CfnGatewayTarget.ToolDefinitionProperty(
        name=tool.name,
        description=tool.description,
        input_schema=agentcore.CfnGatewayTarget.SchemaDefinitionProperty(
            type="object",
            properties=properties,
            required=[a.name for a in tool.arguments if a.required],
        ),
    )


def _pascal(value: str) -> str:
    """finance-reports -> FinanceReports, for CDK logical IDs."""
    return "".join(part.capitalize() for part in value.replace("_", "-").split("-"))
