# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Load and validate governance.yaml.

Validation here is deliberately strict and fails loudly. A .get() with a default
can swallow a wrong key name and return an empty result forever, so nothing in this file uses a silent default
for a value that must exist.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


class ConfigError(Exception):
    """Raised when governance.yaml is missing, unreadable, or invalid."""


@dataclass(frozen=True)
class ToolArgument:
    name: str
    type: str
    description: str
    required: bool


@dataclass(frozen=True)
class Tool:
    name: str
    tenant: str
    handler: str
    description: str
    owner: str = ""
    arguments: list[ToolArgument] = field(default_factory=list)


@dataclass(frozen=True)
class RegistryConfig:
    """The catalogue. Optional — the Gateway works without it.

    That is not a design compromise, it is what the service does: there is no
    registry field on create-gateway or create-gateway-target, so a record is
    documentation and review workflow, not an admission gate. Saying so plainly
    here is cheaper than discovering it in front of a customer.
    """

    name: str
    auto_approval: bool = False


@dataclass(frozen=True)
class AdmissionScanConfig:
    """The prompt-injection scan, run by AgentCore Policy as guardrail rules.

    Unlike the registry, this one IS in the request path — the policy engine
    scores the tool arguments through Bedrock Guardrails while it decides the
    call, and a refusal actually refuses. That distinction is easy to miss, so it
    is stated in both places.

    mode decides whether the guardrail rules are enforced:
        OBSERVE   rules run in LOG_ONLY: the score is recorded in the decision
                  log, with whether it would have changed the decision, and the
                  call is allowed
        ENFORCE   rules are ACTIVE: a call whose arguments score above the
                  threshold is refused

    threshold is the PROMPT_INJECTION confidence score a call must exceed to be
    refused. Guardrails returns discrete scores (0, 0.2, 0.4, ... 1.0); AWS's
    default is 0.4.

    There is no fail-open setting. If the guardrail check cannot run, the policy
    engine refuses the call. That is the right posture for a security control,
    and it is the only one the service offers.
    """

    mode: str
    threshold: float


@dataclass(frozen=True)
class DashboardConfig:
    """The catalogue's visible surface — a React app on CloudFront plus a read API.

    Optional, and genuinely so: everything the dashboard shows is also available
    from scripts/catalogue.py. It exists because an asset register is furniture a
    security reviewer recognises, and a terminal is not.

    What it must never imply is enforcement. It reads the Registry, and the
    Gateway does not consult the Registry — so a screen of APPROVED rows says
    nothing about what is callable. The API returns that caveat in every response
    and the UI renders it, rather than relying on the reader to remember.

    reviewer_group is a Cognito group. Reads are open to any authenticated user
    in the pool, scoped to their own tenant; acting on the review queue requires
    membership. A dashboard where a tenant approves its own asset would look like
    governance while being a rubber stamp.
    """

    reviewer_group: str = "platform-reviewers"


@dataclass(frozen=True)
class CognitoConfig:
    user_pool_id: str
    app_client_id: str
    tenant_claim: str

    @property
    def discovery_url(self) -> str:
        region = self.user_pool_id.split("_", 1)[0]
        return (
            f"https://cognito-idp.{region}.amazonaws.com/"
            f"{self.user_pool_id}/.well-known/openid-configuration"
        )


@dataclass(frozen=True)
class Config:
    platform_name: str
    region: str
    cognito: CognitoConfig
    tenants: list[str]
    tools: list[Tool]
    enforcement_mode: str
    registry: RegistryConfig | None = None
    admission_scan: AdmissionScanConfig | None = None
    dashboard: DashboardConfig | None = None

    @property
    def policy_engine_name(self) -> str:
        """A policy engine name AgentCore will accept.

        PolicyEngineName must match ^[A-Za-z][A-Za-z0-9_]*$ — no hyphens. The
        platform name has them, so they become underscores.
        """
        return self.platform_name.replace("-", "_") + "_engine"


# LOG_ONLY evaluates policies and records what *would* happen without enforcing.
# ENFORCE actually denies. There is no third value, and notably no DISABLED —
# to take a policy out of play you delete it.
ENFORCEMENT_MODES = ("LOG_ONLY", "ENFORCE")

# The admission scan's own modes. Different words from ENFORCEMENT_MODES on
# purpose: OBSERVE switches only the guardrail rules to LOG_ONLY, while
# enforcement_mode switches the whole policy engine, and this repo already
# has one pair of easily-confused mode knobs (a policy's ACTIVE/LOG_ONLY vs the
# Gateway's LOG_ONLY/ENFORCE). A third value spelled "LOG_ONLY" would make a
# misconfiguration unreadable in a log line.
SCAN_MODES = ("OBSERVE", "ENFORCE")

# Reserved concurrency for each Lambda this sample defines. It caps how many
# copies of one function run at once, so a runaway caller cannot use up the
# account's shared pool or run up cost. Five is plenty for a sample. Lambda
# refuses a reservation that would leave fewer than 100 unreserved executions,
# so on an account with a low concurrency quota lower or remove this.
LAMBDA_RESERVED_CONCURRENCY = 5


def load(path: Path) -> Config:
    """Read governance.yaml and return a validated Config."""
    if not path.is_file():
        raise ConfigError(f"config file not found: {path}")

    try:
        raw = yaml.safe_load(path.read_text()) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"{path} is not valid YAML: {exc}") from exc

    platform = _require_mapping(raw, "platform")
    cognito_raw = _require_mapping(raw, "cognito")

    cognito = CognitoConfig(
        user_pool_id=_require_str(cognito_raw, "user_pool_id", "cognito"),
        app_client_id=_require_str(cognito_raw, "app_client_id", "cognito"),
        tenant_claim=cognito_raw.get("tenant_claim", "custom:tenant"),
    )

    tenants = [
        _require_str(t, "name", "tenants[]")
        for t in _require_list(raw, "tenants")
    ]

    tools = [_parse_tool(t, tenants) for t in _require_list(raw, "tools")]

    # This is the value people switch between LOG_ONLY and ENFORCE. Validate it
    # here rather than letting a typo reach CloudFormation, where the failure is
    # slow and the message unhelpful.
    governance = raw.get("governance") or {}
    if not isinstance(governance, dict):
        raise ConfigError("governance must be a mapping")
    enforcement_mode = governance.get("enforcement_mode", "ENFORCE")
    if enforcement_mode not in ENFORCEMENT_MODES:
        raise ConfigError(
            f"governance.enforcement_mode is {enforcement_mode!r}; "
            f"must be one of {list(ENFORCEMENT_MODES)}. "
            "There is no DISABLED — delete policies to take them out of play."
        )

    # The catalogue is optional; the Gateway does not depend on it. But if the
    # section is present it must be well-formed — a typo'd key here would
    # otherwise silently produce no records at all, which looks identical to
    # "the registry isn't wired up yet".
    registry_raw = raw.get("registry")
    registry: RegistryConfig | None = None
    if registry_raw is not None:
        if not isinstance(registry_raw, dict):
            raise ConfigError("registry must be a mapping")
        auto_approval = registry_raw.get("auto_approval", False)
        if not isinstance(auto_approval, bool):
            raise ConfigError(
                f"registry.auto_approval is {auto_approval!r}; must be true or false. "
                "false (the service default) means a human must approve each record."
            )
        registry = RegistryConfig(
            name=_require_str(registry_raw, "name", "registry"),
            auto_approval=auto_approval,
        )
        unowned = [t.name for t in tools if not t.owner]
        if unowned:
            raise ConfigError(
                f"tools without an owner: {unowned}. A registry record names an "
                "accountable human; add `owner:` to each tool, or remove the "
                "registry section."
            )

    # The scan is optional too, and validated the same strict way. A typo'd mode
    # here matters more than most: "Observe" silently falling back to a default
    # would mean either an unwatched control or an unenforced one, and the log
    # line looks identical either way.
    scan_raw = raw.get("admission_scan")
    admission_scan: AdmissionScanConfig | None = None
    if scan_raw is not None:
        if not isinstance(scan_raw, dict):
            raise ConfigError("admission_scan must be a mapping")
        mode = str(scan_raw.get("mode", "OBSERVE")).upper()
        if mode not in SCAN_MODES:
            raise ConfigError(
                f"admission_scan.mode is {scan_raw.get('mode')!r}; must be one of "
                f"{list(SCAN_MODES)}. OBSERVE scores and logs without blocking; "
                "ENFORCE refuses the call. Note these are NOT the same words as "
                "governance.enforcement_mode, which controls Cedar."
            )
        if "fail_open" in scan_raw:
            raise ConfigError(
                "admission_scan.fail_open is no longer supported: the scan runs as "
                "AgentCore Policy guardrail rules, which always refuse a call when "
                "the check cannot run. Remove the setting."
            )
        threshold = scan_raw.get("threshold")
        valid = isinstance(threshold, (int, float)) and not isinstance(threshold, bool)
        if not valid or not 0 <= threshold < 1:
            raise ConfigError(
                f"admission_scan.threshold is {threshold!r}; must be a number from 0 "
                "up to (not including) 1. A call is refused when its PROMPT_INJECTION "
                "score is greater than this. AWS's default is 0.4."
            )
        admission_scan = AdmissionScanConfig(mode=mode, threshold=float(threshold))

        # Every string argument must be required. The guardrail rule names each
        # field it scores, and a call that omits a named field is refused
        # ("request missing field(s) required for guardrail evaluation"), so an
        # optional field would make an ordinary call fail. Leaving optional
        # fields out of the rule instead would leave them unscanned. A guardrail
        # condition cannot be combined with a Cedar "has" check to skip a
        # missing field, so the argument has to be required.
        for tool in tools:
            optional = [
                a.name for a in tool.arguments if a.type == "string" and not a.required
            ]
            if optional:
                raise ConfigError(
                    f"tools[{tool.name}]: string argument(s) {optional} are optional, "
                    "but the admission scan needs every string argument to be "
                    "required. Set required: true. Note the scan also refuses an "
                    "empty string, so give callers a non-empty value such as \"*\" "
                    "for 'all'."
                )

    # The dashboard reads the catalogue, so it cannot exist without one. Saying
    # that here, at load time, beats a CloudFormation failure or — worse — a
    # deployed dashboard permanently showing an empty table.
    dashboard_raw = raw.get("dashboard")
    dashboard: DashboardConfig | None = None
    if dashboard_raw is not None:
        if not isinstance(dashboard_raw, dict):
            raise ConfigError("dashboard must be a mapping")
        if registry is None:
            raise ConfigError(
                "dashboard is configured but registry is not. The dashboard reads "
                "the catalogue; without a registry section it would deploy and show "
                "an empty table forever."
            )
        group = dashboard_raw.get("reviewer_group", "platform-reviewers")
        if not isinstance(group, str) or not group.strip():
            raise ConfigError(
                f"dashboard.reviewer_group is {group!r}; must be a non-empty string. "
                "It names the Cognito group whose members may approve or reject."
            )
        dashboard = DashboardConfig(reviewer_group=group.strip())

    names = [t.name for t in tools]
    duplicates = {n for n in names if names.count(n) > 1}
    if duplicates:
        raise ConfigError(
            f"duplicate tool names: {sorted(duplicates)}. "
            "Tool names must be unique — the Gateway aggregates them into one namespace."
        )

    return Config(
        platform_name=_require_str(platform, "name", "platform"),
        region=platform.get("region", "us-east-1"),
        cognito=cognito,
        tenants=tenants,
        tools=tools,
        enforcement_mode=enforcement_mode,
        registry=registry,
        admission_scan=admission_scan,
        dashboard=dashboard,
    )


def _parse_tool(raw: Any, tenants: list[str]) -> Tool:
    if not isinstance(raw, dict):
        raise ConfigError(f"each entry in tools must be a mapping, got {type(raw).__name__}")

    name = _require_str(raw, "name", "tools[]")
    tenant = _require_str(raw, "tenant", f"tools[{name}]")
    if tenant not in tenants:
        raise ConfigError(
            f"tool {name!r} claims tenant {tenant!r}, which is not declared in tenants: {tenants}"
        )

    args_raw = raw.get("arguments") or {}
    if not isinstance(args_raw, dict):
        raise ConfigError(f"tools[{name}].arguments must be a mapping of name -> spec")

    arguments = [
        ToolArgument(
            name=arg_name,
            type=_require_str(spec, "type", f"tools[{name}].arguments.{arg_name}"),
            description=spec.get("description", ""),
            required=bool(spec.get("required", False)),
        )
        for arg_name, spec in args_raw.items()
    ]

    return Tool(
        name=name,
        tenant=tenant,
        handler=_require_str(raw, "handler", f"tools[{name}]"),
        description=_require_str(raw, "description", f"tools[{name}]").strip(),
        owner=str(raw.get("owner", "")).strip(),
        arguments=arguments,
    )


def _require_mapping(raw: dict[str, Any], key: str) -> dict[str, Any]:
    value = raw.get(key)
    if not isinstance(value, dict):
        raise ConfigError(f"missing or invalid top-level section: {key!r}")
    return value


def _require_list(raw: dict[str, Any], key: str) -> list[Any]:
    value = raw.get(key)
    if not isinstance(value, list) or not value:
        raise ConfigError(f"{key!r} must be a non-empty list")
    return value


def _require_str(raw: Any, key: str, where: str) -> str:
    if not isinstance(raw, dict):
        raise ConfigError(f"{where} must be a mapping")
    value = raw.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"{where}.{key} is required and must be a non-empty string")
    if value.strip().startswith("<"):
        raise ConfigError(f"{where}.{key} is still the placeholder {value.strip()!r}; set it in governance.yaml")
    return value.strip()
