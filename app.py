#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""CDK entry point. Reads governance.yaml, deploys the Gateway stack."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import aws_cdk as cdk

from infra.config import ConfigError, load
from infra.gateway.stack import GatewayStack


def main() -> None:
    try:
        config = load(Path(__file__).parent / "governance.yaml")
    except ConfigError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)

    app = cdk.App()
    GatewayStack(
        app,
        "AiGovernanceGateway",
        config=config,
        env=cdk.Environment(region=config.region),
        description="Multi-tenant AI agent governance with Amazon Bedrock AgentCore (sample)",
    )
    app.synth()


if __name__ == "__main__":
    main()
