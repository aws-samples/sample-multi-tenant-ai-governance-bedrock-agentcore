# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""The dashboard: a read API plus a static React app.

WHY THIS IS TWO PIECES AND NOT ONE

The browser cannot call the Registry. Every agent-registry-control API is
SigV4/IAM-authenticated and a browser holds a Cognito JWT, so something has to
sit between them. That something is a Lambda behind an HTTP API whose JWT
authorizer points at the SAME Cognito user pool the Gateway uses — so a user who
can call tools can also read the catalogue, with one login and no second
identity system.

WHAT IT DOES NOT DO, STATED UP FRONT

This dashboard reads the catalogue. It does not show, and must not imply, what
anyone is permitted to call. The Gateway does not consult the Registry (verified
on live infrastructure), so a screen full of APPROVED rows says
nothing about reachability. The API returns an explicit `caveat` string and the
UI renders it, because a dashboard is the easiest place in this platform to
accidentally overclaim.

BUILD MODEL: LOCAL, NOT CONTAINERISED

The usual CDK approach bundles a web app inside a Docker container so the build
is reproducible. There is no Docker on the build machine (Podman is installed but
its Linux VM is stopped), and making every `cdk deploy` depend on a background VM
being awake is a bad failure mode — the deploy breaks and the reason is not
obvious. So `dashboard/dist` is built locally by `npm run build` and uploaded as
an asset.

The cost of that choice is that a stale or missing bundle could ship silently, so
_ui_source() FAILS THE SYNTH with instructions instead. A missing dashboard that
stops the deploy is much better than a deployed dashboard showing yesterday's
data, which looks like a caching bug and wastes an afternoon.

S3 + CloudFront, private bucket, OAC. Not an S3 website endpoint: those are
HTTP-only, and serving a page that handles Cognito tokens over plain HTTP would
be indefensible in a governance sample.
"""

from __future__ import annotations

import json
from pathlib import Path

import aws_cdk as cdk
from aws_cdk import aws_apigatewayv2 as apigw
from aws_cdk import aws_apigatewayv2_authorizers as apigw_auth
from aws_cdk import aws_apigatewayv2_integrations as apigw_integ
from aws_cdk import aws_cloudfront as cloudfront
from aws_cdk import aws_cloudfront_origins as origins
from aws_cdk import aws_iam as iam
from aws_cdk import aws_lambda as lambda_
from aws_cdk import aws_logs as logs
from aws_cdk import aws_s3 as s3
from aws_cdk import aws_s3_deployment as s3_deploy
from constructs import Construct

from infra.config import LAMBDA_RESERVED_CONCURRENCY, Config

API_DIR = Path(__file__).resolve().parent
UI_DIR = API_DIR.parent.parent / "dashboard"
UI_DIST = UI_DIR / "dist"
SDK_LAYER_DIR = API_DIR / "sdk_layer"
SDK_LAYER_BUILD = SDK_LAYER_DIR / "build"


# The reviewer group comes from governance.yaml (dashboard.reviewer_group), not
# from a constant here: it is a governance decision, and governance decisions
# live in that file. Reads are open to any authenticated user in the pool, scoped
# to their own tenant; acting on the review queue requires membership.


class Dashboard(Construct):
    """The catalogue's visible surface: HTTP API + CloudFront-hosted React app."""

    def __init__(
        self,
        scope: Construct,
        id: str,
        *,
        config: Config,
        registry_id: str,
        gateway_url: str,
        # Optional, and the API degrades honestly without either: the summary
        # response reports which features are unavailable and why, and the UI
        # hides them. A button that fails with a 503 is worse than no button.
        guardrail_arn: str | None = None,
        guardrail_id: str | None = None,
        decision_log_group: logs.ILogGroup | None = None,
    ) -> None:
        super().__init__(scope, id)

        self.config = config
        self.reviewer_group = config.dashboard.reviewer_group

        self.function = self._create_api_lambda(
            registry_id, gateway_url, guardrail_arn, guardrail_id, decision_log_group
        )
        self.http_api = self._create_http_api()
        self.log_bucket = self._create_log_bucket()
        self.bucket = self._create_bucket()
        self.distribution = self._create_distribution()
        self.deployment = self._deploy_ui()

    # ---------------------------------------------------------------- lambda

    def _create_api_lambda(
        self,
        registry_id: str,
        gateway_url: str,
        guardrail_arn: str | None,
        guardrail_id: str | None,
        decision_log_group: logs.ILogGroup | None,
    ) -> lambda_.Function:
        log_group = logs.LogGroup(
            self,
            "ApiLogs",
            log_group_name=f"/aws/lambda/{self.config.platform_name}-dashboard-api",
            retention=logs.RetentionDays.ONE_MONTH,
            removal_policy=cdk.RemovalPolicy.DESTROY,
        )

        scan = self.config.admission_scan
        fn = lambda_.Function(
            self,
            "Api",
            function_name=f"{self.config.platform_name}-dashboard-api",
            runtime=lambda_.Runtime.PYTHON_3_14,
            architecture=lambda_.Architecture.ARM_64,
            handler="api.handler",
            # Ship api.py only: the CDK construct and the layer recipe in the
            # same directory are deploy-time code, not part of the function.
            code=lambda_.Code.from_asset(
                str(API_DIR),
                exclude=["construct.py", "__init__.py", "__pycache__", "sdk_layer"],
            ),
            # 60s, not the 30 a read-only API needed. A register call is a
            # guardrail invocation plus a create plus a submit, and the audit
            # trail pages through a log group. A timeout part-way through a
            # register leaves a record behind with no response to say so, which
            # is the one outcome worth paying for headroom to avoid.
            timeout=cdk.Duration.seconds(60),
            memory_size=512,
            description="Reads the AWS Agent Registry on behalf of the dashboard",
            log_group=log_group,
            reserved_concurrent_executions=LAMBDA_RESERVED_CONCURRENCY,
            layers=[self._sdk_layer()],
            environment={
                "REGISTRY_ID": registry_id,
                "GATEWAY_URL": gateway_url,
                "ENFORCEMENT_MODE": self.config.enforcement_mode,
                "SCAN_MODE": scan.mode if scan else "OFF",
                "TENANT_CLAIM": self.config.cognito.tenant_claim,
                "REVIEWER_GROUP": self.reviewer_group,
                # The guardrail that scans tool descriptions at registration. Tool
                # arguments are scored at call time by guardrail rules in the
                # policy engine, using the same PROMPT_ATTACK filter.
                "GUARDRAIL_ID": guardrail_id or "",
                "GUARDRAIL_VERSION": "DRAFT",
                "DECISION_LOG_GROUP": (
                    decision_log_group.log_group_name if decision_log_group else ""
                ),
                # Needed to turn Cognito subs into emails in the audit trail. The
                # raw log carries only the sub, so without this every row reads as
                # a hex fragment — useless to the people the trail exists for.
                "USER_POOL_ID": self.config.cognito.user_pool_id,
            },
        )

        # Reads are scoped to the registry and its records. The write action is
        # granted too, but note it is gated in application code by Cognito group
        # membership — IAM cannot express "only if the caller is a reviewer",
        # because the caller here is always this Lambda's role.
        registry_arn = (
            f"arn:{cdk.Aws.PARTITION}:agent-registry:{self.config.region}:"
            f"{cdk.Stack.of(self).account}:registry/{registry_id}"
        )
        registry_arns = [registry_arn, f"{registry_arn}/record/*"]
        fn.add_to_role_policy(
            iam.PolicyStatement(
                sid="ReadAndReviewTheCatalogue",
                actions=[
                    "agent-registry:ListRegistryRecords",
                    "agent-registry:GetRegistryRecord",
                    "agent-registry:GetRegistry",
                    "agent-registry:UpdateRegistryRecordStatus",
                    # Registering from the page. CreateRegistryRecord and Submit
                    # are separate actions because they are separate steps, and
                    # granting only the first would create records that can never
                    # reach a reviewer — a catalogue of permanent drafts.
                    #
                    # NOT granted: DeleteRegistryRecord. The page can propose an
                    # asset and a reviewer can reject it, but nothing here can
                    # make a record disappear. Deletion erases the audit trail,
                    # so it stays with scripts/reset-registry.py and a human at a
                    # terminal.
                    "agent-registry:CreateRegistryRecord",
                    "agent-registry:SubmitRegistryRecordForApproval",
                ],
                resources=registry_arns,
            )
        )

        # The publish-time scan, scoped to the one guardrail ARN — not "*", which would let this Lambda scan against any
        # guardrail in the account including one with everything switched off.
        if guardrail_arn:
            fn.add_to_role_policy(
                iam.PolicyStatement(
                    sid="ScanSubmittedDescriptors",
                    actions=["bedrock:ApplyGuardrail"],
                    resources=[guardrail_arn],
                )
            )

        # The audit trail. Read-only on the one decision log group, and no
        # logs:* wildcard — this Lambda writes to its OWN log group, and a broad
        # grant would let the thing reading the audit trail also write to it.
        if decision_log_group:
            fn.add_to_role_policy(
                iam.PolicyStatement(
                    sid="ReadTheDecisionTrail",
                    actions=["logs:FilterLogEvents", "logs:DescribeLogStreams"],
                    resources=[
                        decision_log_group.log_group_arn,
                        f"{decision_log_group.log_group_arn}:*",
                    ],
                )
            )
            # Turns Cognito subs into emails. ListUsers only — the dashboard has
            # no business creating, disabling or reading any single user, and a
            # broad cognito-idp grant on a governance surface is exactly the kind
            # of thing a security reviewer will ask about.
            user_pool_arn = (
                f"arn:aws:cognito-idp:{self.config.region}:"
                f"{cdk.Stack.of(self).account}:userpool/"
                f"{self.config.cognito.user_pool_id}"
            )
            fn.add_to_role_policy(
                iam.PolicyStatement(
                    sid="NamePrincipalsInTheTrail",
                    actions=["cognito-idp:ListUsers"],
                    resources=[user_pool_arn],
                )
            )
        return fn

    # -------------------------------------------------------------- http api

    def _create_http_api(self) -> apigw.HttpApi:
        """An HTTP API whose JWT authorizer is the same Cognito pool as the Gateway.

        The point is one identity, two surfaces. The
        user does not log in twice, and the tenant claim the dashboard filters on
        is the same claim Cedar reads. Nothing is re-implemented.

        The authorizer validates signature, issuer and audience before the Lambda
        runs, which is why api.py does no token parsing of its own.
        """
        cognito = self.config.cognito
        region = cognito.user_pool_id.split("_", 1)[0]

        authorizer = apigw_auth.HttpJwtAuthorizer(
            "CognitoAuthorizer",
            jwt_issuer=f"https://cognito-idp.{region}.amazonaws.com/{cognito.user_pool_id}",
            jwt_audience=[cognito.app_client_id],
            identity_source=["$request.header.Authorization"],
        )

        api = apigw.HttpApi(
            self,
            # Not "Api" — the Lambda above already owns that id inside this
            # construct, and CDK rejects the duplicate rather than disambiguating.
            "HttpApi",
            api_name=f"{self.config.platform_name}-dashboard",
            description="Read the AI asset catalogue. Same Cognito pool as the Gateway.",
            cors_preflight=apigw.CorsPreflightOptions(
                # The React app is served from CloudFront, a different origin
                # from the API, so preflight is required. Left as ANY_ORIGIN
                # deliberately for a reference architecture: pinning it to the
                # CloudFront domain creates a circular dependency (the
                # distribution needs the API URL to build the app config, and
                # the API would need the distribution domain). A real deployment
                # with a known custom domain should pin it, and that is a
                # one-line change here.
                allow_origins=["*"],
                allow_headers=["authorization", "content-type"],
                allow_methods=[
                    apigw.CorsHttpMethod.GET,
                    apigw.CorsHttpMethod.POST,
                    apigw.CorsHttpMethod.OPTIONS,
                ],
                max_age=cdk.Duration.hours(1),
            ),
        )

        integration = apigw_integ.HttpLambdaIntegration("ApiIntegration", self.function)
        for method, path in (
            (apigw.HttpMethod.GET, "/api/summary"),
            (apigw.HttpMethod.GET, "/api/records"),
            (apigw.HttpMethod.GET, "/api/decisions"),
            # POST /api/records and POST /api/records/{id}/status are distinct
            # routes, and HTTP API matches the literal segment before the greedy
            # one — so registering does not shadow approving. api.py matches the
            # first on equality rather than prefix for the same reason.
            (apigw.HttpMethod.POST, "/api/records"),
            (apigw.HttpMethod.POST, "/api/records/{id}/status"),
        ):
            api.add_routes(
                path=path,
                methods=[method],
                integration=integration,
                authorizer=authorizer,
            )
        self._enable_api_access_logs(api)
        return api

    def _sdk_layer(self) -> lambda_.LayerVersion:
        """A current boto3 for the dashboard API.

        The Lambda Python runtime's built-in boto3 predates the agent-registry
        service and fails with "Unknown service: 'agent-registry-control'".
        The layer's python/ directory is on the import path ahead of the
        runtime's own copy, so the function picks up this one.

        The layer is built by a pip install step before deploy (see the README),
        like the dashboard's npm build, and CDK only packages the result.
        """
        if not (SDK_LAYER_BUILD / "python" / "boto3").is_dir():
            raise FileNotFoundError(
                f"{SDK_LAYER_BUILD}/python/boto3 not found — the SDK layer has not been built.\n"
                f"  pip install --requirement {SDK_LAYER_DIR}/requirements.txt "
                f"--target {SDK_LAYER_BUILD}/python --python-version 3.14 --only-binary :all: --no-compile"
            )
        return lambda_.LayerVersion(
            self,
            "SdkLayer",
            description="boto3 with the agent-registry client, for the dashboard API",
            compatible_runtimes=[lambda_.Runtime.PYTHON_3_14],
            compatible_architectures=[lambda_.Architecture.ARM_64],
            code=lambda_.Code.from_asset(str(SDK_LAYER_BUILD)),
        )

    def _enable_api_access_logs(self, api: apigw.HttpApi) -> None:
        """One log line per API request: caller, route, status and latency.

        HttpApi creates its $default stage itself and takes no log settings, so
        they go on the stage resource underneath. That keeps the same stage and
        the same API URL.
        """
        log_group = logs.LogGroup(
            self,
            "ApiAccessLogs",
            log_group_name=f"/aws/apigateway/{self.config.platform_name}-dashboard",
            retention=logs.RetentionDays.ONE_MONTH,
            removal_policy=cdk.RemovalPolicy.DESTROY,
        )
        stage = api.default_stage.node.default_child
        stage.access_log_settings = apigw.CfnStage.AccessLogSettingsProperty(
            destination_arn=log_group.log_group_arn,
            format=json.dumps({
                "requestId": "$context.requestId",
                "requestTime": "$context.requestTime",
                "sourceIp": "$context.identity.sourceIp",
                "caller": "$context.authorizer.claims.email",
                "routeKey": "$context.routeKey",
                "status": "$context.status",
                "responseLength": "$context.responseLength",
                "latencyMs": "$context.responseLatency",
                "integrationError": "$context.integrationErrorMessage",
            }),
        )

    # --------------------------------------------------------------- hosting

    def _create_log_bucket(self) -> s3.Bucket:
        """Access logs for the site bucket and the CloudFront distribution.

        CloudFront standard logging writes with an ACL, so this bucket keeps
        ACLs enabled (OBJECT_WRITER); every other bucket here enforces bucket
        ownership. Logs expire after 30 days and the bucket is emptied and
        deleted with the stack. It does not log access to itself: a log bucket
        that logs to itself logs its own log writes.
        """
        return s3.Bucket(
            self,
            "AccessLogBucket",
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            encryption=s3.BucketEncryption.S3_MANAGED,
            enforce_ssl=True,
            object_ownership=s3.ObjectOwnership.OBJECT_WRITER,
            versioned=True,
            lifecycle_rules=[
                s3.LifecycleRule(
                    expiration=cdk.Duration.days(30),
                    noncurrent_version_expiration=cdk.Duration.days(7),
                )
            ],
            removal_policy=cdk.RemovalPolicy.DESTROY,
            auto_delete_objects=True,
        )

    def _create_bucket(self) -> s3.Bucket:
        # Versioned, so an overwritten or deleted build can be recovered. Old
        # versions expire after 30 days: every deploy replaces the whole bundle.
        return s3.Bucket(
            self,
            "SiteBucket",
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            encryption=s3.BucketEncryption.S3_MANAGED,
            enforce_ssl=True,
            versioned=True,
            lifecycle_rules=[
                s3.LifecycleRule(noncurrent_version_expiration=cdk.Duration.days(30))
            ],
            server_access_logs_bucket=self.log_bucket,
            server_access_logs_prefix="s3/",
            removal_policy=cdk.RemovalPolicy.DESTROY,
            auto_delete_objects=True,
        )

    def _create_distribution(self) -> cloudfront.Distribution:
        """CloudFront in front of a private bucket, via Origin Access Control.

        Not an S3 website endpoint: those serve HTTP only, and this page handles
        Cognito tokens. HTTPS is not optional for that.

        The 403 -> index.html rewrite is what makes a single-page app work: S3
        returns 403 (not 404) for an unknown key on a private bucket, and without
        this any deep link or refresh shows an error page.
        """
        return cloudfront.Distribution(
            self,
            "SiteDistribution",
            default_behavior=cloudfront.BehaviorOptions(
                origin=origins.S3BucketOrigin.with_origin_access_control(self.bucket),
                viewer_protocol_policy=cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
                cache_policy=cloudfront.CachePolicy.CACHING_OPTIMIZED,
            ),
            default_root_object="index.html",
            error_responses=[
                cloudfront.ErrorResponse(
                    http_status=403,
                    response_http_status=200,
                    response_page_path="/index.html",
                    ttl=cdk.Duration.minutes(1),
                ),
                cloudfront.ErrorResponse(
                    http_status=404,
                    response_http_status=200,
                    response_page_path="/index.html",
                    ttl=cdk.Duration.minutes(1),
                ),
            ],
            comment=f"{self.config.platform_name} governance dashboard",
            enable_logging=True,
            log_bucket=self.log_bucket,
            log_file_prefix="cloudfront/",
        )

    def _deploy_ui(self) -> s3_deploy.BucketDeployment:
        """Upload the built React app, plus a runtime config file.

        config.json is written HERE rather than baked into the bundle at build
        time, and that is deliberate: the API URL and Cognito ids are known to
        CloudFormation, not to npm. Baking them in would mean rebuilding the
        bundle for every environment and would make `npm run build` depend on a
        deployed stack. This way the same bundle works anywhere.
        """
        cognito = self.config.cognito
        scan = self.config.admission_scan

        return s3_deploy.BucketDeployment(
            self,
            "Deploy",
            sources=[
                self._ui_source(),
                s3_deploy.Source.json_data(
                    "config.json",
                    {
                        "apiUrl": self.http_api.api_endpoint,
                        "region": self.config.region,
                        "userPoolId": cognito.user_pool_id,
                        "clientId": cognito.app_client_id,
                        "platformName": self.config.platform_name,
                        "enforcementMode": self.config.enforcement_mode,
                        "scanMode": scan.mode if scan else "OFF",
                        "reviewerGroup": self.reviewer_group,
                    },
                ),
            ],
            destination_bucket=self.bucket,
            distribution=self.distribution,
            # Invalidate everything. The app is a handful of files, so the cost
            # is trivial, and a partially invalidated site showing stale data is
            # the worst possible outcome.
            distribution_paths=["/*"],
            prune=True,
        )

    def _ui_source(self) -> s3_deploy.ISource:
        """The built bundle — or a synth failure that says how to build it.

        This is the guard that makes the local-build model safe. Without it, a
        missing dist/ deploys an empty bucket and the dashboard shows nothing,
        which looks like an API or auth problem and sends you debugging the wrong
        layer entirely.
        """
        if not (UI_DIST / "index.html").is_file():
            raise FileNotFoundError(
                f"{UI_DIST}/index.html not found — the dashboard has not been built.\n"
                f"  cd {UI_DIR} && npm install && npm run build\n"
                "The build is local rather than containerised because there is no "
                "Docker on this machine; see the module docstring."
            )
        return s3_deploy.Source.asset(str(UI_DIST))

    # --------------------------------------------------------------- outputs

    @property
    def url(self) -> str:
        return f"https://{self.distribution.distribution_domain_name}"

    @property
    def api_url(self) -> str:
        return self.http_api.api_endpoint
