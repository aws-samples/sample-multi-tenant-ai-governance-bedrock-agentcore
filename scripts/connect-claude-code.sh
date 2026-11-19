#!/usr/bin/env bash
#
# The end-user experience, in one script.
#
# This is what a developer at a customer runs once to point Claude Code at the
# governed Gateway. After this, every MCP tool they can see has been through
# the Gateway and through Cedar policy.
#
#   export AWS_PROFILE=<your-profile>
#   source scripts/connect-claude-code.sh john@company.com '<password>'
#
# MUST be sourced, not executed — it exports AIGOV_TOKEN into your shell, and a
# subprocess cannot do that for you.
#
# Two things worth knowing:
#
#   1. Claude Code MUST be given the Cognito ID token. The access token is
#      rejected by the Gateway with HTTP 403 "insufficient_scope", because
#      custom:tenant is not a claim on the access token. Cedar therefore has no
#      tenant to fence on. Pass IdToken.
#
#   2. The token goes in an ENVIRONMENT VARIABLE, never inline. Passing
#      --header "Authorization: Bearer <token>" writes the raw JWT in cleartext
#      into ~/.claude.json, where it persists long after it expires. Claude Code
#      expands ${AIGOV_TOKEN} in headers at connect time, so the config file
#      stays free of secrets.

set -u

# NB: not "USERNAME" — macOS already exports that, and it silently wins.
AIGOV_USER="${1:-john@company.com}"
AIGOV_PASS="${2:-}"
REGION="${AIGOV_REGION:-us-east-1}"
STACK="${AIGOV_STACK:-AiGovernanceGateway}"

if [ -z "$AIGOV_PASS" ]; then
  echo "usage: source scripts/connect-claude-code.sh <username> <password>" >&2
  return 1 2>/dev/null || exit 1
fi

AIGOV_ROOT="${AIGOV_ROOT:-$PWD}"

POOL_ID=$(awk '/user_pool_id:/ {print $2}' "$AIGOV_ROOT/governance.yaml")
CLIENT_ID=$(awk '/app_client_id:/ {print $2}' "$AIGOV_ROOT/governance.yaml")

GATEWAY_URL=$(aws cloudformation describe-stacks \
  --stack-name "$STACK" --region "$REGION" \
  --query "Stacks[0].Outputs[?OutputKey=='GatewayUrl'].OutputValue" \
  --output text)

if [ -z "$GATEWAY_URL" ] || [ "$GATEWAY_URL" = "None" ]; then
  echo "could not read GatewayUrl from stack $STACK — is it deployed?" >&2
  return 1 2>/dev/null || exit 1
fi

# IdToken, deliberately. See note 1 above.
AIGOV_TOKEN=$(aws cognito-idp admin-initiate-auth \
  --region "$REGION" \
  --user-pool-id "$POOL_ID" \
  --client-id "$CLIENT_ID" \
  --auth-flow ADMIN_USER_PASSWORD_AUTH \
  --auth-parameters "USERNAME=$AIGOV_USER,PASSWORD=$AIGOV_PASS" \
  --query 'AuthenticationResult.IdToken' --output text)

if [ -z "$AIGOV_TOKEN" ] || [ "$AIGOV_TOKEN" = "None" ]; then
  echo "login failed for $AIGOV_USER" >&2
  return 1 2>/dev/null || exit 1
fi
export AIGOV_TOKEN

# Idempotent: re-registering the same name errors, so clear it first.
claude mcp remove aigov -s local >/dev/null 2>&1 || true
claude mcp add --transport http aigov "$GATEWAY_URL" \
  --header 'Authorization: Bearer ${AIGOV_TOKEN}' -s local >/dev/null

echo "connected as $AIGOV_USER"
echo "gateway : $GATEWAY_URL"
echo
echo "Now run:  claude mcp list        # expect: aigov ... ✔ Connected"
echo "Then ask Claude Code to use the finance-reports or jira-search tool."
echo
echo "Token is in \$AIGOV_TOKEN in THIS shell only, and expires in ~1 hour."
echo "A new shell needs to source this script again."
