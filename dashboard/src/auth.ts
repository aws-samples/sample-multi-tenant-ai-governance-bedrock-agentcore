/* Cognito login, straight from the browser.
 *
 * SRP against the user pool, not the hosted UI. Two reasons, and the second one
 * is the reason it matters:
 *
 * · The deployed app client has no callback URLs and no OAuth flows configured
 *   (verified), so a redirect-based login would need infrastructure that does not
 *   exist yet. SRP works with what is deployed.
 *
 * · The dashboard must send the SAME token type the Gateway accepts — the ID
 *   token, not the access token. The Gateway rejects an access token with
 *   403 insufficient_scope because it carries no custom:tenant claim. Using the
 *   ID token here keeps one rule for the whole platform: everything sends the
 *   ID token. Sending the access token would work against this API (the JWT
 *   authorizer would accept it) and then fail confusingly for tenant scoping,
 *   because the claim the API filters on would simply be absent.
 *
 * No token is written to localStorage. It lives in memory for the page's
 * lifetime, so a refresh means logging in again. That is a deliberate trade of
 * convenience for not persisting a bearer token in a place that outlives its
 * expiry — the same reasoning that keeps the JWT out of ~/.claude.json.
 */

import {
  CognitoUser,
  CognitoUserPool,
  AuthenticationDetails,
} from 'amazon-cognito-identity-js'
import type { AppConfig } from './config'

export type Session = {
  idToken: string
  email: string
  tenant: string
  groups: string[]
}

export function signIn(cfg: AppConfig, email: string, password: string): Promise<Session> {
  const pool = new CognitoUserPool({
    UserPoolId: cfg.userPoolId,
    ClientId: cfg.clientId,
  })
  const user = new CognitoUser({ Username: email, Pool: pool })
  const details = new AuthenticationDetails({ Username: email, Password: password })

  return new Promise((resolve, reject) => {
    user.authenticateUser(details, {
      onSuccess: (result) => {
        const idToken = result.getIdToken()
        const claims = idToken.decodePayload() as Record<string, unknown>
        resolve({
          idToken: idToken.getJwtToken(),
          email: String(claims.email ?? email),
          // Read the claim by its configured name. Hard-coding 'custom:tenant'
          // would silently break if governance.yaml changed tenant_claim.
          tenant: String(claims['custom:tenant'] ?? ''),
          groups: normaliseGroups(claims['cognito:groups']),
        })
      },
      onFailure: (err) => reject(new Error(err.message || String(err))),
      newPasswordRequired: () =>
        reject(
          new Error(
            'this user must set a new password before signing in — do it in the ' +
              'Cognito console, or reset it with the AWS CLI',
          ),
        ),
    })
  })
}

/* cognito:groups can arrive as an array or a bracketed string depending on how
 * the token was minted. Both shapes are real. Assuming one means group
 * membership evaluates false, which fails closed (no reviewer rights) and so
 * presents as a permissions problem rather than a parsing one. */
function normaliseGroups(raw: unknown): string[] {
  if (Array.isArray(raw)) return raw.map(String)
  if (typeof raw === 'string') {
    return raw
      .replace(/[[\]]/g, '')
      .split(/[\s,]+/)
      .filter(Boolean)
  }
  return []
}
