/* Calls to the dashboard API.
 *
 * Every request carries the Cognito ID token. API Gateway's JWT authorizer
 * validates it before the Lambda runs, so a 401 here means the token expired
 * (~1 hour) rather than anything subtler — and the UI says exactly that, because
 * "unauthorised" on its own sends people looking at IAM.
 */

import type { AppConfig } from './config'

/* Named AssetRecord, not Record: TypeScript's built-in Record<K,V> utility type
 * is used two lines below, and shadowing it produces an error that reads like a
 * generics problem rather than a naming one. */
export type AssetRecord = {
  id: string
  name: string
  description: string
  tenant: string
  owner: string
  type: string
  status: string
  statusReason: string
  createdAt: string
  updatedAt: string
}

export type Summary = {
  records: AssetRecord[]
  counts: Record<string, number>
  viewer: { email: string; tenant: string; isReviewer: boolean }
  platform: { gatewayUrl: string; enforcementMode: string; scanMode: string }
  /* What this deployment can actually do. The UI hides a feature it cannot
   * support rather than offering a button that fails — and shows the stated
   * reason, so "missing" never has to be guessed at. */
  capabilities: {
    register: boolean
    registerDisabledBecause: string
    auditTrail: boolean
    auditDisabledBecause: string
  }
  caveat: string
}

/* The verdict from the publish-time guardrail scan.
 *
 * blocked and failed are separate fields on purpose. blocked means the scan ran
 * and found something; failed means the scan could not run at all. Both refuse
 * the registration, but they are different facts, and a UI that renders an
 * outage as a detection would be reporting a control that worked when it
 * did not. */
export type ScanVerdict = {
  blocked: boolean
  reasons: string[]
  latencyMs: number | null
  failed: boolean
  guardrailId: string
}

export type Decision = {
  requestId: string
  at: number
  tool: string
  decision: string
  principal: string
  determiningPolicies: string[]
  reason: string
  /* The contradiction only LOG_ONLY can produce: the policy said DENY and the
   * caller got their data anyway. Computed by the API rather than inferred here,
   * so both surfaces agree on what it means. */
  succeededDespiteDeny: boolean
  blocked: boolean
}

export type Decisions = {
  decisions: Decision[]
  scopedTo: string | null
  minutes: number
  limits: string[]
  unavailable?: string
  /* Set when the window held more events than one read returns. The
   * explanation is appended to `limits`, which is already on screen. */
  truncated?: boolean
}

export type Registered = {
  id: string
  name: string
  status: string
  scan: ScanVerdict
  note?: string
  warning?: string
}

export async function fetchSummary(cfg: AppConfig, token: string): Promise<Summary> {
  return call<Summary>(cfg, token, '/api/summary')
}

export async function fetchDecisions(
  cfg: AppConfig,
  token: string,
  minutes = 60,
): Promise<Decisions> {
  return call<Decisions>(cfg, token, `/api/decisions?minutes=${minutes}`)
}

/* Register an asset. Only the name and description are sent: tenant and owner
 * come from the caller's token server-side, so there is nothing to send and
 * nothing a form could falsify. */
export async function registerAsset(
  cfg: AppConfig,
  token: string,
  name: string,
  description: string,
): Promise<Registered> {
  return call<Registered>(cfg, token, '/api/records', {
    method: 'POST',
    body: JSON.stringify({ name, description }),
  })
}

export async function setStatus(
  cfg: AppConfig,
  token: string,
  id: string,
  status: string,
  reason: string,
): Promise<void> {
  await call(cfg, token, `/api/records/${encodeURIComponent(id)}/status`, {
    method: 'POST',
    body: JSON.stringify({ status, reason }),
  })
}

/* An error that keeps the response body.
 *
 * Needed for one case specifically: a registration refused by the scan returns
 * 422 with the guardrail's reasons attached, and those reasons are what the user
 * needs to see: "PROMPT_ATTACK (HIGH confidence)" explains the refusal. Throwing a
 * plain Error would reduce that to a sentence and drop the evidence. */
export class ApiError extends Error {
  status: number
  scan?: ScanVerdict
  why?: string

  constructor(status: number, message: string, body: unknown) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    if (body && typeof body === 'object') {
      const b = body as { scan?: ScanVerdict; why?: string }
      this.scan = b.scan
      this.why = b.why
    }
  }
}

async function call<T>(
  cfg: AppConfig,
  token: string,
  path: string,
  init: RequestInit = {},
): Promise<T> {
  const res = await fetch(`${cfg.apiUrl}${path}`, {
    ...init,
    headers: {
      authorization: `Bearer ${token}`,
      'content-type': 'application/json',
      ...(init.headers ?? {}),
    },
  })

  if (res.status === 401) {
    throw new Error('token rejected or expired — sign in again (tokens last ~1 hour)')
  }

  const text = await res.text()
  let body: unknown = null
  try {
    body = text ? JSON.parse(text) : null
  } catch {
    // Fall through: a non-JSON body from an API that always returns JSON is
    // itself the useful signal, so surface it verbatim rather than masking it.
  }

  if (!res.ok) {
    const detail =
      body && typeof body === 'object' && 'error' in body
        ? String((body as { error: unknown }).error)
        : text || `HTTP ${res.status}`
    throw new ApiError(res.status, detail, body)
  }
  return body as T
}
