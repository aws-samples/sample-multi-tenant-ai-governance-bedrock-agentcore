/* Runtime configuration, fetched rather than compiled in.
 *
 * config.json is written by CDK at deploy time (see infra/dashboard/construct.py)
 * because the API URL and Cognito ids are known to CloudFormation, not to npm.
 * The consequence worth knowing: this bundle is environment-agnostic — the same
 * build works against any deployment, and `npm run build` never needs a deployed
 * stack.
 *
 * If the fetch fails the app says so plainly instead of rendering an empty table.
 * An empty table and a broken config look identical on screen, and telling them
 * apart at a glance is worth more here than a tidier loading state.
 */

export type AppConfig = {
  apiUrl: string
  region: string
  userPoolId: string
  clientId: string
  platformName: string
  enforcementMode: string
  scanMode: string
  reviewerGroup: string
}

export async function loadConfig(): Promise<AppConfig> {
  // '/config.json', not './config.json'. On a deep link like /reviews the
  // relative form resolves to /reviews/config.json, which the CloudFront SPA
  // rewrite answers with index.html — a 200 carrying HTML, so the fetch
  // succeeds and res.json() throws a parse error that names neither the real
  // path nor the real cause. Same reason vite.config.ts uses base '/'.
  const res = await fetch('/config.json', { cache: 'no-store' })
  if (!res.ok) {
    throw new Error(
      `could not load config.json (HTTP ${res.status}). The dashboard cannot ` +
        `know where its API is. This is a deployment problem, not a login one.`,
    )
  }
  const cfg = (await res.json().catch(() => {
    throw new Error(
      'config.json returned something that is not JSON — most likely index.html, ' +
        'which means the file was not deployed and CloudFront fell back to the SPA ' +
        'rewrite. Check the BucketDeployment.',
    )
  })) as Partial<AppConfig>
  // Check the values that must exist. A missing clientId fails later at login
  // with a confusing Cognito error; failing here names the actual cause.
  for (const key of ['apiUrl', 'userPoolId', 'clientId'] as const) {
    if (!cfg[key]) throw new Error(`config.json is missing ${key}`)
  }
  return cfg as AppConfig
}
