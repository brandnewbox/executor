import { randomBytes } from "node:crypto";
import { Rancher, tokenName, type CreatedToken } from "./rancher";

// A grant is one Executor connection's chain of Rancher tokens. Each person who
// connects gets:
//
// - an access token: a short-lived Rancher API token Executor sends to Rancher.
// - a refresh credential: a long-lived Rancher API token that only the proxy
//   uses, to mint the next access token and the next refresh credential.
//   Executor holds it sealed inside its refresh token, so it can't use it directly.
//
// Every refresh replaces both, which slides the refresh credential's expiry
// forward: a connection that is used at least once per refresh TTL never has
// to sign in again. All tokens carry the grant's label, so a refresh also
// deletes the grant's older tokens. The refresh credential presented is kept
// until its successor is used, in case Executor failed to store the new one.

export const GRANT_LABEL = "rancher-auth.brandnewbox.com/grant";
export const ROLE_LABEL = "rancher-auth.brandnewbox.com/role";

export interface Grant {
  id: string;
  /** Bearer value of the current refresh credential. */
  credential: string;
}

export interface IssuedGrant {
  grant: Grant;
  access: CreatedToken;
}

export interface GrantTtls {
  accessTokenTtlMs: number;
  refreshCredentialTtlMs: number;
}

/** Starts a grant with the Rancher OIDC JWT from sign-in, which stops working when the login session ends. */
export async function startGrant(rancher: Rancher, jwt: string, ttls: GrantTtls): Promise<IssuedGrant> {
  const id = randomBytes(16).toString("hex");
  const credential = await createRefreshCredential(rancher, jwt, id, ttls);
  const access = await createAccessToken(rancher, credential.bearer, id, ttls);
  log("grant started", { grant: id, user: access.userId, access: access.name, refresh: credential.name });
  return { grant: { id, credential: credential.bearer }, access };
}

/** Rotates the grant's tokens. Throws a RancherError with `unauthorized` once Rancher rejects the refresh credential. */
export async function renewGrant(rancher: Rancher, grant: Grant, ttls: GrantTtls): Promise<IssuedGrant> {
  const credential = await createRefreshCredential(rancher, grant.credential, grant.id, ttls);
  const access = await createAccessToken(rancher, credential.bearer, grant.id, ttls);

  const keep = new Set([tokenName(grant.credential), credential.name, access.name]);
  const deleted: string[] = [];
  try {
    for (const token of await rancher.listTokens(credential.bearer, { key: GRANT_LABEL, value: grant.id })) {
      if (keep.has(token.name)) continue;
      await rancher.deleteToken(credential.bearer, token.name);
      deleted.push(token.name);
    }
  } catch (error) {
    // Leftovers are cleaned up on the next refresh; don't fail this one for them.
    log("cleanup failed", { grant: grant.id, error: (error as Error).message });
  }

  log("grant renewed", { grant: grant.id, user: access.userId, access: access.name, refresh: credential.name, deleted });
  return { grant: { id: grant.id, credential: credential.bearer }, access };
}

function createRefreshCredential(rancher: Rancher, bearer: string, grantId: string, ttls: GrantTtls) {
  return rancher.createToken(bearer, {
    description: "Executor refresh credential (rancher-auth). Delete to disconnect Executor.",
    ttlMs: ttls.refreshCredentialTtlMs,
    labels: { [GRANT_LABEL]: grantId, [ROLE_LABEL]: "refresh" },
  });
}

function createAccessToken(rancher: Rancher, bearer: string, grantId: string, ttls: GrantTtls) {
  return rancher.createToken(bearer, {
    description: "Executor access token (rancher-auth). Replaced automatically.",
    ttlMs: ttls.accessTokenTtlMs,
    labels: { [GRANT_LABEL]: grantId, [ROLE_LABEL]: "access" },
  });
}

export function log(event: string, fields: Record<string, unknown> = {}) {
  console.log(JSON.stringify({ time: new Date().toISOString(), event, ...fields }));
}
