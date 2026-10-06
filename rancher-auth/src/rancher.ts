// The few Rancher calls the proxy makes. Tokens are Rancher "ext" API tokens
// (ext.cattle.io/v1 Token), the same kind as Account & API Keys.

export class RancherError extends Error {
  constructor(message: string, readonly status: number) {
    super(message);
  }

  /** Rancher no longer accepts the credential: deleted, expired, or the user lost access. */
  get unauthorized() {
    return this.status === 401;
  }
}

export interface RancherToken {
  name: string;
  userId: string;
  labels: Record<string, string>;
}

export interface CreatedToken extends RancherToken {
  bearer: string;
  expiresAt: Date;
}

export interface CodeExchange {
  code: string;
  codeVerifier: string;
  redirectUri: string;
  clientId: string;
  clientSecret: string;
}

const TIMEOUT_MS = 15_000;

export class Rancher {
  constructor(private readonly baseUrl: URL) {}

  /** Exchanges an /oidc/authorize code for Rancher's access token, a JWT bound to the person's login session. */
  async exchangeCode({ code, codeVerifier, redirectUri, clientId, clientSecret }: CodeExchange): Promise<string> {
    const body = await this.request("/oidc/token", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        code_verifier: codeVerifier,
        redirect_uri: redirectUri,
        client_id: clientId,
        client_secret: clientSecret,
      }),
    });
    if (typeof body?.access_token !== "string") throw new RancherError("Rancher returned no access token", 502);
    return body.access_token;
  }

  async createToken(
    bearer: string,
    spec: { description: string; ttlMs: number; labels: Record<string, string> },
  ): Promise<CreatedToken> {
    const token = await this.request("/v1/ext.cattle.io.tokens", {
      method: "POST",
      bearer,
      json: {
        type: "ext.cattle.io.token",
        apiVersion: "ext.cattle.io/v1",
        kind: "Token",
        metadata: { labels: spec.labels },
        spec: { description: spec.description, ttl: spec.ttlMs },
      },
    });
    return {
      ...toToken(token),
      bearer: token.status.bearerToken,
      expiresAt: new Date(token.status.expiresAt),
    };
  }

  /** Lists the bearer's own tokens carrying the given label. */
  async listTokens(bearer: string, label: { key: string; value: string }): Promise<RancherToken[]> {
    const query = new URLSearchParams({ labelSelector: `${label.key}=${label.value}` });
    const body = await this.request(`/v1/ext.cattle.io.tokens?${query}`, { bearer });
    return (body.data ?? []).map(toToken).filter((token: RancherToken) => token.labels[label.key] === label.value);
  }

  async deleteToken(bearer: string, name: string): Promise<void> {
    await this.request(`/v1/ext.cattle.io.tokens/${encodeURIComponent(name)}`, { method: "DELETE", bearer });
  }

  private async request(
    path: string,
    { bearer, json, ...init }: RequestInit & { bearer?: string; json?: unknown } = {},
  ): Promise<any> {
    const headers = new Headers(init.headers);
    headers.set("accept", "application/json");
    if (bearer) headers.set("authorization", `Bearer ${bearer}`);
    if (json !== undefined) headers.set("content-type", "application/json");

    let res: Response;
    try {
      res = await fetch(new URL(path, this.baseUrl), {
        ...init,
        headers,
        body: json === undefined ? init.body : JSON.stringify(json),
        signal: AbortSignal.timeout(TIMEOUT_MS),
      });
    } catch (error) {
      throw new RancherError(`Rancher request failed: ${(error as Error).message}`, 503);
    }

    const text = await res.text();
    if (!res.ok) {
      throw new RancherError(`${init.method ?? "GET"} ${path.split("?")[0]} returned ${res.status}: ${text.slice(0, 200)}`, res.status);
    }
    return text ? JSON.parse(text) : null;
  }
}

function toToken(token: any): RancherToken {
  return {
    name: token.metadata.name,
    userId: token.spec.userID,
    labels: token.metadata.labels ?? {},
  };
}

/** The token name from an `ext/<name>:<secret>` bearer value. */
export function tokenName(bearer: string): string {
  return bearer.replace(/^ext\//, "").split(":")[0];
}
