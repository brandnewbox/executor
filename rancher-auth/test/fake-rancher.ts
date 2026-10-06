import { createHash, randomBytes } from "node:crypto";

// Just enough of Rancher's OIDC provider and ext token API for the proxy:
// login sessions back OIDC JWTs, and ext tokens outlive them.

interface StoredToken {
  name: string;
  userId: string;
  secret: string;
  labels: Record<string, string>;
  description: string;
  ttl: number;
  expiresAt: number;
}

export const MAX_TTL_MS = 90 * 24 * 60 * 60 * 1000;

export class FakeRancher {
  readonly tokens = new Map<string, StoredToken>();
  /** When set, every API call fails with this status, as if Rancher were down. */
  failWith: number | null = null;
  private readonly codes = new Map<string, { userId: string; challenge: string; redirectUri: string }>();
  private readonly sessions = new Map<string, string>();
  private nextToken = 1;
  private readonly server = Bun.serve({ port: 0, fetch: (req) => this.handle(req) });

  constructor(readonly client: { id: string; secret: string }) {}

  get url() {
    return `http://localhost:${this.server.port}`;
  }

  stop() {
    this.server.stop(true);
  }

  /** What Rancher's /oidc/authorize does once the person is logged in: issue a code for them. */
  approve(authorizeUrl: string, userId: string): string {
    const params = new URL(authorizeUrl).searchParams;
    const code = randomBytes(8).toString("hex");
    this.codes.set(code, { userId, challenge: params.get("code_challenge")!, redirectUri: params.get("redirect_uri")! });
    return code;
  }

  /** Logs the person out: every JWT issued from their login session stops working. */
  endSessions(userId: string) {
    for (const [jwt, owner] of this.sessions) if (owner === userId) this.sessions.delete(jwt);
  }

  userFor(bearer: string): string | null {
    if (bearer.startsWith("ext/")) {
      const [name, secret] = bearer.slice(4).split(":");
      const token = this.tokens.get(name);
      return token && token.secret === secret && token.expiresAt > Date.now() ? token.userId : null;
    }
    return this.sessions.get(bearer) ?? null;
  }

  tokensFor(userId: string) {
    return [...this.tokens.values()].filter((token) => token.userId === userId);
  }

  private async handle(req: Request): Promise<Response> {
    const url = new URL(req.url);
    if (this.failWith) return new Response("unavailable", { status: this.failWith });

    if (req.method === "POST" && url.pathname === "/oidc/token") {
      const form = new URLSearchParams(await req.text());
      const pending = this.codes.get(form.get("code") ?? "");
      this.codes.delete(form.get("code") ?? "");
      const verified =
        pending &&
        form.get("client_id") === this.client.id &&
        form.get("client_secret") === this.client.secret &&
        form.get("redirect_uri") === pending.redirectUri &&
        createHash("sha256").update(form.get("code_verifier") ?? "").digest("base64url") === pending.challenge;
      if (!verified) return Response.json({ error: "invalid_grant" }, { status: 400 });

      const jwt = `jwt-${randomBytes(8).toString("hex")}`;
      this.sessions.set(jwt, pending.userId);
      // Rancher reports expires_in in nanoseconds.
      return Response.json({ access_token: jwt, token_type: "Bearer", expires_in: 3_600_000_000_000 });
    }

    const userId = this.userFor(req.headers.get("authorization")?.replace(/^Bearer /, "") ?? "");
    if (!userId) return Response.json({ message: "must authenticate" }, { status: 401 });

    if (req.method === "POST" && url.pathname === "/v1/ext.cattle.io.tokens") {
      const body = await req.json();
      const ttl = Math.min(body.spec.ttl || MAX_TTL_MS, MAX_TTL_MS);
      const token: StoredToken = {
        name: `token-${this.nextToken++}`,
        userId,
        secret: randomBytes(16).toString("hex"),
        labels: body.metadata?.labels ?? {},
        description: body.spec.description,
        ttl,
        expiresAt: Date.now() + ttl,
      };
      this.tokens.set(token.name, token);
      return Response.json(
        {
          ...this.toResource(token),
          status: { bearerToken: `ext/${token.name}:${token.secret}`, expiresAt: new Date(token.expiresAt).toISOString() },
        },
        { status: 201 },
      );
    }

    if (req.method === "GET" && url.pathname === "/v1/ext.cattle.io.tokens") {
      const [key, value] = (url.searchParams.get("labelSelector") ?? "").split("=");
      const data = this.tokensFor(userId)
        .filter((token) => !key || token.labels[key] === value)
        .map((token) => this.toResource(token));
      return Response.json({ data });
    }

    const deleteMatch = url.pathname.match(/^\/v1\/ext\.cattle\.io\.tokens\/(.+)$/);
    if (req.method === "DELETE" && deleteMatch) {
      const token = this.tokens.get(deleteMatch[1]);
      if (!token || token.userId !== userId) return Response.json({ message: "not found" }, { status: 404 });
      this.tokens.delete(token.name);
      return new Response(null, { status: 204 });
    }

    return new Response("not found", { status: 404 });
  }

  private toResource(token: StoredToken) {
    return {
      metadata: { name: token.name, labels: token.labels },
      spec: { userID: token.userId, description: token.description, ttl: token.ttl },
    };
  }
}
