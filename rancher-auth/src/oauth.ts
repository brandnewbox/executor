import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import type { Config } from "./config";
import { log, renewGrant, startGrant, type Grant, type IssuedGrant } from "./grants";
import { Rancher, RancherError } from "./rancher";
import { seal, unseal } from "./seal";

// An OAuth 2.0 authorization server for one client, Executor. Sign-in is
// delegated to Rancher's OIDC provider; the tokens it hands Executor are
// Rancher API tokens that outlive the Rancher login session.

const AUTHORIZE_TTL_MS = 10 * 60 * 1000;
const CODE_TTL_MS = 60 * 1000;

interface AuthorizeState {
  /** Executor's state, PKCE challenge and our own PKCE verifier for Rancher. */
  state: string;
  challenge: string;
  verifier: string;
}

interface Code {
  id: string;
  jwt: string;
  challenge: string;
}

export function createHandler(config: Config) {
  const rancher = new Rancher(config.rancherUrl);
  const base = config.publicUrl.pathname.replace(/\/$/, "");
  const callbackUrl = `${config.publicUrl}/callback`;
  // Codes are stateless but single-use: remember redeemed ones until they expire.
  const redeemedCodes = new Map<string, number>();

  async function authorize(url: URL): Promise<Response> {
    const params = url.searchParams;
    if (params.get("client_id") !== config.executorClientId) return text(400, "Unknown client_id.");
    if (params.get("redirect_uri") !== config.executorRedirectUri) return text(400, "Unregistered redirect_uri.");

    const state = params.get("state") ?? "";
    const challenge = params.get("code_challenge");
    if (params.get("response_type") !== "code") {
      return redirectToExecutor({ error: "unsupported_response_type", state });
    }
    if (!challenge || params.get("code_challenge_method") !== "S256") {
      return redirectToExecutor({ error: "invalid_request", error_description: "PKCE with S256 is required", state });
    }

    const verifier = randomBytes(32).toString("base64url");
    const rancherAuthorize = new URL("/oidc/authorize", config.rancherUrl);
    rancherAuthorize.search = new URLSearchParams({
      response_type: "code",
      client_id: config.rancherClientId,
      redirect_uri: callbackUrl,
      scope: "openid profile",
      state: seal(config.sealingKey, "authorize", { state, challenge, verifier } satisfies AuthorizeState, AUTHORIZE_TTL_MS),
      code_challenge: s256(verifier),
      code_challenge_method: "S256",
    }).toString();
    return Response.redirect(rancherAuthorize.toString(), 302);
  }

  async function callback(url: URL): Promise<Response> {
    const params = url.searchParams;
    const pending = unseal<AuthorizeState>(config.sealingKey, "authorize", params.get("state"));
    if (!pending) return text(400, "This sign-in has expired. Start again from Executor.");

    const code = params.get("code");
    if (!code) {
      log("rancher sign-in failed", { error: params.get("error") });
      return redirectToExecutor({ error: "access_denied", state: pending.state });
    }

    let jwt: string;
    try {
      jwt = await rancher.exchangeCode({
        code,
        codeVerifier: pending.verifier,
        redirectUri: callbackUrl,
        clientId: config.rancherClientId,
        clientSecret: config.rancherClientSecret,
      });
    } catch (error) {
      log("rancher code exchange failed", { error: (error as Error).message });
      return redirectToExecutor({ error: "server_error", state: pending.state });
    }

    const ourCode = seal(
      config.sealingKey,
      "code",
      { id: randomBytes(16).toString("hex"), jwt, challenge: pending.challenge } satisfies Code,
      CODE_TTL_MS,
    );
    return redirectToExecutor({ code: ourCode, state: pending.state });
  }

  async function token(req: Request): Promise<Response> {
    const form = new URLSearchParams(await req.text());
    if (!authenticateClient(req, form)) return oauthError(401, "invalid_client");

    try {
      switch (form.get("grant_type")) {
        case "authorization_code":
          return await redeemCode(form);
        case "refresh_token":
          return await refresh(form);
        default:
          return oauthError(400, "unsupported_grant_type");
      }
    } catch (error) {
      if (error instanceof RancherError && error.unauthorized) {
        return oauthError(400, "invalid_grant", "Rancher no longer accepts this connection's credential.");
      }
      log("token request failed", { grant_type: form.get("grant_type"), error: (error as Error).message });
      return oauthError(503, "temporarily_unavailable");
    }
  }

  async function redeemCode(form: URLSearchParams): Promise<Response> {
    const code = unseal<Code>(config.sealingKey, "code", form.get("code"));
    if (!code || redeemedCodes.has(code.id)) return oauthError(400, "invalid_grant");
    if (form.get("redirect_uri") !== config.executorRedirectUri) return oauthError(400, "invalid_grant");
    if (s256(form.get("code_verifier") ?? "") !== code.challenge) return oauthError(400, "invalid_grant");

    forgetExpiredCodes();
    redeemedCodes.set(code.id, Date.now() + CODE_TTL_MS);
    return tokenResponse(await startGrant(rancher, code.jwt, config));
  }

  async function refresh(form: URLSearchParams): Promise<Response> {
    const grant = unseal<Grant>(config.sealingKey, "refresh", form.get("refresh_token"));
    if (!grant) return oauthError(400, "invalid_grant");
    return tokenResponse(await renewGrant(rancher, grant, config));
  }

  function tokenResponse({ grant, access }: IssuedGrant): Response {
    return Response.json(
      {
        access_token: access.bearer,
        token_type: "Bearer",
        expires_in: Math.max(0, Math.floor((access.expiresAt.getTime() - Date.now()) / 1000)),
        refresh_token: seal(config.sealingKey, "refresh", { id: grant.id, credential: grant.credential } satisfies Grant),
      },
      { headers: { "cache-control": "no-store", pragma: "no-cache" } },
    );
  }

  /** Accepts client_secret_post (Executor's "Request body") and client_secret_basic. */
  function authenticateClient(req: Request, form: URLSearchParams): boolean {
    let id = form.get("client_id");
    let secret = form.get("client_secret");
    const basic = req.headers.get("authorization")?.match(/^Basic\s+(.+)$/i);
    if (basic) {
      const decoded = Buffer.from(basic[1], "base64").toString("utf8");
      const separator = decoded.indexOf(":");
      id = decodeURIComponent(decoded.slice(0, separator));
      secret = decodeURIComponent(decoded.slice(separator + 1));
    }
    return id === config.executorClientId && secret !== null && safeEqual(secret, config.executorClientSecret);
  }

  function redirectToExecutor(params: Record<string, string>): Response {
    const url = new URL(config.executorRedirectUri);
    for (const [key, value] of Object.entries(params)) if (value) url.searchParams.set(key, value);
    return Response.redirect(url.toString(), 302);
  }

  function forgetExpiredCodes() {
    const now = Date.now();
    for (const [id, expiresAt] of redeemedCodes) if (expiresAt < now) redeemedCodes.delete(id);
  }

  return async function handle(req: Request): Promise<Response> {
    const url = new URL(req.url);
    const path = url.pathname.startsWith(base) ? url.pathname.slice(base.length) : null;
    if (req.method === "GET" && path === "/authorize") return authorize(url);
    if (req.method === "GET" && path === "/callback") return callback(url);
    if (req.method === "POST" && path === "/token") return token(req);
    if (req.method === "GET" && path === "/healthz") return text(200, "ok");
    return text(404, "Not found.");
  };
}

function s256(value: string): string {
  return createHash("sha256").update(value).digest("base64url");
}

function safeEqual(a: string, b: string): boolean {
  const left = createHash("sha256").update(a).digest();
  const right = createHash("sha256").update(b).digest();
  return timingSafeEqual(left, right);
}

function text(status: number, body: string): Response {
  return new Response(body, { status, headers: { "content-type": "text/plain; charset=utf-8" } });
}

function oauthError(status: number, error: string, description?: string): Response {
  return Response.json(
    { error, ...(description ? { error_description: description } : {}) },
    { status, headers: { "cache-control": "no-store" } },
  );
}
