import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { loadConfig } from "../src/config";
import { createHandler } from "../src/oauth";
import { FakeRancher, MAX_TTL_MS } from "./fake-rancher";

const PUBLIC_URL = "https://executor.example.com/rancher-auth";
const EXECUTOR_CALLBACK = "https://executor.example.com/api/oauth/callback";
const VERIFIER = "executor-pkce-verifier-0123456789abcdefghijklmnop";
const CHALLENGE = createHash("sha256").update(VERIFIER).digest("base64url");
const DAY_SECONDS = 24 * 60 * 60;

let rancher: FakeRancher;
let handle: (req: Request) => Promise<Response>;

beforeEach(() => {
  rancher = new FakeRancher({ id: "client-rancher", secret: "rancher-secret" });
  handle = createHandler(
    loadConfig({
      PUBLIC_URL,
      RANCHER_URL: rancher.url,
      RANCHER_CLIENT_ID: "client-rancher",
      RANCHER_CLIENT_SECRET: "rancher-secret",
      EXECUTOR_CLIENT_ID: "executor",
      EXECUTOR_CLIENT_SECRET: "executor-secret",
      EXECUTOR_REDIRECT_URI: EXECUTOR_CALLBACK,
      SEALING_KEY: Buffer.alloc(32, 7).toString("base64"),
    }),
  );
});

afterEach(() => rancher.stop());

function authorizeUrl(overrides: Record<string, string> = {}) {
  const params = new URLSearchParams({
    response_type: "code",
    client_id: "executor",
    redirect_uri: EXECUTOR_CALLBACK,
    state: "executor-state",
    code_challenge: CHALLENGE,
    code_challenge_method: "S256",
    scope: "openid",
    ...overrides,
  });
  return `${PUBLIC_URL}/authorize?${params}`;
}

function tokenRequest(form: Record<string, string>) {
  return handle(
    new Request(`${PUBLIC_URL}/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ client_id: "executor", client_secret: "executor-secret", ...form }),
    }),
  );
}

/** Runs the browser part of sign-in and returns the code Executor receives. */
async function signInCode(userId: string): Promise<string> {
  const toRancher = (await handle(new Request(authorizeUrl()))).headers.get("location")!;
  const rancherState = new URL(toRancher).searchParams.get("state")!;
  const code = rancher.approve(toRancher, userId);
  const toExecutor = (await handle(new Request(`${PUBLIC_URL}/callback?code=${code}&state=${rancherState}`))).headers.get("location")!;
  return new URL(toExecutor).searchParams.get("code")!;
}

async function connect(userId: string) {
  const res = await tokenRequest({ grant_type: "authorization_code", code: await signInCode(userId), code_verifier: VERIFIER, redirect_uri: EXECUTOR_CALLBACK });
  return res.json();
}

function refresh(refreshToken: string) {
  return tokenRequest({ grant_type: "refresh_token", refresh_token: refreshToken });
}

const tokenNameOf = (bearer: string) => bearer.slice(4).split(":")[0];

describe("sign-in", () => {
  test("gives Executor a Rancher API token that outlives the Rancher login session", async () => {
    const toRancher = await handle(new Request(authorizeUrl()));
    expect(toRancher.status).toBe(302);
    const rancherAuthorize = new URL(toRancher.headers.get("location")!);
    expect(rancherAuthorize.origin + rancherAuthorize.pathname).toBe(`${rancher.url}/oidc/authorize`);
    expect(rancherAuthorize.searchParams.get("client_id")).toBe("client-rancher");
    expect(rancherAuthorize.searchParams.get("redirect_uri")).toBe(`${PUBLIC_URL}/callback`);
    expect(rancherAuthorize.searchParams.get("code_challenge_method")).toBe("S256");

    const code = rancher.approve(rancherAuthorize.toString(), "u-alice");
    const toExecutor = await handle(
      new Request(`${PUBLIC_URL}/callback?code=${code}&state=${rancherAuthorize.searchParams.get("state")}`),
    );
    const executorCallback = new URL(toExecutor.headers.get("location")!);
    expect(executorCallback.origin + executorCallback.pathname).toBe(EXECUTOR_CALLBACK);
    expect(executorCallback.searchParams.get("state")).toBe("executor-state");

    const res = await tokenRequest({
      grant_type: "authorization_code",
      code: executorCallback.searchParams.get("code")!,
      code_verifier: VERIFIER,
      redirect_uri: EXECUTOR_CALLBACK,
    });
    const body = await res.json();
    expect(res.status).toBe(200);
    expect(res.headers.get("cache-control")).toBe("no-store");
    expect(body.token_type).toBe("Bearer");
    expect(body.expires_in).toBeWithin(DAY_SECONDS - 5, DAY_SECONDS + 1);
    expect(body.refresh_token).toBeString();

    rancher.endSessions("u-alice");
    expect(rancher.userFor(body.access_token)).toBe("u-alice");

    const [refreshCredential, accessToken] = rancher.tokensFor("u-alice");
    expect(accessToken.name).toBe(tokenNameOf(body.access_token));
    expect(accessToken.labels["rancher-auth.brandnewbox.com/role"]).toBe("access");
    expect(refreshCredential.labels["rancher-auth.brandnewbox.com/role"]).toBe("refresh");
    expect(refreshCredential.ttl).toBe(MAX_TTL_MS);
    expect(refreshCredential.labels["rancher-auth.brandnewbox.com/grant"]).toBe(
      accessToken.labels["rancher-auth.brandnewbox.com/grant"],
    );
  });

  test("refuses to send people to a redirect_uri other than Executor's", async () => {
    const res = await handle(new Request(authorizeUrl({ redirect_uri: "https://evil.example.com/callback" })));
    expect(res.status).toBe(400);
    expect(res.headers.get("location")).toBeNull();
  });

  test("requires PKCE from Executor", async () => {
    const res = await handle(new Request(authorizeUrl({ code_challenge_method: "plain" })));
    const location = new URL(res.headers.get("location")!);
    expect(location.origin + location.pathname).toBe(EXECUTOR_CALLBACK);
    expect(location.searchParams.get("error")).toBe("invalid_request");
  });

  test("redeems a code once, and only with the matching PKCE verifier", async () => {
    const code = await signInCode("u-alice");
    const form = { grant_type: "authorization_code", code, redirect_uri: EXECUTOR_CALLBACK };

    expect((await (await tokenRequest({ ...form, code_verifier: "wrong-verifier" })).json()).error).toBe("invalid_grant");
    expect((await tokenRequest({ ...form, code_verifier: VERIFIER })).status).toBe(200);
    expect((await (await tokenRequest({ ...form, code_verifier: VERIFIER })).json()).error).toBe("invalid_grant");
    expect(rancher.tokensFor("u-alice")).toHaveLength(2);
  });

  test("rejects token requests without Executor's client secret", async () => {
    const res = await tokenRequest({ client_secret: "guess", grant_type: "authorization_code", code: await signInCode("u-alice"), code_verifier: VERIFIER, redirect_uri: EXECUTOR_CALLBACK });
    expect(res.status).toBe(401);
    expect((await res.json()).error).toBe("invalid_client");
    expect(rancher.tokensFor("u-alice")).toHaveLength(0);
  });
});

describe("refresh", () => {
  test("replaces both tokens and cleans up the ones Executor no longer holds", async () => {
    const first = await connect("u-alice");
    const [firstCredential] = rancher.tokensFor("u-alice").map((t) => t.name);

    const secondRes = await refresh(first.refresh_token);
    const second = await secondRes.json();
    expect(secondRes.status).toBe(200);
    expect(second.access_token).not.toBe(first.access_token);
    expect(second.refresh_token).not.toBe(first.refresh_token);
    expect(second.expires_in).toBeWithin(DAY_SECONDS - 5, DAY_SECONDS + 1);
    expect(rancher.userFor(second.access_token)).toBe("u-alice");
    expect(rancher.userFor(first.access_token)).toBeNull();

    const secondTokens = rancher.tokensFor("u-alice").map((t) => t.name);
    const secondCredential = secondTokens.find((name) => name !== firstCredential && name !== tokenNameOf(second.access_token))!;
    // The credential Executor just used is kept until its successor is used.
    expect(secondTokens.sort()).toEqual([firstCredential, secondCredential, tokenNameOf(second.access_token)].sort());

    const third = await (await refresh(second.refresh_token)).json();
    const thirdTokens = rancher.tokensFor("u-alice").map((t) => t.name);
    expect(thirdTokens).not.toContain(firstCredential);
    expect(thirdTokens).toContain(secondCredential);
    expect(thirdTokens).toContain(tokenNameOf(third.access_token));
    expect(thirdTokens).toHaveLength(3);
  });

  test("still works with the previous refresh token if Executor lost the new one", async () => {
    const first = await connect("u-alice");
    const lost = await (await refresh(first.refresh_token)).json();

    const retryRes = await refresh(first.refresh_token);
    const retry = await retryRes.json();
    expect(retryRes.status).toBe(200);
    expect(rancher.userFor(retry.access_token)).toBe("u-alice");
    expect(rancher.userFor(lost.access_token)).toBeNull();
    expect(rancher.tokensFor("u-alice")).toHaveLength(3);
  });

  test("asks for a reconnect once the person deletes the refresh credential in Rancher", async () => {
    const connection = await connect("u-alice");
    for (const token of rancher.tokensFor("u-alice")) rancher.tokens.delete(token.name);

    const res = await refresh(connection.refresh_token);
    expect(res.status).toBe(400);
    expect((await res.json()).error).toBe("invalid_grant");
  });

  test("reports a Rancher outage as temporary so Executor keeps the connection", async () => {
    const connection = await connect("u-alice");
    rancher.failWith = 503;

    const res = await refresh(connection.refresh_token);
    expect(res.status).toBe(503);
    expect((await res.json()).error).toBe("temporarily_unavailable");

    rancher.failWith = null;
    expect((await refresh(connection.refresh_token)).status).toBe(200);
  });

  test("does not accept an authorization code as a refresh token", async () => {
    const res = await refresh(await signInCode("u-alice"));
    expect((await res.json()).error).toBe("invalid_grant");
    expect(rancher.tokensFor("u-alice")).toHaveLength(0);
  });
});
