# rancher-auth

A small OAuth authorization server that Executor's "Rancher Kubernetes" integration signs in through. It hands Executor Rancher API tokens that keep working after the person's Rancher login session ends, so people connect once instead of every day.

Rancher's own OIDC tokens only last as long as the Rancher login session (16 hours), and Rancher reports `expires_in` in nanoseconds, so Executor can't tell when to refresh them. See "Executor integration" in `services/rancher2.md` in brandnewbox/devops for the background.

## How it works

1. Executor sends the person to `/authorize`. The proxy sends them on to Rancher's `/oidc/authorize` as its own OIDC client.
2. Rancher redirects back to `/callback` with a code. The proxy exchanges it for Rancher's OIDC JWT and gives Executor a one-time code (60 seconds, encrypted, contains the JWT).
3. Executor redeems the code at `/token`. The proxy uses the JWT once to create two Rancher API tokens owned by the person:
   - an **access token** (24 hours), returned as `access_token` with `expires_in` in seconds;
   - a **refresh credential** (90 days), returned encrypted inside `refresh_token`. Only the proxy can use it.
4. Executor calls Rancher directly with the access token. Shortly before it expires, Executor sends the refresh token to `/token`. The proxy uses the refresh credential to create a new access token and a new refresh credential, and deletes the connection's older tokens.

Every refresh pushes the refresh credential's 90-day expiry forward, so a connection that's used at least once every 90 days never needs to sign in again. The refresh credential Executor just used is kept until its successor is used, in case Executor failed to save the new one.

All tokens a connection creates carry the label `rancher-auth.brandnewbox.com/grant=<connection id>` and a `rancher-auth.brandnewbox.com/role` of `access` or `refresh`. The proxy has no database: state between steps travels in values encrypted with `SEALING_KEY`, and redeemed codes are remembered in memory for their 60 seconds. Run one replica.

## Endpoints

All paths are under the `PUBLIC_URL` path, e.g. `https://executor.brandnewops.com/rancher-auth`.

| Path | Purpose |
|---|---|
| `GET /authorize` | OAuth authorization endpoint for Executor. Requires PKCE (`S256`). |
| `GET /callback` | Rancher's redirect URI. |
| `POST /token` | OAuth token endpoint. `authorization_code` and `refresh_token` grants. Client secret in the body or HTTP Basic. |
| `GET /healthz` | Returns `ok`. |

When Rancher rejects the refresh credential (deleted, expired, or the person lost access), `/token` returns `invalid_grant` and Executor asks the person to reconnect. When Rancher is unreachable it returns `503 temporarily_unavailable`, and Executor keeps the connection.

## Configuration

| Variable | |
|---|---|
| `PUBLIC_URL` | Where browsers and Executor reach the proxy, e.g. `https://executor.brandnewops.com/rancher-auth`. Rancher's redirect URI is `<PUBLIC_URL>/callback`. |
| `RANCHER_URL` | `https://rancher2.brandnewops.com` |
| `RANCHER_CLIENT_ID`, `RANCHER_CLIENT_SECRET` | The proxy's Rancher OIDC client. |
| `EXECUTOR_CLIENT_ID`, `EXECUTOR_CLIENT_SECRET` | What Executor's OAuth app uses to authenticate to the proxy. |
| `EXECUTOR_REDIRECT_URI` | Executor's OAuth callback, e.g. `https://executor.brandnewops.com/api/oauth/callback`. The only redirect the proxy allows. |
| `SEALING_KEY` | 32 random bytes, base64 (`openssl rand -base64 32`). Encrypts state, codes and refresh tokens. Changing it disconnects everyone. |
| `ACCESS_TOKEN_TTL_HOURS` | Default 24. |
| `REFRESH_TOKEN_TTL_DAYS` | Default 90. Rancher caps it at `auth-token-max-ttl-minutes`. |
| `PORT` | Default 8080. |

## Development

```sh
cd rancher-auth
bun install
bun test
bun run typecheck
```

The tests run the proxy against a fake Rancher (`test/fake-rancher.ts`).

## Release

Tag with the `rancher-auth-v` prefix:

```sh
git tag rancher-auth-v1
git push origin rancher-auth-v1
```

CircleCI builds `registry.digitalocean.com/brandnewbox/executor-rancher-auth:<tag>` from `rancher-auth/Dockerfile` and updates the `rancher-auth` Deployment in the `executor` namespace with Drydock. Executor's own `v*` tags don't build the proxy, and the proxy's tags don't build Executor.
