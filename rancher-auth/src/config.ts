export interface Config {
  /** Where Executor and browsers reach this service, e.g. https://executor.brandnewops.com/rancher-auth */
  publicUrl: URL;
  rancherUrl: URL;
  rancherClientId: string;
  rancherClientSecret: string;
  executorClientId: string;
  executorClientSecret: string;
  executorRedirectUri: string;
  /** AES-256-GCM key for state, codes and refresh tokens. Changing it disconnects everyone. */
  sealingKey: Buffer;
  accessTokenTtlMs: number;
  refreshCredentialTtlMs: number;
  port: number;
}

const HOUR = 60 * 60 * 1000;
const DAY = 24 * HOUR;

export function loadConfig(env: Record<string, string | undefined> = process.env): Config {
  const required = (name: string) => {
    const value = env[name]?.trim();
    if (!value) throw new Error(`${name} is required`);
    return value;
  };

  const sealingKey = Buffer.from(required("SEALING_KEY"), "base64");
  if (sealingKey.length !== 32) throw new Error("SEALING_KEY must be 32 bytes, base64 encoded (openssl rand -base64 32)");

  return {
    publicUrl: new URL(required("PUBLIC_URL").replace(/\/+$/, "")),
    rancherUrl: new URL(required("RANCHER_URL").replace(/\/+$/, "")),
    rancherClientId: required("RANCHER_CLIENT_ID"),
    rancherClientSecret: required("RANCHER_CLIENT_SECRET"),
    executorClientId: required("EXECUTOR_CLIENT_ID"),
    executorClientSecret: required("EXECUTOR_CLIENT_SECRET"),
    executorRedirectUri: required("EXECUTOR_REDIRECT_URI"),
    sealingKey,
    accessTokenTtlMs: Number(env.ACCESS_TOKEN_TTL_HOURS ?? 24) * HOUR,
    refreshCredentialTtlMs: Number(env.REFRESH_TOKEN_TTL_DAYS ?? 90) * DAY,
    port: Number(env.PORT ?? 8080),
  };
}
