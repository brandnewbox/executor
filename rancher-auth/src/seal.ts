import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

// Sealed values are AES-256-GCM encrypted JSON, so they can travel through
// browsers and Executor's credential store without either being able to read
// or forge them. The purpose is bound as associated data, so a value sealed as
// one thing (an authorization code) can't be replayed as another (a refresh token).
export type Purpose = "authorize" | "code" | "refresh";

export function seal(key: Buffer, purpose: Purpose, payload: object, ttlMs?: number): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(Buffer.from(purpose));
  const body = JSON.stringify({ ...payload, exp: ttlMs === undefined ? undefined : Date.now() + ttlMs });
  const ciphertext = Buffer.concat([cipher.update(body, "utf8"), cipher.final()]);
  return Buffer.concat([iv, ciphertext, cipher.getAuthTag()]).toString("base64url");
}

/** Returns null for anything tampered with, sealed for another purpose, or expired. */
export function unseal<T>(key: Buffer, purpose: Purpose, sealed: string | null | undefined): T | null {
  if (!sealed) return null;
  try {
    const raw = Buffer.from(sealed, "base64url");
    const decipher = createDecipheriv("aes-256-gcm", key, raw.subarray(0, 12));
    decipher.setAAD(Buffer.from(purpose));
    decipher.setAuthTag(raw.subarray(raw.length - 16));
    const body = Buffer.concat([decipher.update(raw.subarray(12, raw.length - 16)), decipher.final()]);
    const payload = JSON.parse(body.toString("utf8"));
    if (payload.exp !== undefined && Date.now() > payload.exp) return null;
    return payload as T;
  } catch {
    return null;
  }
}
