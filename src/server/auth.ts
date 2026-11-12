/**
 * Accounts: username + password ONLY. No phone number, no email, ever.
 *
 * - Passwords: scrypt (node:crypto) with a per-user random salt.
 * - Sessions: 256-bit random tokens; only their SHA-256 hash is stored.
 * - The account record carries the user's PUBLIC key, uploaded at
 *   registration. The matching private key is generated and kept by the
 *   client — the server never sees it.
 */
import { createHash, randomBytes, scryptSync, timingSafeEqual } from "node:crypto";
import { isValidPublicKeyB64 } from "../crypto/protocol.ts";
import type { Store } from "./store.ts";

export const USERNAME_RE = /^[A-Za-z0-9_.-]{3,24}$/;
export const MIN_PASSWORD_LENGTH = 8;

export type AuthResult<T> = { ok: true; value: T } | { ok: false; error: string };

function hashPassword(password: string, salt: Buffer): Buffer {
  return scryptSync(password, salt, 64);
}

export function hashToken(token: string): string {
  return createHash("sha256").update(token, "utf8").digest("hex");
}

export function registerUser(
  store: Store,
  username: string,
  password: string,
  publicKeyB64: string,
): AuthResult<{ username: string }> {
  if (!USERNAME_RE.test(username)) {
    return { ok: false, error: "username must be 3-24 chars of [A-Za-z0-9_.-]" };
  }
  if (typeof password !== "string" || password.length < MIN_PASSWORD_LENGTH) {
    return { ok: false, error: `password must be at least ${MIN_PASSWORD_LENGTH} characters` };
  }
  if (!isValidPublicKeyB64(publicKeyB64)) {
    return { ok: false, error: "publicKey must be a raw 32-byte X25519 key (base64)" };
  }
  if (store.getUser(username) !== undefined) {
    return { ok: false, error: "username already taken" };
  }
  const salt = randomBytes(16);
  const hash = hashPassword(password, salt);
  store.createUser({
    username,
    passHash: hash.toString("hex"),
    passSalt: salt.toString("hex"),
    publicKey: publicKeyB64,
    createdAt: Date.now(),
  });
  return { ok: true, value: { username } };
}

export function loginUser(
  store: Store,
  username: string,
  password: string,
): AuthResult<{ token: string }> {
  const user = store.getUser(username);
  if (user === undefined || typeof password !== "string") {
    return { ok: false, error: "invalid username or password" };
  }
  const expected = Buffer.from(user.passHash, "hex");
  const actual = hashPassword(password, Buffer.from(user.passSalt, "hex"));
  if (expected.length !== actual.length || !timingSafeEqual(expected, actual)) {
    return { ok: false, error: "invalid username or password" };
  }
  const token = randomBytes(32).toString("hex");
  store.createSession(hashToken(token), username);
  return { ok: true, value: { token } };
}

export function authenticateToken(store: Store, token: string): string | undefined {
  if (typeof token !== "string" || token.length === 0) return undefined;
  return store.getSessionUsername(hashToken(token));
}

export function logoutToken(store: Store, token: string): void {
  store.deleteSession(hashToken(token));
}
