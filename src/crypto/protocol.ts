/**
 * PrivChat wire cryptography — reference implementation (Node / `node:crypto`).
 *
 * Protocol "privchat-v1":
 *   - Identity: one X25519 keypair per user, generated ON THE CLIENT.
 *     The private key never leaves the client device.
 *   - Session key: X25519 ECDH(myPrivate, peerPublic) shared secret, then
 *     HKDF-SHA256 with salt = the two usernames sorted and joined with ":",
 *     info = "privchat-v1", output 32 bytes -> AES-256-GCM key.
 *   - Message: AES-256-GCM with a random 12-byte nonce per message.
 *     Wire ciphertext = base64(ciphertext || 16-byte auth tag).
 *     Wire format = { to, nonce (base64), ciphertext (base64) }.
 *
 * Only vetted primitives from Node's crypto module are used — nothing
 * hand-rolled. The browser client (public/app.js) implements the identical
 * derivation with WebCrypto (SubtleCrypto), which is wire-compatible:
 * WebCrypto's AES-GCM output is also ciphertext || tag, X25519 raw public
 * keys are the same 32 bytes, and HKDF-SHA256 parameters match exactly.
 */
import {
  createCipheriv,
  createDecipheriv,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  hkdfSync,
  randomBytes,
  type KeyObject,
} from "node:crypto";

export const PROTOCOL_INFO = "privchat-v1";

export interface Identity {
  /** base64 of the raw 32-byte X25519 public key — safe to publish. */
  publicKeyB64: string;
  /** The private key. Client-side only; never send this anywhere. */
  privateKey: KeyObject;
}

function rawPublicKeyB64(publicKey: KeyObject): string {
  const jwk = publicKey.export({ format: "jwk" }) as { x?: unknown };
  if (typeof jwk.x !== "string") throw new Error("X25519 public key export failed");
  return Buffer.from(jwk.x, "base64url").toString("base64");
}

/** Import a peer's raw public key (base64 of 32 bytes). Throws if malformed. */
export function importPublicKey(publicKeyB64: string): KeyObject {
  const raw = Buffer.from(publicKeyB64, "base64");
  if (raw.length !== 32) throw new Error("public key must be 32 bytes");
  return createPublicKey({
    key: { kty: "OKP", crv: "X25519", x: raw.toString("base64url") },
    format: "jwk",
  });
}

/** True iff the string is a well-formed raw X25519 public key. */
export function isValidPublicKeyB64(publicKeyB64: string): boolean {
  try {
    importPublicKey(publicKeyB64);
    return true;
  } catch {
    return false;
  }
}

/** Generate a fresh client-side identity keypair. */
export function generateIdentity(): Identity {
  const { publicKey, privateKey } = generateKeyPairSync("x25519");
  return { publicKeyB64: rawPublicKeyB64(publicKey), privateKey };
}

/**
 * Serialize a private key so a (non-browser) client can store it locally.
 * The result is as sensitive as the key itself — store it like a password.
 */
export function exportPrivateKeyB64(privateKey: KeyObject): string {
  return privateKey.export({ format: "der", type: "pkcs8" }).toString("base64");
}

export function importPrivateKeyB64(b64: string): KeyObject {
  return createPrivateKey({
    key: Buffer.from(b64, "base64"),
    format: "der",
    type: "pkcs8",
  });
}

/**
 * Derive the shared AES-256 key for a 1:1 conversation.
 * Both sides derive the IDENTICAL key: ECDH is symmetric and the HKDF salt
 * uses the sorted username pair, so argument order does not matter.
 */
export function deriveSessionKey(
  myPrivateKey: KeyObject,
  peerPublicKeyB64: string,
  myUsername: string,
  peerUsername: string,
): Buffer {
  const shared = diffieHellman({
    privateKey: myPrivateKey,
    publicKey: importPublicKey(peerPublicKeyB64),
  });
  const salt = Buffer.from([myUsername, peerUsername].sort().join(":"), "utf8");
  const key = hkdfSync("sha256", shared, salt, Buffer.from(PROTOCOL_INFO, "utf8"), 32);
  return Buffer.from(key);
}

export interface EncryptedMessage {
  /** base64, 12 bytes */
  nonce: string;
  /** base64 of ciphertext || 16-byte GCM auth tag */
  ciphertext: string;
}

/** Encrypt a UTF-8 plaintext under a session key from deriveSessionKey(). */
export function encryptMessage(sessionKey: Buffer, plaintext: string): EncryptedMessage {
  const nonce = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", sessionKey, nonce);
  const ct = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    nonce: nonce.toString("base64"),
    ciphertext: Buffer.concat([ct, tag]).toString("base64"),
  };
}

/**
 * Decrypt a message. Throws on ANY tampering, wrong key, or malformed input —
 * AES-GCM authentication failure is never swallowed.
 */
export function decryptMessage(sessionKey: Buffer, msg: EncryptedMessage): string {
  const nonce = Buffer.from(msg.nonce, "base64");
  if (nonce.length !== 12) throw new Error("nonce must be 12 bytes");
  const data = Buffer.from(msg.ciphertext, "base64");
  if (data.length < 16) throw new Error("ciphertext too short");
  const tag = data.subarray(data.length - 16);
  const ct = data.subarray(0, data.length - 16);
  const decipher = createDecipheriv("aes-256-gcm", sessionKey, nonce);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]).toString("utf8");
}
