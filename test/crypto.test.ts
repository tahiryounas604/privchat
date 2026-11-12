import assert from "node:assert/strict";
import { test } from "node:test";
import {
  decryptMessage,
  deriveSessionKey,
  encryptMessage,
  exportPrivateKeyB64,
  generateIdentity,
  importPrivateKeyB64,
} from "../src/crypto/protocol.ts";

test("ECDH: both sides derive the SAME session key", () => {
  const alice = generateIdentity();
  const bob = generateIdentity();
  const keyAlice = deriveSessionKey(alice.privateKey, bob.publicKeyB64, "alice", "bob");
  const keyBob = deriveSessionKey(bob.privateKey, alice.publicKeyB64, "bob", "alice");
  assert.equal(keyAlice.length, 32);
  assert.deepEqual(keyAlice, keyBob);
});

test("encrypt -> decrypt round-trip restores the plaintext", () => {
  const alice = generateIdentity();
  const bob = generateIdentity();
  const keyAlice = deriveSessionKey(alice.privateKey, bob.publicKeyB64, "alice", "bob");
  const keyBob = deriveSessionKey(bob.privateKey, alice.publicKeyB64, "bob", "alice");
  const wire = encryptMessage(keyAlice, "salaam, this is secret ✓");
  // Wire format sanity: 12-byte nonce, ciphertext longer than plaintext (tag).
  assert.equal(Buffer.from(wire.nonce, "base64").length, 12);
  assert.ok(Buffer.from(wire.ciphertext, "base64").length > 22);
  assert.equal(decryptMessage(keyBob, wire), "salaam, this is secret ✓");
});

test("tampered ciphertext fails decryption loudly", () => {
  const alice = generateIdentity();
  const bob = generateIdentity();
  const key = deriveSessionKey(alice.privateKey, bob.publicKeyB64, "alice", "bob");
  const wire = encryptMessage(key, "integrity matters");
  const raw = Buffer.from(wire.ciphertext, "base64");
  raw[0] = (raw[0] as number) ^ 0xff;
  assert.throws(() => decryptMessage(key, { nonce: wire.nonce, ciphertext: raw.toString("base64") }));
  // Tampered nonce must fail too.
  const badNonce = Buffer.from(wire.nonce, "base64");
  badNonce[0] = (badNonce[0] as number) ^ 0xff;
  assert.throws(() =>
    decryptMessage(key, { nonce: badNonce.toString("base64"), ciphertext: wire.ciphertext }),
  );
});

test("a third party with a different key cannot decrypt", () => {
  const alice = generateIdentity();
  const bob = generateIdentity();
  const mallory = generateIdentity();
  const keyAliceBob = deriveSessionKey(alice.privateKey, bob.publicKeyB64, "alice", "bob");
  const wire = encryptMessage(keyAliceBob, "for bob only");
  const keyMallory = deriveSessionKey(mallory.privateKey, alice.publicKeyB64, "mallory", "alice");
  assert.throws(() => decryptMessage(keyMallory, wire));
});

test("different conversations derive different keys (username-bound salt)", () => {
  const alice = generateIdentity();
  const bob = generateIdentity();
  const k1 = deriveSessionKey(alice.privateKey, bob.publicKeyB64, "alice", "bob");
  const k2 = deriveSessionKey(alice.privateKey, bob.publicKeyB64, "alice", "carol");
  assert.notDeepEqual(k1, k2);
});

test("private key export/import round-trips (client-side storage format)", () => {
  const id = generateIdentity();
  const restored = importPrivateKeyB64(exportPrivateKeyB64(id.privateKey));
  const peer = generateIdentity();
  const k1 = deriveSessionKey(id.privateKey, peer.publicKeyB64, "me", "peer");
  const k2 = deriveSessionKey(restored, peer.publicKeyB64, "me", "peer");
  assert.deepEqual(k1, k2);
});
