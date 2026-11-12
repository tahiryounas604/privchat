import assert from "node:assert/strict";
import { test } from "node:test";
import {
  decryptMessage,
  deriveSessionKey,
  encryptMessage,
} from "../src/crypto/protocol.ts";
import { connectClient, createUser, startTestServer } from "./helpers.ts";

test("smoke: client page serves, two users register, one E2E message decrypts", async (t) => {
  const srv = await startTestServer();
  t.after(() => srv.cleanup());

  // 1. The web client is served at /.
  const page = await fetch(`${srv.base}/`);
  assert.equal(page.status, 200);
  const html = await page.text();
  assert.ok(html.includes("PrivChat"));
  assert.ok(html.includes("/app.js"));
  const js = await fetch(`${srv.base}/app.js`);
  assert.equal(js.status, 200);
  assert.ok((await js.text()).includes("RTCPeerConnection"));
  const health = await fetch(`${srv.base}/health`);
  assert.equal(health.status, 200);

  // 2. Two users register + login through the real API.
  const alice = await createUser(srv.base, "alice");
  const bob = await createUser(srv.base, "bob");

  // 3. Alice looks up Bob's public key the way the client does.
  const lookup = await fetch(`${srv.base}/api/users/bob/pubkey`, {
    headers: { authorization: `Bearer ${alice.token}` },
  });
  assert.equal(lookup.status, 200);
  const { publicKey } = (await lookup.json()) as { publicKey: string };
  assert.equal(publicKey, bob.identity.publicKeyB64);

  // 4. Both connect; Alice encrypts to Bob's key and sends via the relay.
  const a = await connectClient(srv.port, alice.token);
  const b = await connectClient(srv.port, bob.token);
  t.after(() => { a.close(); b.close(); });
  const keyAB = deriveSessionKey(alice.identity.privateKey, publicKey, "alice", "bob");
  const wire = encryptMessage(keyAB, "end-to-end, server saw nothing");
  a.send({ type: "msg", to: "bob", nonce: wire.nonce, ciphertext: wire.ciphertext });

  // 5. Bob receives ciphertext only, and decrypts it with his private key.
  const got = await b.waitFor((m) => m.type === "msg");
  const keyBA = deriveSessionKey(bob.identity.privateKey, alice.identity.publicKeyB64, "bob", "alice");
  const plain = decryptMessage(keyBA, {
    nonce: String(got.nonce),
    ciphertext: String(got.ciphertext),
  });
  assert.equal(plain, "end-to-end, server saw nothing");

  // 6. The server's own store contains no trace of the plaintext.
  assert.equal(srv.app.store.queueDepth("bob"), 0);
});
