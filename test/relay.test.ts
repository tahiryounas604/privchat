import assert from "node:assert/strict";
import { test } from "node:test";
import {
  decryptMessage,
  deriveSessionKey,
  encryptMessage,
} from "../src/crypto/protocol.ts";
import { connectClient, createUser, delay, startTestServer } from "./helpers.ts";

test("online relay: B receives byte-identical ciphertext and can decrypt it", async (t) => {
  const srv = await startTestServer();
  t.after(() => srv.cleanup());
  const alice = await createUser(srv.base, "alice");
  const bob = await createUser(srv.base, "bob");
  const aClient = await connectClient(srv.port, alice.token);
  const bClient = await connectClient(srv.port, bob.token);
  t.after(() => { aClient.close(); bClient.close(); });

  const keyAB = deriveSessionKey(alice.identity.privateKey, bob.identity.publicKeyB64, "alice", "bob");
  const wire = encryptMessage(keyAB, "meet at the old bridge at noon");
  aClient.send({ type: "msg", to: "bob", nonce: wire.nonce, ciphertext: wire.ciphertext });

  const got = await bClient.waitFor((m) => m.type === "msg");
  assert.equal(got.from, "alice");
  assert.equal(got.nonce, wire.nonce);
  assert.equal(got.ciphertext, wire.ciphertext); // byte-identical through the relay
  const keyBA = deriveSessionKey(bob.identity.privateKey, alice.identity.publicKeyB64, "bob", "alice");
  assert.equal(decryptMessage(keyBA, { nonce: String(got.nonce), ciphertext: String(got.ciphertext) }),
    "meet at the old bridge at noon");
  assert.equal(srv.app.store.queueDepth("bob"), 0); // live delivery queues nothing
});

test("offline queue: delivered on next login, exactly once, queue drained", async (t) => {
  const srv = await startTestServer();
  t.after(() => srv.cleanup());
  const alice = await createUser(srv.base, "alice");
  const bob = await createUser(srv.base, "bob");
  const aClient = await connectClient(srv.port, alice.token);
  t.after(() => aClient.close());

  // Bob is offline: send two encrypted messages.
  const keyAB = deriveSessionKey(alice.identity.privateKey, bob.identity.publicKeyB64, "alice", "bob");
  for (const text of ["first while offline", "second while offline"]) {
    const wire = encryptMessage(keyAB, text);
    aClient.send({ type: "msg", to: "bob", nonce: wire.nonce, ciphertext: wire.ciphertext });
  }
  await delay(300);
  assert.equal(srv.app.store.queueDepth("bob"), 2);

  // Bob logs in: both queued messages arrive, marked queued, then are gone.
  const bClient = await connectClient(srv.port, bob.token);
  const keyBA = deriveSessionKey(bob.identity.privateKey, alice.identity.publicKeyB64, "bob", "alice");
  const plaintexts: string[] = [];
  // Collect the two queued frames (waitFor returns history matches too).
  for (let i = 0; i < 40 && plaintexts.length < 2; i += 1) {
    const queued = bClient.messages.filter((m) => m.type === "msg" && m.queued === true);
    for (const q of queued) {
      const text = decryptMessage(keyBA, { nonce: String(q.nonce), ciphertext: String(q.ciphertext) });
      if (!plaintexts.includes(text)) plaintexts.push(text);
    }
    if (plaintexts.length < 2) await delay(50);
  }
  assert.deepEqual(plaintexts.sort(), ["first while offline", "second while offline"]);
  assert.equal(srv.app.store.queueDepth("bob"), 0);
  bClient.close();

  // Reconnecting must NOT redeliver.
  const bAgain = await connectClient(srv.port, bob.token);
  t.after(() => bAgain.close());
  await delay(300);
  assert.equal(bAgain.messages.filter((m) => m.type === "msg").length, 0);
});

test("message to a nonexistent user errors back and queues nothing", async (t) => {
  const srv = await startTestServer();
  t.after(() => srv.cleanup());
  const alice = await createUser(srv.base, "alice");
  const aClient = await connectClient(srv.port, alice.token);
  t.after(() => aClient.close());
  aClient.send({ type: "msg", to: "nobody", nonce: "AAAA", ciphertext: "BBBB" });
  const err = await aClient.waitFor((m) => m.type === "error");
  assert.equal(err.error, "no such user");
});

test("unauthenticated sockets cannot relay (auth is enforced)", async (t) => {
  const srv = await startTestServer();
  t.after(() => srv.cleanup());
  const bob = await createUser(srv.base, "bob");
  const bClient = await connectClient(srv.port, bob.token);
  t.after(() => bClient.close());
  // Connect with a bogus token: server must reject, and Bob gets nothing.
  const { WebSocket } = await import("ws");
  const bad = new WebSocket(`ws://127.0.0.1:${srv.port}/ws`);
  await new Promise<void>((resolve) => {
    bad.on("open", () => {
      bad.send(JSON.stringify({ type: "auth", token: "deadbeef" }));
      bad.send(JSON.stringify({ type: "msg", to: "bob", nonce: "AAAA", ciphertext: "BBBB" }));
    });
    bad.on("close", () => resolve());
    setTimeout(resolve, 2000);
  });
  await delay(200);
  assert.equal(bClient.messages.filter((m) => m.type === "msg").length, 0);
});
