import assert from "node:assert/strict";
import { test } from "node:test";
import { connectClient, createUser, delay, startTestServer } from "./helpers.ts";

test("call signaling reaches only the intended peer, verbatim + sender stamped", async (t) => {
  const srv = await startTestServer();
  t.after(() => srv.cleanup());
  const alice = await createUser(srv.base, "alice");
  const bob = await createUser(srv.base, "bob");
  const carol = await createUser(srv.base, "carol");
  const a = await connectClient(srv.port, alice.token);
  const b = await connectClient(srv.port, bob.token);
  const c = await connectClient(srv.port, carol.token);
  t.after(() => { a.close(); b.close(); c.close(); });

  a.send({ type: "call-invite", to: "bob", media: { audio: true, video: true } });
  const invite = await b.waitFor((m) => m.type === "call-invite");
  assert.equal(invite.from, "alice");
  assert.deepEqual(invite.media, { audio: true, video: true });

  const fakeSdp = { type: "offer", sdp: "v=0 o=- 1 1 IN IP4 127.0.0.1" };
  b.send({ type: "sdp", to: "alice", sdp: fakeSdp });
  const sdp = await a.waitFor((m) => m.type === "sdp");
  assert.equal(sdp.from, "bob");
  assert.deepEqual(sdp.sdp, fakeSdp);

  const candidate = { candidate: "candidate:1 1 udp 1 127.0.0.1 9 typ host", sdpMid: "0" };
  a.send({ type: "ice", to: "bob", candidate });
  const ice = await b.waitFor((m) => m.type === "ice");
  assert.equal(ice.from, "alice");
  assert.deepEqual(ice.candidate, candidate);

  b.send({ type: "call-end", to: "alice" });
  const end = await a.waitFor((m) => m.type === "call-end");
  assert.equal(end.from, "bob");

  // Carol was online the whole time and must have received nothing of this.
  await delay(250);
  const carolSignal = c.messages.filter((m) =>
    ["call-invite", "call-accept", "call-reject", "call-end", "sdp", "ice"].includes(String(m.type)),
  );
  assert.equal(carolSignal.length, 0);
});

test("call-invite to an offline user returns call-unavailable", async (t) => {
  const srv = await startTestServer();
  t.after(() => srv.cleanup());
  const alice = await createUser(srv.base, "alice");
  await createUser(srv.base, "bob"); // registered but never connects
  const a = await connectClient(srv.port, alice.token);
  t.after(() => a.close());
  a.send({ type: "call-invite", to: "bob", media: { audio: true, video: false } });
  const un = await a.waitFor((m) => m.type === "call-unavailable");
  assert.equal(un.to, "bob");
});

test("a sender cannot spoof 'from' — the server stamps the authed username", async (t) => {
  const srv = await startTestServer();
  t.after(() => srv.cleanup());
  const alice = await createUser(srv.base, "alice");
  const bob = await createUser(srv.base, "bob");
  const a = await connectClient(srv.port, alice.token);
  const b = await connectClient(srv.port, bob.token);
  t.after(() => { a.close(); b.close(); });
  // Alice claims to be "carol" in the frame; Bob must see from=alice.
  a.send({ type: "call-invite", to: "bob", from: "carol", media: { audio: true, video: false } });
  const invite = await b.waitFor((m) => m.type === "call-invite");
  assert.equal(invite.from, "alice");
});
