import assert from "node:assert/strict";
import { test } from "node:test";
import { generateIdentity } from "../src/crypto/protocol.ts";
import { startTestServer } from "./helpers.ts";

async function postJson(
  base: string,
  path: string,
  body: Record<string, unknown>,
): Promise<{ status: number; body: Record<string, unknown> }> {
  const res = await fetch(`${base}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  return { status: res.status, body: (await res.json()) as Record<string, unknown> };
}

test("register + login succeeds; token authenticates pubkey lookup", async (t) => {
  const srv = await startTestServer();
  t.after(() => srv.cleanup());
  const alice = generateIdentity();
  const reg = await postJson(srv.base, "/api/register", {
    username: "alice",
    password: "alice-password-1",
    publicKey: alice.publicKeyB64,
  });
  assert.equal(reg.status, 201);

  const login = await postJson(srv.base, "/api/login", {
    username: "alice",
    password: "alice-password-1",
  });
  assert.equal(login.status, 200);
  assert.equal(typeof login.body.token, "string");

  const res = await fetch(`${srv.base}/api/users/alice/pubkey`, {
    headers: { authorization: `Bearer ${String(login.body.token)}` },
  });
  assert.equal(res.status, 200);
  const body = (await res.json()) as { publicKey: string };
  assert.equal(body.publicKey, alice.publicKeyB64);
});

test("wrong password is rejected; unknown user is rejected identically", async (t) => {
  const srv = await startTestServer();
  t.after(() => srv.cleanup());
  const id = generateIdentity();
  await postJson(srv.base, "/api/register", {
    username: "bob",
    password: "bob-password-1",
    publicKey: id.publicKeyB64,
  });
  const wrong = await postJson(srv.base, "/api/login", { username: "bob", password: "nope-nope-nope" });
  assert.equal(wrong.status, 401);
  const ghost = await postJson(srv.base, "/api/login", { username: "ghost", password: "whatever-123" });
  assert.equal(ghost.status, 401);
});

test("duplicate username is rejected with 409", async (t) => {
  const srv = await startTestServer();
  t.after(() => srv.cleanup());
  const a = generateIdentity();
  const b = generateIdentity();
  const first = await postJson(srv.base, "/api/register", {
    username: "carol",
    password: "carol-password",
    publicKey: a.publicKeyB64,
  });
  assert.equal(first.status, 201);
  const second = await postJson(srv.base, "/api/register", {
    username: "carol",
    password: "other-password",
    publicKey: b.publicKeyB64,
  });
  assert.equal(second.status, 409);
});

test("password is never stored in plain text (scrypt hash + salt at rest)", async (t) => {
  const srv = await startTestServer();
  t.after(() => srv.cleanup());
  const id = generateIdentity();
  await postJson(srv.base, "/api/register", {
    username: "dave",
    password: "dave-password-9",
    publicKey: id.publicKeyB64,
  });
  const row = srv.app.store.getUser("dave");
  assert.ok(row !== undefined);
  assert.notEqual(row.passHash, "dave-password-9");
  assert.ok(!row.passHash.includes("dave"));
  assert.equal(row.passHash.length, 128); // 64-byte scrypt output, hex
  assert.equal(row.passSalt.length, 32); // 16-byte salt, hex
});

test("bad inputs rejected: short password, bad username, bad public key", async (t) => {
  const srv = await startTestServer();
  t.after(() => srv.cleanup());
  const id = generateIdentity();
  const short = await postJson(srv.base, "/api/register", {
    username: "erin",
    password: "short",
    publicKey: id.publicKeyB64,
  });
  assert.equal(short.status, 400);
  const badName = await postJson(srv.base, "/api/register", {
    username: "no spaces!",
    password: "long-enough-1",
    publicKey: id.publicKeyB64,
  });
  assert.equal(badName.status, 400);
  const badKey = await postJson(srv.base, "/api/register", {
    username: "erin",
    password: "long-enough-1",
    publicKey: "AAAA",
  });
  assert.equal(badKey.status, 400);
});

test("pubkey lookup requires auth and 404s for unknown users", async (t) => {
  const srv = await startTestServer();
  t.after(() => srv.cleanup());
  const id = generateIdentity();
  await postJson(srv.base, "/api/register", {
    username: "frank",
    password: "frank-password",
    publicKey: id.publicKeyB64,
  });
  const login = await postJson(srv.base, "/api/login", {
    username: "frank",
    password: "frank-password",
  });
  const noAuth = await fetch(`${srv.base}/api/users/frank/pubkey`);
  assert.equal(noAuth.status, 401);
  const missing = await fetch(`${srv.base}/api/users/nobody/pubkey`, {
    headers: { authorization: `Bearer ${String(login.body.token)}` },
  });
  assert.equal(missing.status, 404);
});
