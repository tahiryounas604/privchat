/** Shared test helpers: ephemeral server + HTTP/WS client plumbing. */
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import WebSocket from "ws";
import { generateIdentity, type Identity } from "../src/crypto/protocol.ts";
import { createPrivChatServer, type PrivChatServer } from "../src/server/server.ts";

export interface TestServer {
  app: PrivChatServer;
  port: number;
  base: string;
  cleanup(): Promise<void>;
}

export async function startTestServer(): Promise<TestServer> {
  const dir = mkdtempSync(join(tmpdir(), "privchat-test-"));
  const app = createPrivChatServer({ dbPath: join(dir, "test.db") });
  const port = await app.listen(0);
  return {
    app,
    port,
    base: `http://127.0.0.1:${port}`,
    async cleanup() {
      await app.close();
      rmSync(dir, { recursive: true, force: true });
    },
  };
}

export interface TestUser {
  username: string;
  password: string;
  identity: Identity;
  token: string;
}

/** Register (with a fresh client-side identity) and log in. */
export async function createUser(
  base: string,
  username: string,
  password = "correct horse battery",
): Promise<TestUser> {
  const identity = generateIdentity();
  const reg = await fetch(`${base}/api/register`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ username, password, publicKey: identity.publicKeyB64 }),
  });
  if (reg.status !== 201) throw new Error(`register ${username} failed: ${reg.status}`);
  const login = await fetch(`${base}/api/login`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  if (login.status !== 200) throw new Error(`login ${username} failed: ${login.status}`);
  const { token } = (await login.json()) as { token: string };
  return { username, password, identity, token };
}

export interface Client {
  ws: WebSocket;
  /** Every frame received on this connection, in order. */
  messages: Record<string, unknown>[];
  /** Resolve with the first frame matching pred (past or future). */
  waitFor(
    pred: (m: Record<string, unknown>) => boolean,
    timeoutMs?: number,
  ): Promise<Record<string, unknown>>;
  send(frame: Record<string, unknown>): void;
  close(): void;
}

/** Connect a WebSocket client and complete the auth handshake. */
export function connectClient(port: number, token: string): Promise<Client> {
  const messages: Record<string, unknown>[] = [];
  const waiters: {
    pred: (m: Record<string, unknown>) => boolean;
    resolve: (m: Record<string, unknown>) => void;
  }[] = [];
  const ws = new WebSocket(`ws://127.0.0.1:${port}/ws`);
  ws.on("message", (data: Buffer) => {
    const frame = JSON.parse(data.toString("utf8")) as Record<string, unknown>;
    messages.push(frame);
    for (let i = waiters.length - 1; i >= 0; i -= 1) {
      const w = waiters[i];
      if (w !== undefined && w.pred(frame)) {
        waiters.splice(i, 1);
        w.resolve(frame);
      }
    }
  });
  const client: Client = {
    ws,
    messages,
    waitFor(pred, timeoutMs = 5000) {
      const seen = messages.find(pred);
      if (seen !== undefined) return Promise.resolve(seen);
      return new Promise((resolve, reject) => {
        const timer = setTimeout(
          () => reject(new Error("waitFor timeout: no matching frame")),
          timeoutMs,
        );
        waiters.push({
          pred,
          resolve: (m) => {
            clearTimeout(timer);
            resolve(m);
          },
        });
      });
    },
    send(frame) {
      ws.send(JSON.stringify(frame));
    },
    close() {
      ws.close();
    },
  };
  return new Promise((resolve, reject) => {
    ws.on("error", reject);
    ws.on("open", () => ws.send(JSON.stringify({ type: "auth", token })));
    void client.waitFor((m) => m.type === "auth-ok").then(() => resolve(client), reject);
  });
}

export function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
