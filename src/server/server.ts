/**
 * PrivChat relay server.
 *
 *   POST /api/register  {username, password, publicKey}      -> 201 | 400 | 409
 *   POST /api/login     {username, password}                 -> 200 {token} | 401
 *   GET  /api/users/:username/pubkey   (Bearer session token) -> 200 {username, publicKey} | 404
 *   GET  / and /app.js, /style.css                            -> the web client
 *   WS   /ws — first frame must be {type:"auth", token}
 *
 * Relayed WebSocket frames (all JSON):
 *   {type:"msg", to, nonce, ciphertext}   end-to-end encrypted blob.
 *        Delivered live if the recipient is online, otherwise queued in
 *        SQLite and delivered (then deleted) on their next login.
 *   {type:"call-invite"|"call-accept"|"call-reject"|"call-end", to, ...}
 *   {type:"sdp", to, sdp}   {type:"ice", to, candidate}
 *        WebRTC signaling only — media flows peer-to-peer, never via here.
 *
 * The server is technically unable to read message content: it routes
 * opaque ciphertext by username. It DOES see metadata (usernames, IPs,
 * timing, ciphertext sizes) — see README "Security model" for honesty.
 */
import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { extname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";
import { WebSocket, WebSocketServer } from "ws";
import { authenticateToken, loginUser, registerUser } from "./auth.ts";
import { Store } from "./store.ts";

const SIGNALING_TYPES = new Set([
  "call-invite",
  "call-accept",
  "call-reject",
  "call-end",
  "sdp",
  "ice",
]);
const MAX_BODY_BYTES = 64 * 1024;
const MAX_WS_PAYLOAD = 1024 * 1024;
const AUTH_TIMEOUT_MS = 10_000;

const MIME: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".png": "image/png",
  ".svg": "image/svg+xml",
};

export interface PrivChatServer {
  httpServer: Server;
  store: Store;
  /** Listen (default port 0 = ephemeral). Resolves to the bound port. */
  listen(port?: number): Promise<number>;
  close(): Promise<void>;
}

export interface ServerOptions {
  dbPath: string;
  publicDir?: string;
}

interface ClientState {
  username: string | undefined;
  authTimer: NodeJS.Timeout | undefined;
}

export function createPrivChatServer(options: ServerOptions): PrivChatServer {
  const store = new Store(options.dbPath);
  const publicDir = options.publicDir ?? defaultPublicDir();
  const clients = new Map<string, Set<WebSocket>>();

  const httpServer = createServer((req, res) => {
    handleHttp(req, res).catch(() => {
      if (!res.headersSent) sendJson(res, 500, { error: "internal error" });
    });
  });

  const wss = new WebSocketServer({ server: httpServer, path: "/ws", maxPayload: MAX_WS_PAYLOAD });

  wss.on("connection", (socket: WebSocket) => {
    const state: ClientState = { username: undefined, authTimer: undefined };
    state.authTimer = setTimeout(() => {
      if (state.username === undefined) socket.close(4001, "auth timeout");
    }, AUTH_TIMEOUT_MS);

    socket.on("message", (data: Buffer) => {
      let frame: Record<string, unknown>;
      try {
        frame = JSON.parse(data.toString("utf8")) as Record<string, unknown>;
      } catch {
        sendFrame(socket, { type: "error", error: "frame must be JSON" });
        return;
      }
      if (state.username === undefined) {
        handleAuthFrame(socket, state, frame);
        return;
      }
      handleAuthedFrame(socket, state.username, frame);
    });

    socket.on("close", () => {
      if (state.authTimer !== undefined) clearTimeout(state.authTimer);
      if (state.username !== undefined) removeClient(state.username, socket);
    });
    socket.on("error", () => {
      /* the close handler does cleanup */
    });
  });

  function sendFrame(socket: WebSocket, frame: Record<string, unknown>): void {
    if (socket.readyState === WebSocket.OPEN) socket.send(JSON.stringify(frame));
  }

  function addClient(username: string, socket: WebSocket): void {
    let set = clients.get(username);
    if (set === undefined) {
      set = new Set();
      clients.set(username, set);
    }
    set.add(socket);
  }

  function removeClient(username: string, socket: WebSocket): void {
    const set = clients.get(username);
    if (set === undefined) return;
    set.delete(socket);
    if (set.size === 0) clients.delete(username);
  }

  function deliver(username: string, frame: Record<string, unknown>): number {
    const set = clients.get(username);
    if (set === undefined) return 0;
    let sent = 0;
    for (const socket of set) {
      sendFrame(socket, frame);
      sent += 1;
    }
    return sent;
  }

  function handleAuthFrame(
    socket: WebSocket,
    state: ClientState,
    frame: Record<string, unknown>,
  ): void {
    if (frame.type !== "auth" || typeof frame.token !== "string") {
      sendFrame(socket, { type: "error", error: "first frame must be {type:'auth', token}" });
      socket.close(4002, "auth required");
      return;
    }
    const username = authenticateToken(store, frame.token);
    if (username === undefined) {
      sendFrame(socket, { type: "error", error: "invalid session token" });
      socket.close(4003, "invalid token");
      return;
    }
    state.username = username;
    if (state.authTimer !== undefined) clearTimeout(state.authTimer);
    addClient(username, socket);
    sendFrame(socket, { type: "auth-ok", username });
    // Deliver anything queued while this user was offline, exactly once.
    for (const queued of store.drainQueue(username)) {
      sendFrame(socket, {
        type: "msg",
        from: queued.fromUser,
        nonce: queued.nonce,
        ciphertext: queued.ciphertext,
        queued: true,
      });
    }
  }

  function handleAuthedFrame(
    socket: WebSocket,
    from: string,
    frame: Record<string, unknown>,
  ): void {
    const type = frame.type;
    const to = frame.to;
    if (typeof type !== "string" || typeof to !== "string") {
      sendFrame(socket, { type: "error", error: "frame needs string 'type' and 'to'" });
      return;
    }
    if (type === "msg") {
      const { nonce, ciphertext } = frame;
      if (typeof nonce !== "string" || typeof ciphertext !== "string") {
        sendFrame(socket, { type: "error", error: "msg needs string 'nonce' and 'ciphertext'" });
        return;
      }
      if (store.getUser(to) === undefined) {
        sendFrame(socket, { type: "error", error: "no such user", to });
        return;
      }
      const delivered = deliver(to, { type: "msg", from, nonce, ciphertext });
      if (delivered === 0) store.enqueue(from, to, nonce, ciphertext);
      return;
    }
    if (SIGNALING_TYPES.has(type)) {
      // Relay verbatim (plus the authenticated sender), live only — calls
      // are not queued. The server never sees media, only SDP/ICE text.
      const relayed: Record<string, unknown> = { ...frame, from };
      const delivered = deliver(to, relayed);
      if (delivered === 0 && type === "call-invite") {
        sendFrame(socket, { type: "call-unavailable", to });
      }
      return;
    }
    sendFrame(socket, { type: "error", error: `unknown frame type: ${type}` });
  }

  async function handleHttp(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url ?? "/", "http://localhost");
    const path = url.pathname;

    if (req.method === "POST" && (path === "/api/register" || path === "/api/login")) {
      const body = await readJsonBody(req);
      if (body === undefined) {
        sendJson(res, 400, { error: "body must be valid JSON" });
        return;
      }
      if (path === "/api/register") {
        const result = registerUser(
          store,
          String(body.username ?? ""),
          String(body.password ?? ""),
          String(body.publicKey ?? ""),
        );
        if (!result.ok) {
          const status = result.error === "username already taken" ? 409 : 400;
          sendJson(res, status, { error: result.error });
          return;
        }
        sendJson(res, 201, { username: result.value.username });
        return;
      }
      const result = loginUser(store, String(body.username ?? ""), String(body.password ?? ""));
      if (!result.ok) {
        sendJson(res, 401, { error: result.error });
        return;
      }
      sendJson(res, 200, { token: result.value.token });
      return;
    }

    const pubkeyMatch = /^\/api\/users\/([^/]+)\/pubkey$/.exec(path);
    if (req.method === "GET" && pubkeyMatch !== null) {
      const auth = req.headers.authorization ?? "";
      const token = auth.startsWith("Bearer ") ? auth.slice("Bearer ".length) : "";
      if (authenticateToken(store, token) === undefined) {
        sendJson(res, 401, { error: "login required" });
        return;
      }
      const target = decodeURIComponent(pubkeyMatch[1] ?? "");
      const user = store.getUser(target);
      if (user === undefined) {
        sendJson(res, 404, { error: "no such user" });
        return;
      }
      sendJson(res, 200, { username: user.username, publicKey: user.publicKey });
      return;
    }

    if (req.method === "GET" && path === "/health") {
      sendJson(res, 200, { ok: true });
      return;
    }

    if (req.method === "GET") {
      await serveStatic(path, res);
      return;
    }

    sendJson(res, 404, { error: "not found" });
  }

  async function serveStatic(path: string, res: ServerResponse): Promise<void> {
    const rel = path === "/" ? "index.html" : path.replace(/^\/+/, "");
    const file = normalize(join(publicDir, rel));
    if (!file.startsWith(normalize(publicDir))) {
      sendJson(res, 403, { error: "forbidden" });
      return;
    }
    try {
      const content = await readFile(file);
      res.writeHead(200, { "content-type": MIME[extname(file)] ?? "application/octet-stream" });
      res.end(content);
    } catch {
      sendJson(res, 404, { error: "not found" });
    }
  }

  return {
    httpServer,
    store,
    listen(port = 0): Promise<number> {
      return new Promise((resolve, reject) => {
        httpServer.once("error", reject);
        httpServer.listen(port, () => {
          const address = httpServer.address();
          if (address === null || typeof address === "string") {
            reject(new Error("server did not bind a TCP port"));
            return;
          }
          resolve(address.port);
        });
      });
    },
    close(): Promise<void> {
      return new Promise((resolve) => {
        for (const set of clients.values()) {
          for (const socket of set) socket.terminate();
        }
        clients.clear();
        wss.close(() => {
          httpServer.close(() => {
            store.close();
            resolve();
          });
        });
      });
    },
  };
}

/**
 * Locate the bundled web client. Source layout is src/server/ -> ../../public;
 * compiled layout is dist/src/server/ -> ../../../public. First match wins.
 */
function defaultPublicDir(): string {
  const here = fileURLToPath(new URL(".", import.meta.url));
  for (const rel of ["../../public", "../../../public"]) {
    const candidate = normalize(join(here, rel));
    if (existsSync(join(candidate, "index.html"))) return candidate;
  }
  return normalize(join(here, "../../public"));
}

function sendJson(res: ServerResponse, status: number, body: Record<string, unknown>): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, { "content-type": "application/json; charset=utf-8" });
  res.end(payload);
}

async function readJsonBody(req: IncomingMessage): Promise<Record<string, unknown> | undefined> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    const buf = chunk as Buffer;
    size += buf.length;
    if (size > MAX_BODY_BYTES) return undefined;
    chunks.push(buf);
  }
  try {
    const parsed = JSON.parse(Buffer.concat(chunks).toString("utf8")) as unknown;
    if (typeof parsed !== "object" || parsed === null) return undefined;
    return parsed as Record<string, unknown>;
  } catch {
    return undefined;
  }
}
