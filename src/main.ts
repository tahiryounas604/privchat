#!/usr/bin/env node
/**
 * PrivChat server entry point.
 *
 *   PORT=8443 PRIVCHAT_DB=./data/privchat.db npm start
 *
 * Defaults: PORT 8787, DB ./data/privchat.db (created on first run).
 * Put it behind TLS (a reverse proxy) before exposing it to the internet —
 * WebRTC and WebSocket both expect a secure origin outside localhost.
 */
import { createPrivChatServer } from "./server/server.ts";

const port = Number.parseInt(process.env.PORT ?? "8787", 10);
const dbPath = process.env.PRIVCHAT_DB ?? "./data/privchat.db";

const server = createPrivChatServer({ dbPath });
const bound = await server.listen(port);
console.log(`PrivChat server listening on http://localhost:${bound}`);
console.log(`Database: ${dbPath}`);

for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.on(signal, () => {
    void server.close().then(() => process.exit(0));
  });
}
