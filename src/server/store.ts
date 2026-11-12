/**
 * SQLite storage (node:sqlite). The server stores ONLY:
 *   - usernames, scrypt password hashes (+salt), and public keys
 *   - session token hashes (never the tokens themselves)
 *   - QUEUED CIPHERTEXT for offline users (deleted on delivery)
 *
 * Message plaintext is never stored — the server cannot produce it.
 * There are deliberately NO phone-number or email columns anywhere.
 */
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { DatabaseSync } from "node:sqlite";

export interface UserRow {
  username: string;
  passHash: string;
  passSalt: string;
  publicKey: string;
  createdAt: number;
}

export interface QueuedMessage {
  id: number;
  fromUser: string;
  toUser: string;
  nonce: string;
  ciphertext: string;
  createdAt: number;
}

export class Store {
  private readonly db: DatabaseSync;

  constructor(path: string) {
    if (path !== ":memory:") mkdirSync(dirname(path), { recursive: true });
    this.db = new DatabaseSync(path);
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS users (
        username   TEXT PRIMARY KEY,
        pass_hash  TEXT NOT NULL,
        pass_salt  TEXT NOT NULL,
        public_key TEXT NOT NULL,
        created_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS sessions (
        token_hash TEXT PRIMARY KEY,
        username   TEXT NOT NULL,
        created_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS queue (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        from_user  TEXT NOT NULL,
        to_user    TEXT NOT NULL,
        nonce      TEXT NOT NULL,
        ciphertext TEXT NOT NULL,
        created_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_queue_to ON queue(to_user, id);
    `);
  }

  createUser(user: UserRow): void {
    this.db
      .prepare(
        "INSERT INTO users (username, pass_hash, pass_salt, public_key, created_at) VALUES (?, ?, ?, ?, ?)",
      )
      .run(user.username, user.passHash, user.passSalt, user.publicKey, user.createdAt);
  }

  getUser(username: string): UserRow | undefined {
    const row = this.db
      .prepare(
        "SELECT username, pass_hash AS passHash, pass_salt AS passSalt, public_key AS publicKey, created_at AS createdAt FROM users WHERE username = ?",
      )
      .get(username) as UserRow | undefined;
    return row;
  }

  createSession(tokenHash: string, username: string): void {
    this.db
      .prepare("INSERT INTO sessions (token_hash, username, created_at) VALUES (?, ?, ?)")
      .run(tokenHash, username, Date.now());
  }

  getSessionUsername(tokenHash: string): string | undefined {
    const row = this.db
      .prepare("SELECT username FROM sessions WHERE token_hash = ?")
      .get(tokenHash) as { username: string } | undefined;
    return row?.username;
  }

  deleteSession(tokenHash: string): void {
    this.db.prepare("DELETE FROM sessions WHERE token_hash = ?").run(tokenHash);
  }

  enqueue(fromUser: string, toUser: string, nonce: string, ciphertext: string): number {
    const info = this.db
      .prepare(
        "INSERT INTO queue (from_user, to_user, nonce, ciphertext, created_at) VALUES (?, ?, ?, ?, ?)",
      )
      .run(fromUser, toUser, nonce, ciphertext, Date.now());
    return Number(info.lastInsertRowid);
  }

  /** Atomically read + delete all queued messages for a user (deliver-once). */
  drainQueue(toUser: string): QueuedMessage[] {
    this.db.exec("BEGIN");
    try {
      const rows = this.db
        .prepare(
          "SELECT id, from_user AS fromUser, to_user AS toUser, nonce, ciphertext, created_at AS createdAt FROM queue WHERE to_user = ? ORDER BY id ASC",
        )
        .all(toUser) as unknown as QueuedMessage[];
      this.db.prepare("DELETE FROM queue WHERE to_user = ?").run(toUser);
      this.db.exec("COMMIT");
      return rows;
    } catch (err) {
      this.db.exec("ROLLBACK");
      throw err;
    }
  }

  queueDepth(toUser: string): number {
    const row = this.db
      .prepare("SELECT COUNT(*) AS n FROM queue WHERE to_user = ?")
      .get(toUser) as { n: number };
    return row.n;
  }

  close(): void {
    this.db.close();
  }
}
