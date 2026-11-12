# PrivChat

**A privacy messenger with no phone number and no email.** Register with just a
username and a password. Your encryption keys are generated on your device and
never leave it. Text chat is end-to-end encrypted; audio/video calls run over
WebRTC. The relay server only ever sees ciphertext and routing metadata — it
is technically unable to read your messages.

Think of it as a self-hostable, open-source (GPL-3.0) starting point in the
spirit of Signal/WhatsApp — without the phone-number identity requirement.

## Features

- **No phone / no email registration** — username + password only. Passwords
  are stored as scrypt hashes; there is no phone or email column anywhere in
  the database.
- **End-to-end encrypted text chat** — X25519 ECDH → HKDF-SHA256 →
  AES-256-GCM ("privchat-v1" protocol, see below).
- **Offline delivery** — messages to offline users are queued (as ciphertext)
  and delivered exactly once on their next login, then deleted.
- **Audio & video calls** — WebRTC (`RTCPeerConnection`); the server relays
  only SDP/ICE signaling text and never touches media.
- **Web client included** — a single-page app (vanilla JS + WebCrypto) served
  by the server itself; works in modern Android/desktop browsers.
- **Tiny footprint** — Node 24, one runtime dependency (`ws`), SQLite storage.

## Quickstart

```bash
npm install
npm run build
npm start            # PORT=8787 by default; DB at ./data/privchat.db
```

Open <http://localhost:8787>, register a user in one browser profile, register
a second user in another profile/window, add each other by username, and chat.
Audio/video calls need a camera/mic permission grant from the browser.

Development mode (no build step): `npm run dev`

## Architecture

```
 Browser A (web client)                    Browser B (web client)
 ┌───────────────────────┐                 ┌───────────────────────┐
 │ X25519 private key    │                 │ X25519 private key    │
 │ (localStorage, JWK)   │                 │ (localStorage, JWK)   │
 │ WebCrypto: ECDH/HKDF/ │                 │ WebCrypto: ECDH/HKDF/ │
 │ AES-GCM, WebRTC media │                 │ AES-GCM, WebRTC media │
 └──────────┬────────────┘                 └──────────┬────────────┘
            │  ciphertext over WebSocket              │
            │ ───────────────┐      ┌─────────────────┘
            │                ▼      ▼        media: direct P2P (WebRTC)
            │        ┌──────────────────┐   ◄ - - - - - - - - - - - ┘
            └───────►│  PrivChat server │      (server never sees media)
                     │  - accounts      │
                     │  - WS relay      │
                     │  - offline queue │  (ciphertext only, SQLite)
                     │  - SDP/ICE relay │
                     │  - static client │
                     └──────────────────┘
```

### Protocol "privchat-v1"

- **Identity:** each client generates an X25519 keypair. The public key is
  uploaded at registration; the private key never leaves the device.
- **Session key:** `HKDF-SHA256( ECDH(myPriv, peerPub), salt, info )` where
  `salt = the two usernames, sorted, joined with ":"` and
  `info = "privchat-v1"`. Output: a 32-byte AES-256-GCM key. Both sides derive
  the identical key.
- **Message:** AES-256-GCM, random 12-byte nonce per message.
  Wire frame: `{type:"msg", to, nonce, ciphertext}` with base64 fields and
  `ciphertext = ciphertext || 16-byte auth tag`. Any tampering or wrong key
  fails decryption loudly.
- **Reference implementation:** `src/crypto/protocol.ts` (Node `crypto`).
  The browser client (`public/app.js`) implements the identical derivation
  with WebCrypto; the formats and parameters are wire-compatible.

### Server API

| Route | Purpose |
|---|---|
| `POST /api/register` | `{username, password, publicKey}` → 201 (409 if taken) |
| `POST /api/login` | `{username, password}` → `{token}` (scrypt-verified) |
| `GET /api/users/:name/pubkey` | Bearer-auth public key lookup (for adding contacts) |
| `GET /` | the web client |
| `WS /ws` | first frame `{type:"auth", token}`; then `msg` + call-signaling frames |

Signaling frames relayed live-only between the two parties:
`call-invite`, `call-accept`, `call-reject`, `call-end`, `sdp`, `ice`.
The server stamps the authenticated sender onto every relayed frame — a client
cannot spoof `from`.

## Security model — honestly

**What is protected**

- Message *content*: end-to-end encrypted with AES-256-GCM; keys are derived
  from X25519 keypairs generated on user devices. The server stores and
  relays ciphertext only, and queued offline messages are deleted on delivery.
- Identity: no phone number, no email — nothing to leak or SIM-swap.
- Passwords: scrypt-hashed with per-user salts. Session tokens are random and
  stored only as SHA-256 hashes.

**What is NOT protected / known limits (v0.1)**

- **Metadata:** the server necessarily sees usernames, IP addresses,
  connection timing, who talks to whom, and ciphertext sizes. E2EE protects
  content, not metadata.
- **No forward secrecy yet:** v0.1 uses one long-term identity key per user
  (no Double Ratchet). If a private key is compromised, past messages to that
  user can be decrypted. A libsignal-style ratchet is the planned v0.2 work.
- **Calls:** media is encrypted by WebRTC (DTLS-SRTP) between peers, but call
  *setup* metadata passes through the server, and there is **no TURN server**
  included — calls may fail on restrictive NATs. STUN uses Google's public
  STUN server, which is another metadata exposure to be aware of.
- **Key storage in the web client** is browser localStorage (as a JWK). Malware
  or XSS on the device/browser can steal it. There is no key backup or
  multi-device sync in v0.1: logging in on a new device without the original
  keys cannot decrypt history.
- **Unaudited v0.1:** this code has an automated test suite, not a security
  audit. Do not rely on it for high-risk communications.

## Tests

```bash
npm test            # 20 tests: crypto, accounts, relay, signaling, smoke
npm run test:built  # same suite against the compiled dist/ output
```

The suite covers: ECDH key agreement, encrypt/decrypt round-trip, tamper and
wrong-key rejection, registration/login rules, password-at-rest checks, live
relay byte-identity, offline queue deliver-once semantics, signaling privacy
(third parties receive nothing), sender spoofing resistance, and an
end-to-end smoke test through the real HTTP + WebSocket server.

## Roadmap

- v0.2: Double Ratchet forward secrecy; safety-number verification
- Group chats; native Android/iOS clients; TURN server packaging
- Key backup / multi-device support

## Author

**Tahir Younas — Tytechlabs**
LinkedIn: https://www.linkedin.com/in/tahiryounas604

## License

GPL-3.0 — see [LICENSE](LICENSE).
