"use strict";
/*
 * PrivChat web client (v0.1).
 *
 * Cryptography — identical to the reference implementation in
 * src/crypto/protocol.ts, done here with WebCrypto (SubtleCrypto):
 *   identity  : X25519 keypair, generated on this device; the private key
 *               (JWK) is stored ONLY in this browser's localStorage.
 *   session   : ECDH bits -> HKDF-SHA256, salt = sorted usernames joined
 *               with ":", info = "privchat-v1" -> AES-256-GCM key.
 *   message   : AES-GCM, random 12-byte nonce; wire = {to, nonce, ciphertext}
 *               (ciphertext = base64 of ciphertext||tag, same as reference).
 * Calls use RTCPeerConnection; the server only relays SDP/ICE signaling.
 */

const $ = (id) => document.getElementById(id);
const subtle = window.crypto.subtle;
const PROTOCOL_INFO = "privchat-v1";
const STUN = { iceServers: [{ urls: "stun:stun.l.google.com:19302" }] };

const state = {
  username: null,
  token: null,
  identity: null,      // { publicKeyB64, privateKey (CryptoKey) }
  ws: null,
  contacts: new Map(), // username -> { publicKeyB64, keyPromise, messages: [], unread }
  currentPeer: null,
  call: null,          // { peer, pc, stream, media: {audio, video}, incoming }
};

/* ---------- base64 helpers ---------- */
const b64encode = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const b64decode = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

/* ---------- identity & session keys ---------- */
async function generateIdentity() {
  const pair = await subtle.generateKeyPair(
    { name: "ECDH", namedCurve: "X25519" }, true, ["deriveBits"]);
  const raw = await subtle.exportKey("raw", pair.publicKey);
  const jwk = await subtle.exportKey("jwk", pair.privateKey);
  return { publicKeyB64: b64encode(raw), privateKey: pair.privateKey, privateKeyJwk: jwk };
}

async function loadIdentity(username) {
  const raw = localStorage.getItem(`privchat:identity:${username}`);
  if (!raw) return null;
  const saved = JSON.parse(raw);
  const privateKey = await subtle.importKey(
    "jwk", saved.privateKeyJwk, { name: "ECDH", namedCurve: "X25519" }, true, ["deriveBits"]);
  return { publicKeyB64: saved.publicKeyB64, privateKey };
}

function saveIdentity(username, identity) {
  localStorage.setItem(`privchat:identity:${username}`, JSON.stringify({
    publicKeyB64: identity.publicKeyB64, privateKeyJwk: identity.privateKeyJwk,
  }));
}

async function deriveSessionKey(peerUsername, peerPublicKeyB64) {
  const peerKey = await subtle.importKey(
    "raw", b64decode(peerPublicKeyB64), { name: "ECDH", namedCurve: "X25519" }, false, []);
  const bits = await subtle.deriveBits(
    { name: "ECDH", public: peerKey }, state.identity.privateKey, 256);
  const hkdfBase = await subtle.importKey("raw", bits, "HKDF", false, ["deriveKey"]);
  const salt = new TextEncoder().encode([state.username, peerUsername].sort().join(":"));
  return subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt, info: new TextEncoder().encode(PROTOCOL_INFO) },
    hkdfBase, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}

async function encryptFor(peer, plaintext) {
  const contact = state.contacts.get(peer);
  const key = await contact.keyPromise;
  const nonce = window.crypto.getRandomValues(new Uint8Array(12));
  const ct = await subtle.encrypt(
    { name: "AES-GCM", iv: nonce }, key, new TextEncoder().encode(plaintext));
  return { nonce: b64encode(nonce), ciphertext: b64encode(ct) };
}

async function decryptFrom(peer, msg) {
  const contact = state.contacts.get(peer);
  const key = await contact.keyPromise;
  const pt = await subtle.decrypt(
    { name: "AES-GCM", iv: b64decode(msg.nonce) }, key, b64decode(msg.ciphertext));
  return new TextDecoder().decode(pt);
}

/* ---------- HTTP ---------- */
async function api(path, options = {}) {
  const res = await fetch(path, {
    ...options,
    headers: { "content-type": "application/json", ...(options.headers || {}) },
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.error || `HTTP ${res.status}`);
  return body;
}

/* ---------- contacts ---------- */
async function addContact(username) {
  if (username === state.username) throw new Error("that's you");
  if (state.contacts.has(username)) { selectPeer(username); return; }
  const { publicKey } = await api(`/api/users/${encodeURIComponent(username)}/pubkey`, {
    headers: { authorization: `Bearer ${state.token}` },
  });
  const contact = {
    publicKeyB64: publicKey, messages: [], unread: 0,
    keyPromise: deriveSessionKey(username, publicKey),
  };
  state.contacts.set(username, contact);
  renderContacts();
  selectPeer(username);
}

function renderContacts() {
  const ul = $("contacts");
  ul.innerHTML = "";
  for (const [name, c] of state.contacts) {
    const li = document.createElement("li");
    li.textContent = name;
    if (c.unread > 0) {
      const badge = document.createElement("span");
      badge.className = "badge"; badge.textContent = c.unread;
      li.appendChild(badge);
    }
    if (name === state.currentPeer) li.className = "active";
    li.onclick = () => selectPeer(name);
    ul.appendChild(li);
  }
}

function selectPeer(name) {
  state.currentPeer = name;
  const c = state.contacts.get(name);
  c.unread = 0;
  $("peer-label").textContent = name;
  $("message-input").disabled = false;
  $("btn-send").disabled = false;
  $("btn-call-audio").disabled = false;
  $("btn-call-video").disabled = false;
  renderContacts();
  renderMessages();
}

function renderMessages() {
  const box = $("messages");
  box.innerHTML = "";
  const c = state.contacts.get(state.currentPeer);
  if (!c) return;
  for (const m of c.messages) {
    const div = document.createElement("div");
    div.className = "msg" + (m.mine ? " mine" : "") + (m.failed ? " undecryptable" : "");
    div.textContent = m.text;
    box.appendChild(div);
  }
  box.scrollTop = box.scrollHeight;
}

/* ---------- WebSocket ---------- */
function connectWs() {
  const proto = location.protocol === "https:" ? "wss:" : "ws:";
  state.ws = new WebSocket(`${proto}//${location.host}/ws`);
  state.ws.onopen = () => state.ws.send(JSON.stringify({ type: "auth", token: state.token }));
  state.ws.onclose = () => { $("conn-label").textContent = "disconnected"; };
  state.ws.onmessage = async (event) => {
    const frame = JSON.parse(event.data);
    if (frame.type === "auth-ok") {
      $("conn-label").textContent = "connected · end-to-end encrypted";
      return;
    }
    if (frame.type === "msg") { await onChatMessage(frame); return; }
    if (["call-invite", "call-accept", "call-reject", "call-end", "sdp", "ice", "call-unavailable"]
      .includes(frame.type)) { await onSignal(frame); }
  };
}

async function onChatMessage(frame) {
  const from = frame.from;
  if (!state.contacts.has(from)) {
    try { await addContact(from); } catch { /* unknown sender; drop */ }
    if (!state.contacts.has(from)) return;
  }
  const contact = state.contacts.get(from);
  let entry;
  try {
    entry = { mine: false, text: await decryptFrom(from, frame) };
  } catch {
    entry = { mine: false, failed: true, text: "⚠ could not decrypt this message" };
  }
  contact.messages.push(entry);
  if (state.currentPeer === from) renderMessages();
  else { contact.unread += 1; renderContacts(); }
}

/* ---------- calls (WebRTC) ---------- */
function sendSignal(frame) { state.ws.send(JSON.stringify(frame)); }

async function startCall(media) {
  const peer = state.currentPeer;
  if (!peer || state.call) return;
  state.call = { peer, media, incoming: false, pc: null, stream: null };
  showCallPanel(`Calling ${peer}…`);
  sendSignal({ type: "call-invite", to: peer, media });
}

async function onSignal(frame) {
  const from = frame.from;
  if (frame.type === "call-invite") {
    if (state.call) { sendSignal({ type: "call-reject", to: from }); return; }
    state.call = { peer: from, media: frame.media || { audio: true, video: false }, incoming: true, pc: null, stream: null };
    showCallPanel(`Incoming ${frame.media && frame.media.video ? "video" : "audio"} call from ${from}`);
    $("btn-accept").hidden = false;
    $("btn-reject").hidden = false;
    return;
  }
  if (!state.call || state.call.peer !== from) return;
  if (frame.type === "call-accept") {
    await setupPeerConnection();
    const offer = await state.call.pc.createOffer();
    await state.call.pc.setLocalDescription(offer);
    sendSignal({ type: "sdp", to: from, sdp: offer });
    $("call-status").textContent = `In call with ${from}`;
    return;
  }
  if (frame.type === "sdp") {
    const pc = state.call.pc ?? (await setupPeerConnection());
    await pc.setRemoteDescription(frame.sdp);
    if (frame.sdp.type === "offer") {
      const answer = await pc.createAnswer();
      await pc.setLocalDescription(answer);
      sendSignal({ type: "sdp", to: from, sdp: answer });
    }
    return;
  }
  if (frame.type === "ice" && state.call.pc && frame.candidate) {
    try { await state.call.pc.addIceCandidate(frame.candidate); } catch { /* stale */ }
    return;
  }
  if (frame.type === "call-reject" || frame.type === "call-end" || frame.type === "call-unavailable") {
    $("call-status").textContent =
      frame.type === "call-unavailable" ? `${from} is offline` : "Call ended";
    endCall(false);
  }
}

async function setupPeerConnection() {
  const call = state.call;
  call.stream = await navigator.mediaDevices.getUserMedia({
    audio: true, video: !!call.media.video,
  });
  $("local-video").srcObject = call.stream;
  $("local-video").style.display = call.media.video ? "" : "none";
  const pc = new RTCPeerConnection(STUN);
  call.pc = pc;
  for (const track of call.stream.getTracks()) pc.addTrack(track, call.stream);
  pc.ontrack = (e) => { $("remote-video").srcObject = e.streams[0]; };
  pc.onicecandidate = (e) => {
    if (e.candidate) sendSignal({ type: "ice", to: call.peer, candidate: e.candidate.toJSON() });
  };
  pc.onconnectionstatechange = () => {
    if (["disconnected", "failed", "closed"].includes(pc.connectionState)) endCall(false);
  };
  $("btn-mute").hidden = false;
  $("btn-hangup").hidden = false;
  return pc;
}

function showCallPanel(status) {
  $("call-panel").hidden = false;
  $("call-status").textContent = status;
  $("btn-accept").hidden = true;
  $("btn-reject").hidden = true;
  $("btn-mute").hidden = true;
  $("btn-hangup").hidden = true;
}

function endCall(notify) {
  const call = state.call;
  if (call && notify) sendSignal({ type: "call-end", to: call.peer });
  if (call && call.pc) call.pc.close();
  if (call && call.stream) for (const t of call.stream.getTracks()) t.stop();
  state.call = null;
  setTimeout(() => { $("call-panel").hidden = true; }, 1200);
}

/* ---------- auth flows ---------- */
async function doRegister() {
  const username = $("reg-username").value.trim();
  const password = $("reg-password").value;
  const identity = await generateIdentity();
  await api("/api/register", {
    method: "POST",
    body: JSON.stringify({ username, password, publicKey: identity.publicKeyB64 }),
  });
  saveIdentity(username, identity);
  $("auth-error").textContent = "Registered. Now login.";
  $("login-username").value = username;
}

async function doLogin() {
  const username = $("login-username").value.trim();
  const password = $("login-password").value;
  const { token } = await api("/api/login", {
    method: "POST", body: JSON.stringify({ username, password }),
  });
  const identity = await loadIdentity(username);
  if (!identity) {
    $("auth-error").textContent =
      "No keys for this user in this browser. Registering on a device creates its keys; " +
      "logging in elsewhere can receive but not decrypt (v0.1 limitation).";
    // Create a fresh keypair so the client still functions for sending is NOT
    // possible safely (server has the registered key) — refuse to continue.
    throw new Error("no local keys for this account on this device");
  }
  state.username = username;
  state.token = token;
  state.identity = identity;
  $("me-label").textContent = `👤 ${username}`;
  $("auth-screen").hidden = true;
  $("chat-screen").hidden = false;
  connectWs();
}

/* ---------- wiring ---------- */
$("btn-register").onclick = () =>
  doRegister().catch((e) => { $("auth-error").textContent = e.message; });
$("btn-login").onclick = () =>
  doLogin().catch((e) => { $("auth-error").textContent = e.message; });
$("btn-logout").onclick = () => location.reload();
$("btn-add-contact").onclick = () =>
  addContact($("new-contact").value.trim())
    .then(() => { $("new-contact").value = ""; $("contact-error").textContent = ""; })
    .catch((e) => { $("contact-error").textContent = e.message; });
$("send-form").onsubmit = async (e) => {
  e.preventDefault();
  const peer = state.currentPeer;
  const text = $("message-input").value;
  if (!peer || !text) return;
  const enc = await encryptFor(peer, text);
  state.ws.send(JSON.stringify({ type: "msg", to: peer, ...enc }));
  state.contacts.get(peer).messages.push({ mine: true, text });
  $("message-input").value = "";
  renderMessages();
};
$("btn-call-audio").onclick = () => startCall({ audio: true, video: false });
$("btn-call-video").onclick = () => startCall({ audio: true, video: true });
$("btn-accept").onclick = async () => {
  $("btn-accept").hidden = true; $("btn-reject").hidden = true;
  await setupPeerConnection();
  $("call-status").textContent = `In call with ${state.call.peer}`;
  sendSignal({ type: "call-accept", to: state.call.peer });
};
$("btn-reject").onclick = () => {
  sendSignal({ type: "call-reject", to: state.call.peer });
  endCall(false);
};
$("btn-hangup").onclick = () => endCall(true);
$("btn-mute").onclick = () => {
  const stream = state.call && state.call.stream;
  if (!stream) return;
  for (const t of stream.getAudioTracks()) t.enabled = !t.enabled;
  $("btn-mute").textContent = stream.getAudioTracks()[0].enabled ? "Mute" : "Unmute";
};
