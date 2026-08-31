require("dotenv").config();
const express = require("express");
const http = require("http");
const path = require("path");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Server } = require("socket.io");
const {
  generateRegistrationOptions, verifyRegistrationResponse,
  generateAuthenticationOptions, verifyAuthenticationResponse
} = require("@simplewebauthn/server");
const db = require("./db");

const JWT_SECRET = process.env.JWT_SECRET || "change-this-secret-in-production";
const PORT = process.env.PORT || 3000;

// WebAuthn needs to know the domain it's running on. Set RP_ID to your bare
// domain (e.g. "swipe-app-wzqp.onrender.com") in production via env var.
// Falls back to localhost for local testing.
const RP_NAME = "SWIPE";
const RP_ID = process.env.RP_ID || "localhost";
const ORIGIN = process.env.ORIGIN || `http://localhost:${PORT}`;

const app = express();
app.use(cors());
app.use(express.json({ limit: "8mb" }));
app.use(express.static(path.join(__dirname, "public")));

const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

function authMiddleware(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Missing token." });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.userId = payload.uid;
    req.username = payload.username;
    next();
  } catch (e) {
    return res.status(401).json({ error: "Invalid or expired token." });
  }
}

// Must run AFTER authMiddleware. Re-checks admin status from the database
// on every request rather than trusting anything baked into the JWT, so a
// demotion takes effect immediately rather than only after the token expires.
function requireAdmin(req, res, next) {
  db.getUserById(req.userId)
    .then(user => {
      if (!user || !user.is_admin) return res.status(403).json({ error: "Admin access required." });
      next();
    })
    .catch(() => res.status(500).json({ error: "Server error checking admin access." }));
}

function safe(handler) {
  return (req, res) => handler(req, res).catch(err => {
    console.error(err);
    res.status(500).json({ error: "Server error. Please try again." });
  });
}

function issueToken(user) {
  return jwt.sign({ uid: user.id, username: user.username }, JWT_SECRET, { expiresIn: "30d" });
}

// ---------------------------------------------------------------------------
// PASSWORD AUTH
// ---------------------------------------------------------------------------
app.post("/api/register", safe(async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password || username.trim().length < 3 || password.length < 4) {
    return res.status(400).json({ error: "Username (3+ chars) and password (4+ chars) required." });
  }
  const clean = username.trim().toLowerCase();
  if (await db.getUserByUsername(clean)) {
    return res.status(409).json({ error: "That username is already taken." });
  }
  const hash = bcrypt.hashSync(password, 10);
  const user = await db.createUser(clean, hash);
  res.json({ token: issueToken(user), username: clean });
}));

app.post("/api/login", safe(async (req, res) => {
  const { username, password } = req.body || {};
  const clean = (username || "").trim().toLowerCase();
  const user = await db.getUserByUsername(clean);
  if (!user || !bcrypt.compareSync(password || "", user.password_hash)) {
    return res.status(401).json({ error: "Invalid username or password." });
  }
  await db.ensureBootstrapAdmin(user.username);
  const fresh = await db.getUserByUsername(clean); // re-read in case bootstrap just changed is_admin
  res.json({ token: issueToken(fresh), username: fresh.username, is_admin: !!fresh.is_admin });
}));

app.get("/api/me", authMiddleware, safe(async (req, res) => {
  const user = await db.getUserById(req.userId);
  res.json({ id: req.userId, username: req.username, is_admin: !!(user && user.is_admin) });
}));

// ---------------------------------------------------------------------------
// WEBAUTHN — BIOMETRIC LOGIN (Face ID / fingerprint / Windows Hello)
// The server only ever stores a public key + counter, never any biometric
// data. Registration requires being already logged in (password or existing
// biometric); login works standalone once a device is registered.
// ---------------------------------------------------------------------------

// STEP 1 of registering a new biometric device (must be logged in already)
app.post("/api/webauthn/register-options", authMiddleware, safe(async (req, res) => {
  const existing = await db.getAuthenticatorsByUser(req.userId);
  const options = await generateRegistrationOptions({
    rpName: RP_NAME,
    rpID: RP_ID,
    userName: req.username,
    userID: Buffer.from(String(req.userId)),
    attestationType: "none",
    excludeCredentials: existing.map(a => ({ id: a.credential_id, transports: a.transports })),
    authenticatorSelection: {
      residentKey: "preferred",
      userVerification: "required" // forces Face ID / fingerprint / PIN, not just "device present"
    }
  });
  await db.saveChallenge(req.userId, options.challenge);
  res.json(options);
}));

// STEP 2 of registering — browser sends back the signed credential
app.post("/api/webauthn/register-verify", authMiddleware, safe(async (req, res) => {
  const expectedChallenge = await db.getChallenge(req.userId);
  if (!expectedChallenge) return res.status(400).json({ error: "Registration expired. Try again." });

  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response: req.body,
      expectedChallenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID
    });
  } catch (e) {
    return res.status(400).json({ error: "Could not verify device: " + e.message });
  }
  if (!verification.verified) return res.status(400).json({ error: "Verification failed." });

  const { credential, credentialDeviceType, credentialBackedUp } = verification.registrationInfo;
  await db.addAuthenticator({
    user_id: req.userId,
    credential_id: credential.id,
    public_key: Buffer.from(credential.publicKey).toString("base64url"),
    counter: credential.counter,
    device_type: credentialDeviceType,
    backed_up: credentialBackedUp,
    transports: credential.transports || [],
    nickname: req.body.nickname || "This device"
  });
  await db.clearChallenge(req.userId);
  res.json({ ok: true });
}));

// STEP 1 of logging in with biometrics — no username needed if the device
// supports discoverable credentials (Face ID / Touch ID do)
app.post("/api/webauthn/login-options", safe(async (req, res) => {
  const options = await generateAuthenticationOptions({
    rpID: RP_ID,
    userVerification: "required"
  });
  await db.saveChallenge(null, options.challenge);
  res.json(options);
}));

// STEP 2 of logging in — verify the signed challenge, issue a normal JWT
app.post("/api/webauthn/login-verify", safe(async (req, res) => {
  const expectedChallenge = await db.getChallenge(null);
  if (!expectedChallenge) return res.status(400).json({ error: "Login expired. Try again." });

  const authenticator = await db.getAuthenticatorByCredentialId(req.body.id);
  if (!authenticator) return res.status(400).json({ error: "This device isn't registered to any account." });

  let verification;
  try {
    verification = await verifyAuthenticationResponse({
      response: req.body,
      expectedChallenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
      credential: {
        id: authenticator.credential_id,
        publicKey: Buffer.from(authenticator.public_key, "base64url"),
        counter: authenticator.counter,
        transports: authenticator.transports
      }
    });
  } catch (e) {
    return res.status(400).json({ error: "Could not verify: " + e.message });
  }
  if (!verification.verified) return res.status(400).json({ error: "Verification failed." });

  await db.updateAuthenticatorCounter(authenticator.credential_id, verification.authenticationInfo.newCounter);
  await db.clearChallenge(null);

  const user = await db.getUserById(authenticator.user_id);
  if (!user) return res.status(404).json({ error: "Account not found." });

  res.json({ token: issueToken(user), username: user.username, is_admin: !!user.is_admin });
}));

app.get("/api/webauthn/devices", authMiddleware, safe(async (req, res) => {
  const rows = await db.getAuthenticatorsByUser(req.userId);
  res.json({ devices: rows.map(r => ({ credential_id: r.credential_id, nickname: r.nickname, created_at: r.created_at })) });
}));

app.delete("/api/webauthn/devices/:credentialId", authMiddleware, safe(async (req, res) => {
  await db.deleteAuthenticator(req.userId, req.params.credentialId);
  res.json({ ok: true });
}));

// ---------------------------------------------------------------------------
// CONTACTS
// ---------------------------------------------------------------------------
app.get("/api/contacts", authMiddleware, safe(async (req, res) => {
  res.json({ contacts: await db.getContacts(req.userId) });
}));

app.post("/api/contacts", authMiddleware, safe(async (req, res) => {
  const { username } = req.body || {};
  const clean = (username || "").trim().toLowerCase();
  if (!clean) return res.status(400).json({ error: "Username required." });
  if (clean === req.username) return res.status(400).json({ error: "You can't add yourself." });
  const target = await db.getUserByUsername(clean);
  if (!target) return res.status(404).json({ error: "No user with that username." });

  await db.addContactPair(req.userId, target.id);
  res.json({ contact: { id: target.id, username: target.username } });
}));

// ---------------------------------------------------------------------------
// MESSAGES (1:1 chat)
// ---------------------------------------------------------------------------
function roomFor(idA, idB) {
  const [a, b] = [idA, idB].sort((x, y) => x - y);
  return `chat:${a}:${b}`;
}

app.get("/api/messages/:username", authMiddleware, safe(async (req, res) => {
  const other = await db.getUserByUsername(req.params.username.trim().toLowerCase());
  if (!other) return res.status(404).json({ error: "User not found." });
  const rows = await db.getMessagesBetween(req.userId, other.id);
  const out = rows.map(r => ({
    id: r.id,
    from: r.sender_id === req.userId ? "You" : other.username,
    kind: r.kind,
    numbers: r.numbers || null,
    image: r.image || null,
    created_at: r.created_at
  }));
  res.json({ messages: out });
}));

app.post("/api/messages", authMiddleware, safe(async (req, res) => {
  const { to, numbers, kind, image } = req.body || {};
  const other = await db.getUserByUsername((to || "").trim().toLowerCase());
  if (!other) return res.status(404).json({ error: "Recipient not found." });
  const msgKind = kind === "image" ? "image" : "text";
  if (msgKind === "text" && (!Array.isArray(numbers) || numbers.length === 0)) {
    return res.status(400).json({ error: "Encoded numbers required." });
  }

  const saved = await db.insertMessage({ sender_id: req.userId, receiver_id: other.id, kind: msgKind, numbers, image });

  const payload = {
    id: saved.id,
    from: req.username,
    kind: msgKind,
    numbers: numbers || null,
    image: image || null,
    created_at: saved.created_at
  };

  io.to(roomFor(req.userId, other.id)).emit("chat:message", { withUserId: req.userId, message: payload });
  res.json({ message: payload });
}));

// ---------------------------------------------------------------------------
// STATUSES
// ---------------------------------------------------------------------------
app.get("/api/statuses", authMiddleware, safe(async (req, res) => {
  res.json({ statuses: await db.getStatuses(100) });
}));

app.post("/api/statuses", authMiddleware, safe(async (req, res) => {
  const { text, image } = req.body || {};
  if (!text || !text.trim()) return res.status(400).json({ error: "Status text required." });
  const saved = await db.insertStatus({ user_id: req.userId, text: text.trim(), image });
  io.emit("status:new", { id: saved.id, username: req.username, text: text.trim(), image: image || null, created_at: saved.created_at });
  res.json({ ok: true });
}));

// ---------------------------------------------------------------------------
// MEETINGS
// ---------------------------------------------------------------------------
app.post("/api/meetings", authMiddleware, safe(async (req, res) => {
  const { pin, max_participants } = req.body || {};
  const clean = (pin || "").trim();
  if (clean.length < 4) return res.status(400).json({ error: "PIN must be at least 4 characters." });
  if (await db.getMeeting(clean)) return res.status(409).json({ error: "That PIN is already in use. Pick another." });
  const cap = max_participants != null && max_participants !== "" ? Number(max_participants) : null;
  if (cap != null && (!Number.isInteger(cap) || cap < 1)) {
    return res.status(400).json({ error: "max_participants must be a whole number of 1 or more." });
  }
  await db.createMeeting(clean, req.userId, req.username, cap);
  res.json({ pin: clean, max_participants: cap });
}));

app.post("/api/meetings/:pin/join", authMiddleware, safe(async (req, res) => {
  const meeting = await db.getMeeting(req.params.pin);
  if (!meeting) return res.status(404).json({ error: "No meeting with that PIN." });
  const me = await db.getUserById(req.userId);
  const isAdmin = !!(me && me.is_admin);
  const allowed = await db.canAccessMeeting(meeting, req.username, isAdmin);
  if (!allowed) {
    return res.status(403).json({
      error: "This meeting has been closed. Request access to get back in.",
      closed: true,
    });
  }

  // Admins joining to review don't count against the host's headcount cap.
  if (!isAdmin) {
    const seat = await db.joinAsParticipant(req.params.pin, req.username);
    if (!seat.ok && seat.reason === "full") {
      return res.status(403).json({
        error: "This meeting is full. Ask the host to raise the limit or reset it.",
        full: true,
      });
    }
  }

  res.json({ pin: meeting.pin });
}));

// Closes a meeting so nobody but an admin can get back in without a
// request being approved. Any authenticated host of THIS meeting can
// close it themselves, or an admin can force-close any meeting.
app.post("/api/meetings/:pin/close", authMiddleware, safe(async (req, res) => {
  const meeting = await db.getMeeting(req.params.pin);
  if (!meeting) return res.status(404).json({ error: "No meeting with that PIN." });
  const me = await db.getUserById(req.userId);
  const isHost = meeting.host_id === req.userId;
  const isAdmin = !!(me && me.is_admin);
  if (!isHost && !isAdmin) return res.status(403).json({ error: "Only the host or an admin can close this meeting." });
  if (meeting.status === "CLOSED") return res.status(400).json({ error: "This meeting is already closed." });

  await db.closeMeeting(req.params.pin, req.userId);
  io.to(`meeting:${req.params.pin}`).emit("meeting:closed", { pin: req.params.pin });
  res.json({ ok: true });
}));

// Host or admin sets/changes the headcount cap. Pass max_participants: null
// to remove the limit entirely.
app.patch("/api/meetings/:pin/capacity", authMiddleware, safe(async (req, res) => {
  const meeting = await db.getMeeting(req.params.pin);
  if (!meeting) return res.status(404).json({ error: "No meeting with that PIN." });
  const me = await db.getUserById(req.userId);
  const isHost = meeting.host_id === req.userId;
  const isAdmin = !!(me && me.is_admin);
  if (!isHost && !isAdmin) return res.status(403).json({ error: "Only the host or an admin can change this meeting's capacity." });

  const { max_participants } = req.body || {};
  const cap = max_participants === null || max_participants === undefined ? null : Number(max_participants);
  if (cap != null && (!Number.isInteger(cap) || cap < 1)) {
    return res.status(400).json({ error: "max_participants must be a whole number of 1 or more, or null to remove the limit." });
  }
  const updated = await db.setMeetingCapacity(req.params.pin, cap);
  res.json({ pin: updated.pin, max_participants: updated.max_participants, participants: updated.participants.length });
}));

// Host/admin need current headcount + limit info; kept lightweight and
// separate from /messages since it's polled by the capacity control UI.
app.get("/api/meetings/:pin/capacity", authMiddleware, safe(async (req, res) => {
  const meeting = await db.getMeeting(req.params.pin);
  if (!meeting) return res.status(404).json({ error: "No meeting with that PIN." });
  res.json({ max_participants: meeting.max_participants, participant_count: meeting.participants.length });
}));

// Clears the current headcount (not who's approved/closed) so new people
// can join again up to the same cap.
app.post("/api/meetings/:pin/reset-capacity", authMiddleware, safe(async (req, res) => {
  const meeting = await db.getMeeting(req.params.pin);
  if (!meeting) return res.status(404).json({ error: "No meeting with that PIN." });
  const me = await db.getUserById(req.userId);
  const isHost = meeting.host_id === req.userId;
  const isAdmin = !!(me && me.is_admin);
  if (!isHost && !isAdmin) return res.status(403).json({ error: "Only the host or an admin can reset this meeting's capacity." });

  await db.resetMeetingCapacity(req.params.pin);
  res.json({ ok: true });
}));

// Submits a request to get back into a closed meeting. Admin reviews these
// in the admin portal — never auto-approved.
app.post("/api/meetings/:pin/request-access", authMiddleware, safe(async (req, res) => {
  const meeting = await db.getMeeting(req.params.pin);
  if (!meeting) return res.status(404).json({ error: "No meeting with that PIN." });
  if (meeting.status !== "CLOSED") return res.status(400).json({ error: "This meeting isn't closed — you can join it directly." });

  const request = await db.createAccessRequest(req.params.pin, req.userId, req.username);
  res.json({ request });
}));

app.get("/api/meetings/:pin/messages", authMiddleware, safe(async (req, res) => {
  const meeting = await db.getMeeting(req.params.pin);
  if (!meeting) return res.status(404).json({ error: "No meeting with that PIN." });
  const me = await db.getUserById(req.userId);
  const allowed = await db.canAccessMeeting(meeting, req.username, !!(me && me.is_admin));
  if (!allowed) return res.status(403).json({ error: "This meeting has been closed.", closed: true });
  res.json({ messages: await db.getMeetingMessages(req.params.pin) });
}));

app.post("/api/meetings/:pin/messages", authMiddleware, safe(async (req, res) => {
  const { numbers } = req.body || {};
  const meeting = await db.getMeeting(req.params.pin);
  if (!meeting) return res.status(404).json({ error: "No meeting with that PIN." });
  const me = await db.getUserById(req.userId);
  const allowed = await db.canAccessMeeting(meeting, req.username, !!(me && me.is_admin));
  if (!allowed) return res.status(403).json({ error: "This meeting has been closed.", closed: true });
  if (!Array.isArray(numbers) || numbers.length === 0) return res.status(400).json({ error: "Encoded numbers required." });

  const saved = await db.insertMeetingMessage({ pin: req.params.pin, sender_username: req.username, numbers });
  io.to(`meeting:${req.params.pin}`).emit("meeting:message", saved);
  res.json({ message: saved });
}));

// ---------------------------------------------------------------------------
// ADMIN — meeting access request queue
// ---------------------------------------------------------------------------
app.get("/api/admin/meeting-requests", authMiddleware, requireAdmin, safe(async (req, res) => {
  res.json({ requests: await db.getPendingAccessRequests() });
}));

app.post("/api/admin/meeting-requests/:id/approve", authMiddleware, requireAdmin, safe(async (req, res) => {
  const request = await db.resolveAccessRequest(Number(req.params.id), true, req.userId);
  if (!request) return res.status(404).json({ error: "Request not found." });
  res.json({ request });
}));

app.post("/api/admin/meeting-requests/:id/deny", authMiddleware, requireAdmin, safe(async (req, res) => {
  const request = await db.resolveAccessRequest(Number(req.params.id), false, req.userId);
  if (!request) return res.status(404).json({ error: "Request not found." });
  res.json({ request });
}));

// Admin bulk action: let everyone who was ever in this meeting back in at
// once, instead of approving each person's request one at a time.
app.post("/api/admin/meetings/:pin/reopen-for-all", authMiddleware, requireAdmin, safe(async (req, res) => {
  const meeting = await db.getMeeting(req.params.pin);
  if (!meeting) return res.status(404).json({ error: "No meeting with that PIN." });
  const updated = await db.reopenMeetingForAllParticipants(req.params.pin);
  res.json({ ok: true, approved_count: updated.approved_usernames.length });
}));

// ---------------------------------------------------------------------------
// SOCKET.IO
// ---------------------------------------------------------------------------
io.use((socket, next) => {
  try {
    const token = socket.handshake.auth?.token;
    const payload = jwt.verify(token, JWT_SECRET);
    socket.userId = payload.uid;
    socket.username = payload.username;
    next();
  } catch (e) {
    next(new Error("unauthorized"));
  }
});

io.on("connection", (socket) => {
  (async () => {
    try {
      const contacts = await db.getContacts(socket.userId);
      contacts.forEach(c => socket.join(roomFor(socket.userId, c.id)));
    } catch (e) {
      console.error("Error joining contact rooms:", e);
    }
  })();

  socket.on("meeting:join", (pin) => {
    if (pin) socket.join(`meeting:${pin}`);
  });

  socket.on("contact:added", (contactId) => {
    socket.join(roomFor(socket.userId, contactId));
  });
});

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

server.listen(PORT, () => {
  console.log(`SWIPE server running on http://localhost:${PORT}`);
});
