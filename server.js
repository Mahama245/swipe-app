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
app.use(express.json({ limit: "20mb" })); // raised from 8mb to fit small video/file attachments as base64
app.use(express.static(path.join(__dirname, "public")));

const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

// Re-checks the account's status from the database on every request, same
// as requireAdmin does for admin rights below — so a suspension or ban
// takes effect immediately, kicking the user out mid-session rather than
// only the next time their token would otherwise expire.
function authMiddleware(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Missing token." });
  let payload;
  try {
    payload = jwt.verify(token, JWT_SECRET);
  } catch (e) {
    return res.status(401).json({ error: "Invalid or expired token." });
  }
  db.getUserById(payload.uid)
    .then(user => {
      if (!user) return res.status(401).json({ error: "Account not found." });
      if (user.status === "banned") return res.status(403).json({ error: "This account has been banned.", banned: true });
      if (user.status === "suspended") return res.status(403).json({ error: "This account is suspended.", suspended: true });
      req.userId = payload.uid;
      req.username = payload.username;
      next();
    })
    .catch(() => res.status(500).json({ error: "Server error checking account status." }));
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
  if (user.status === "banned") return res.status(403).json({ error: "This account has been banned.", banned: true });
  if (user.status === "suspended") return res.status(403).json({ error: "This account is suspended.", suspended: true });
  await db.ensureBootstrapAdmin(user.username);
  const fresh = await db.getUserByUsername(clean); // re-read in case bootstrap just changed is_admin
  res.json({ token: issueToken(fresh), username: fresh.username, is_admin: !!fresh.is_admin, avatar: fresh.avatar || null });
}));

app.get("/api/me", authMiddleware, safe(async (req, res) => {
  const user = await db.getUserById(req.userId);
  const pendingUsernameRequest = await db.getPendingUsernameRequestForUser(req.userId);
  res.json({
    id: req.userId,
    username: req.username,
    is_admin: !!(user && user.is_admin),
    avatar: (user && user.avatar) || null,
    pending_username_request: pendingUsernameRequest ? pendingUsernameRequest.requested_username : null
  });
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
  if (user.status === "banned") return res.status(403).json({ error: "This account has been banned.", banned: true });
  if (user.status === "suspended") return res.status(403).json({ error: "This account is suspended.", suspended: true });

  res.json({ token: issueToken(user), username: user.username, is_admin: !!user.is_admin, avatar: user.avatar || null });
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
// SELF-SERVICE ACCOUNT — avatar, password change, username change request
// ---------------------------------------------------------------------------

// Rough sanity cap on avatar size — the client resizes images before
// uploading, so a legitimate avatar should never get near this.
const MAX_AVATAR_BYTES = 2 * 1024 * 1024;

app.patch("/api/me/avatar", authMiddleware, safe(async (req, res) => {
  const { avatar } = req.body || {};
  if (avatar !== null && (typeof avatar !== "string" || !avatar.startsWith("data:image/"))) {
    return res.status(400).json({ error: "Avatar must be an image, or null to remove it." });
  }
  if (avatar && avatar.length > MAX_AVATAR_BYTES) {
    return res.status(400).json({ error: "That image is too large. Try a smaller photo." });
  }
  const updated = await db.setUserAvatar(req.userId, avatar);
  res.json({ ok: true, avatar: updated.avatar });
}));

app.post("/api/me/change-password", authMiddleware, safe(async (req, res) => {
  const { current_password, new_password } = req.body || {};
  if (!new_password || new_password.length < 4) {
    return res.status(400).json({ error: "New password must be at least 4 characters." });
  }
  const user = await db.getUserById(req.userId);
  if (!user || !bcrypt.compareSync(current_password || "", user.password_hash)) {
    return res.status(401).json({ error: "Current password is incorrect." });
  }
  const hash = bcrypt.hashSync(new_password, 10);
  await db.setUserPasswordHash(req.userId, hash);
  res.json({ ok: true });
}));

app.post("/api/me/username-request", authMiddleware, safe(async (req, res) => {
  const { requested_username } = req.body || {};
  const clean = (requested_username || "").trim().toLowerCase();
  if (clean.length < 3) return res.status(400).json({ error: "Username must be at least 3 characters." });
  if (clean === req.username) return res.status(400).json({ error: "That's already your username." });
  const result = await db.createUsernameChangeRequest(req.userId, req.username, clean);
  if (result.error === "already_pending") return res.status(409).json({ error: "You already have a username change request pending approval." });
  if (result.error === "taken") return res.status(409).json({ error: "That username is already taken." });
  res.json({ request: result.request });
}));

app.get("/api/me/username-request", authMiddleware, safe(async (req, res) => {
  const request = await db.getPendingUsernameRequestForUser(req.userId);
  res.json({ request });
}));


app.get("/api/contacts", authMiddleware, safe(async (req, res) => {
  res.json({ contacts: await db.getContacts(req.userId) });
}));

// Everyone you've exchanged a message with — the actual inbox, independent
// of your curated contacts list. This is what lets a message from someone
// you haven't added yet still show up and be readable.
app.get("/api/conversations", authMiddleware, safe(async (req, res) => {
  res.json({ conversations: await db.getConversations(req.userId) });
}));

// ---------------------------------------------------------------------------
// CONTACT REQUESTS — tap a participant's profile in a meeting to send one;
// they only become contacts once the recipient accepts.
// ---------------------------------------------------------------------------
app.post("/api/contact-requests", authMiddleware, safe(async (req, res) => {
  const { to_id } = req.body || {};
  const toId = Number(to_id);
  if (!Number.isInteger(toId)) return res.status(400).json({ error: "Recipient required." });
  const target = await db.getUserById(toId);
  if (!target) return res.status(404).json({ error: "User not found." });
  const result = await db.createContactRequest(req.userId, toId);
  if (result.error === "self") return res.status(400).json({ error: "You can't send yourself a request." });
  if (result.error === "already_contacts") return res.status(409).json({ error: "You're already contacts." });
  if (result.error === "already_pending") return res.status(409).json({ error: "There's already a pending request between you two." });
  // Live-notify the recipient if they're online right now.
  io.to(`user:${toId}`).emit("contact-request:new", { id: result.request.id, from_id: req.userId, from_username: req.username, created_at: result.request.created_at });
  res.json({ request: result.request });
}));

app.get("/api/contact-requests", authMiddleware, safe(async (req, res) => {
  res.json({ requests: await db.getPendingContactRequestsFor(req.userId) });
}));

app.post("/api/contact-requests/:id/accept", authMiddleware, safe(async (req, res) => {
  const result = await db.resolveContactRequest(Number(req.params.id), req.userId, true);
  if (result.error === "not_found") return res.status(404).json({ error: "Request not found." });
  if (result.error === "not_yours") return res.status(403).json({ error: "That's not your request to resolve." });
  if (result.error === "already_resolved") return res.status(409).json({ error: "That request was already handled." });
  io.to(`user:${result.request.from_id}`).emit("contact-request:accepted", { by_id: req.userId, by_username: req.username });
  res.json({ ok: true });
}));

app.post("/api/contact-requests/:id/decline", authMiddleware, safe(async (req, res) => {
  const result = await db.resolveContactRequest(Number(req.params.id), req.userId, false);
  if (result.error === "not_found") return res.status(404).json({ error: "Request not found." });
  if (result.error === "not_yours") return res.status(403).json({ error: "That's not your request to resolve." });
  if (result.error === "already_resolved") return res.status(409).json({ error: "That request was already handled." });
  res.json({ ok: true });
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
    file_data: r.file_data || null,
    file_name: r.file_name || null,
    file_type: r.file_type || null,
    shared_username: r.shared_username || null,
    created_at: r.created_at
  }));
  res.json({ messages: out });
}));

app.post("/api/messages", authMiddleware, safe(async (req, res) => {
  const { to, numbers, kind, image, file_data, file_name, file_type, shared_username } = req.body || {};
  const other = await db.getUserByUsername((to || "").trim().toLowerCase());
  if (!other) return res.status(404).json({ error: "Recipient not found." });

  const validKinds = ["text", "image", "video", "file", "contact"];
  const msgKind = validKinds.includes(kind) ? kind : "text";
  if (msgKind === "text" && (!Array.isArray(numbers) || numbers.length === 0)) {
    return res.status(400).json({ error: "Encoded numbers required." });
  }
  if (msgKind === "image" && !image) {
    return res.status(400).json({ error: "Image data required." });
  }
  if ((msgKind === "video" || msgKind === "file") && (!file_data || !file_name)) {
    return res.status(400).json({ error: "File data and file name required." });
  }
  // MongoDB rejects any document over 16MB outright — this is the real
  // backstop (the client-side check is just a faster, friendlier version
  // of the same limit).
  if ((msgKind === "video" || msgKind === "file" || msgKind === "image")) {
    const payloadSize = (file_data || image || "").length;
    if (payloadSize > 11 * 1024 * 1024) {
      return res.status(413).json({ error: "That attachment is too large. Try a smaller file (max ~8MB)." });
    }
  }
  let sharedTarget = null;
  if (msgKind === "contact") {
    const cleanShared = (shared_username || "").trim().toLowerCase();
    sharedTarget = await db.getUserByUsername(cleanShared);
    if (!sharedTarget) return res.status(404).json({ error: "That contact doesn't exist." });
  }

  const saved = await db.insertMessage({
    sender_id: req.userId, receiver_id: other.id, kind: msgKind,
    numbers, image, file_data, file_name, file_type,
    shared_username: sharedTarget ? sharedTarget.username : null
  });

  const payload = {
    id: saved.id,
    from: req.username,
    from_id: req.userId,
    kind: msgKind,
    numbers: numbers || null,
    image: image || null,
    file_data: file_data || null,
    file_name: file_name || null,
    file_type: file_type || null,
    shared_username: sharedTarget ? sharedTarget.username : null,
    created_at: saved.created_at
  };

  // Delivered to the recipient's personal room, not a contacts-gated pair
  // room — so a message from someone you haven't added yet still arrives
  // live instead of silently sitting in the database until you add them.
  io.to(`user:${other.id}`).emit("chat:message", { message: payload });
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

// Lets the client render tappable profiles for "who's in this meeting" —
// each participant, minus you, with enough info to send a contact request.
app.get("/api/meetings/:pin/participants", authMiddleware, safe(async (req, res) => {
  const meeting = await db.getMeeting(req.params.pin);
  if (!meeting) return res.status(404).json({ error: "No meeting with that PIN." });
  const me = await db.getUserById(req.userId);
  const allowed = await db.canAccessMeeting(meeting, req.username, !!(me && me.is_admin));
  if (!allowed) return res.status(403).json({ error: "This meeting has been closed.", closed: true });
  const all = await db.getMeetingParticipants(req.params.pin);
  const myContacts = await db.getContacts(req.userId);
  const contactIds = new Set(myContacts.map(c => c.id));
  const participants = all
    .filter(p => p.id !== req.userId)
    .map(p => ({ id: p.id, username: p.username, is_contact: contactIds.has(p.id) }));
  res.json({ participants });
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
  await logAdmin(req, "approve_meeting_request", "meeting_request", request.id, request.requester_username, `PIN ${request.pin}`);
  res.json({ request });
}));

app.post("/api/admin/meeting-requests/:id/deny", authMiddleware, requireAdmin, safe(async (req, res) => {
  const request = await db.resolveAccessRequest(Number(req.params.id), false, req.userId);
  if (!request) return res.status(404).json({ error: "Request not found." });
  await logAdmin(req, "deny_meeting_request", "meeting_request", request.id, request.requester_username, `PIN ${request.pin}`);
  res.json({ request });
}));

// Admin bulk action: let everyone who was ever in this meeting back in at
// once, instead of approving each person's request one at a time.
app.post("/api/admin/meetings/:pin/reopen-for-all", authMiddleware, requireAdmin, safe(async (req, res) => {
  const meeting = await db.getMeeting(req.params.pin);
  if (!meeting) return res.status(404).json({ error: "No meeting with that PIN." });
  const updated = await db.reopenMeetingForAllParticipants(req.params.pin);
  await logAdmin(req, "reopen_meeting_for_all", "meeting", req.params.pin, null, `${updated.approved_usernames.length} participant(s) let back in`);
  res.json({ ok: true, approved_count: updated.approved_usernames.length });
}));

// ---------------------------------------------------------------------------
// ADMIN — user management (suspend / ban / delete / reset password)
// ---------------------------------------------------------------------------

// An admin can never take one of these actions on their own account (so they
// can't accidentally lock themselves out) or on the bootstrap admin account
// (so there's always at least one admin left to fix things).
function guardAdminTarget(req, res, targetUser) {
  if (!targetUser) { res.status(404).json({ error: "User not found." }); return false; }
  if (targetUser.id === req.userId) { res.status(400).json({ error: "You can't do that to your own account." }); return false; }
  if (db.isBootstrapAdminUsername(targetUser.username)) { res.status(400).json({ error: "The bootstrap admin account is protected." }); return false; }
  return true;
}

// Every admin action logs itself here — who did it, to whom, and when —
// so nothing an admin does (ban, delete, password reset...) happens off
// the record. Logging failure never blocks the underlying action.
function logAdmin(req, action, target_type, target_id, target_username, details) {
  return db.logAdminAction({
    actor_id: req.userId,
    actor_username: req.username,
    action, target_type, target_id, target_username, details
  }).catch(err => console.error("Failed to write admin audit log entry:", err));
}

app.get("/api/admin/users", authMiddleware, requireAdmin, safe(async (req, res) => {
  res.json({ users: await db.listUsers() });
}));

app.post("/api/admin/users/:id/suspend", authMiddleware, requireAdmin, safe(async (req, res) => {
  const target = await db.getUserById(Number(req.params.id));
  if (!guardAdminTarget(req, res, target)) return;
  const updated = await db.setUserStatus(target.id, "suspended");
  await logAdmin(req, "suspend_user", "user", target.id, target.username);
  res.json({ ok: true, user: { id: updated.id, username: updated.username, status: updated.status } });
}));

app.post("/api/admin/users/:id/ban", authMiddleware, requireAdmin, safe(async (req, res) => {
  const target = await db.getUserById(Number(req.params.id));
  if (!guardAdminTarget(req, res, target)) return;
  const updated = await db.setUserStatus(target.id, "banned");
  await logAdmin(req, "ban_user", "user", target.id, target.username);
  res.json({ ok: true, user: { id: updated.id, username: updated.username, status: updated.status } });
}));

// Lifts either a suspension or a ban, restoring normal access.
app.post("/api/admin/users/:id/reactivate", authMiddleware, requireAdmin, safe(async (req, res) => {
  const target = await db.getUserById(Number(req.params.id));
  if (!target) return res.status(404).json({ error: "User not found." });
  const updated = await db.setUserStatus(target.id, "active");
  await logAdmin(req, "reactivate_user", "user", target.id, target.username);
  res.json({ ok: true, user: { id: updated.id, username: updated.username, status: updated.status } });
}));

app.delete("/api/admin/users/:id", authMiddleware, requireAdmin, safe(async (req, res) => {
  const target = await db.getUserById(Number(req.params.id));
  if (!guardAdminTarget(req, res, target)) return;
  await db.deleteUserAccount(target.id);
  await logAdmin(req, "delete_user", "user", target.id, target.username);
  res.json({ ok: true });
}));

app.post("/api/admin/users/:id/reset-password", authMiddleware, requireAdmin, safe(async (req, res) => {
  const target = await db.getUserById(Number(req.params.id));
  if (!target) return res.status(404).json({ error: "User not found." });
  const { new_password } = req.body || {};
  if (!new_password || new_password.length < 4) {
    return res.status(400).json({ error: "New password must be at least 4 characters." });
  }
  const hash = bcrypt.hashSync(new_password, 10);
  await db.setUserPasswordHash(target.id, hash);
  // Never log the password itself — only that a reset happened.
  await logAdmin(req, "reset_password", "user", target.id, target.username);
  res.json({ ok: true });
}));

// ---------------------------------------------------------------------------
// ADMIN — audit log
// ---------------------------------------------------------------------------
app.get("/api/admin/audit-log", authMiddleware, requireAdmin, safe(async (req, res) => {
  const limit = Math.min(Number(req.query.limit) || 200, 500);
  res.json({ entries: await db.getAdminAuditLog(limit) });
}));

// ---------------------------------------------------------------------------
// ADMIN — username change requests
// ---------------------------------------------------------------------------
app.get("/api/admin/username-requests", authMiddleware, requireAdmin, safe(async (req, res) => {
  res.json({ requests: await db.getPendingUsernameRequests() });
}));

app.post("/api/admin/username-requests/:id/approve", authMiddleware, requireAdmin, safe(async (req, res) => {
  const result = await db.resolveUsernameRequest(Number(req.params.id), true, req.userId);
  if (!result) return res.status(404).json({ error: "Request not found." });
  if (result.error === "taken") return res.status(409).json({ error: "That username was taken in the meantime. Request denied." });
  await logAdmin(req, "approve_username_change", "user", result.request.user_id, result.request.current_username,
    `${result.request.current_username} -> ${result.request.requested_username}`);
  res.json({ request: result.request });
}));

app.post("/api/admin/username-requests/:id/deny", authMiddleware, requireAdmin, safe(async (req, res) => {
  const result = await db.resolveUsernameRequest(Number(req.params.id), false, req.userId);
  if (!result) return res.status(404).json({ error: "Request not found." });
  await logAdmin(req, "deny_username_change", "user", result.request.user_id, result.request.current_username,
    `requested ${result.request.requested_username}`);
  res.json({ request: result.request });
}));

// ---------------------------------------------------------------------------
// SOCKET.IO
// ---------------------------------------------------------------------------
io.use((socket, next) => {
  let payload;
  try {
    const token = socket.handshake.auth?.token;
    payload = jwt.verify(token, JWT_SECRET);
  } catch (e) {
    return next(new Error("unauthorized"));
  }
  db.getUserById(payload.uid)
    .then(user => {
      if (!user || user.status === "banned" || user.status === "suspended") {
        return next(new Error("unauthorized"));
      }
      socket.userId = payload.uid;
      socket.username = payload.username;
      next();
    })
    .catch(() => next(new Error("unauthorized")));
});

io.on("connection", (socket) => {
  // A personal room per user, not per contact-pair — this is what makes
  // messages from a non-contact arrive live instead of only after the
  // recipient happens to add that person back.
  socket.join(`user:${socket.userId}`);

  socket.on("meeting:join", (pin) => {
    if (pin) socket.join(`meeting:${pin}`);
  });
});

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

server.listen(PORT, () => {
  console.log(`SWIPE server running on http://localhost:${PORT}`);
});
