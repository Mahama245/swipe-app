require("dotenv").config();
const express = require("express");
const http = require("http");
const path = require("path");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Server } = require("socket.io");
const db = require("./db");

const JWT_SECRET = process.env.JWT_SECRET || "change-this-secret-in-production";
const PORT = process.env.PORT || 3000;

// ---------------------------------------------------------------------------
// APP + SOCKET SETUP
// ---------------------------------------------------------------------------
const app = express();
app.use(cors());
app.use(express.json({ limit: "8mb" })); // allow small base64 images
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

// ---------------------------------------------------------------------------
// AUTH ROUTES
// ---------------------------------------------------------------------------
app.post("/api/register", (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password || username.trim().length < 3 || password.length < 4) {
    return res.status(400).json({ error: "Username (3+ chars) and password (4+ chars) required." });
  }
  const clean = username.trim().toLowerCase();
  if (db.getUserByUsername(clean)) {
    return res.status(409).json({ error: "That username is already taken." });
  }
  const hash = bcrypt.hashSync(password, 10);
  const user = db.createUser(clean, hash);
  const token = jwt.sign({ uid: user.id, username: clean }, JWT_SECRET, { expiresIn: "30d" });
  res.json({ token, username: clean });
});

app.post("/api/login", (req, res) => {
  const { username, password } = req.body || {};
  const clean = (username || "").trim().toLowerCase();
  const user = db.getUserByUsername(clean);
  if (!user || !bcrypt.compareSync(password || "", user.password_hash)) {
    return res.status(401).json({ error: "Invalid username or password." });
  }
  const token = jwt.sign({ uid: user.id, username: user.username }, JWT_SECRET, { expiresIn: "30d" });
  res.json({ token, username: user.username });
});

app.get("/api/me", authMiddleware, (req, res) => {
  res.json({ id: req.userId, username: req.username });
});

// ---------------------------------------------------------------------------
// CONTACTS
// ---------------------------------------------------------------------------
app.get("/api/contacts", authMiddleware, (req, res) => {
  res.json({ contacts: db.getContacts(req.userId) });
});

app.post("/api/contacts", authMiddleware, (req, res) => {
  const { username } = req.body || {};
  const clean = (username || "").trim().toLowerCase();
  if (!clean) return res.status(400).json({ error: "Username required." });
  if (clean === req.username) return res.status(400).json({ error: "You can't add yourself." });
  const target = db.getUserByUsername(clean);
  if (!target) return res.status(404).json({ error: "No user with that username." });

  db.addContactPair(req.userId, target.id);
  res.json({ contact: { id: target.id, username: target.username } });
});

// ---------------------------------------------------------------------------
// MESSAGES (1:1 chat) — server only ever stores/relays number arrays,
// never the plaintext or the formula. Friends agree on the formula out of band.
// ---------------------------------------------------------------------------
function roomFor(idA, idB) {
  const [a, b] = [idA, idB].sort((x, y) => x - y);
  return `chat:${a}:${b}`;
}

app.get("/api/messages/:username", authMiddleware, (req, res) => {
  const other = db.getUserByUsername(req.params.username.trim().toLowerCase());
  if (!other) return res.status(404).json({ error: "User not found." });
  const rows = db.getMessagesBetween(req.userId, other.id);
  const out = rows.map(r => ({
    id: r.id,
    from: r.sender_id === req.userId ? "You" : other.username,
    kind: r.kind,
    numbers: r.numbers || null,
    image: r.image || null,
    created_at: r.created_at
  }));
  res.json({ messages: out });
});

app.post("/api/messages", authMiddleware, (req, res) => {
  const { to, numbers, kind, image } = req.body || {};
  const other = db.getUserByUsername((to || "").trim().toLowerCase());
  if (!other) return res.status(404).json({ error: "Recipient not found." });
  const msgKind = kind === "image" ? "image" : "text";
  if (msgKind === "text" && (!Array.isArray(numbers) || numbers.length === 0)) {
    return res.status(400).json({ error: "Encoded numbers required." });
  }

  const saved = db.insertMessage({ sender_id: req.userId, receiver_id: other.id, kind: msgKind, numbers, image });

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
});

// ---------------------------------------------------------------------------
// STATUSES
// ---------------------------------------------------------------------------
app.get("/api/statuses", authMiddleware, (req, res) => {
  res.json({ statuses: db.getStatuses(100) });
});

app.post("/api/statuses", authMiddleware, (req, res) => {
  const { text, image } = req.body || {};
  if (!text || !text.trim()) return res.status(400).json({ error: "Status text required." });
  const saved = db.insertStatus({ user_id: req.userId, text: text.trim(), image });
  io.emit("status:new", { id: saved.id, username: req.username, text: text.trim(), image: image || null, created_at: saved.created_at });
  res.json({ ok: true });
});

// ---------------------------------------------------------------------------
// MEETINGS (PIN-based rooms). Formula is shared out-of-band by participants;
// the server just relays encoded numbers between everyone in the room.
// ---------------------------------------------------------------------------
app.post("/api/meetings", authMiddleware, (req, res) => {
  const { pin } = req.body || {};
  const clean = (pin || "").trim();
  if (clean.length < 4) return res.status(400).json({ error: "PIN must be at least 4 characters." });
  if (db.getMeeting(clean)) return res.status(409).json({ error: "That PIN is already in use. Pick another." });
  db.createMeeting(clean, req.userId);
  res.json({ pin: clean });
});

app.post("/api/meetings/:pin/join", authMiddleware, (req, res) => {
  const meeting = db.getMeeting(req.params.pin);
  if (!meeting) return res.status(404).json({ error: "No meeting with that PIN." });
  res.json({ pin: meeting.pin });
});

app.get("/api/meetings/:pin/messages", authMiddleware, (req, res) => {
  const meeting = db.getMeeting(req.params.pin);
  if (!meeting) return res.status(404).json({ error: "No meeting with that PIN." });
  res.json({ messages: db.getMeetingMessages(req.params.pin) });
});

app.post("/api/meetings/:pin/messages", authMiddleware, (req, res) => {
  const { numbers } = req.body || {};
  const meeting = db.getMeeting(req.params.pin);
  if (!meeting) return res.status(404).json({ error: "No meeting with that PIN." });
  if (!Array.isArray(numbers) || numbers.length === 0) return res.status(400).json({ error: "Encoded numbers required." });

  const saved = db.insertMeetingMessage({ pin: req.params.pin, sender_username: req.username, numbers });
  io.to(`meeting:${req.params.pin}`).emit("meeting:message", saved);
  res.json({ message: saved });
});

// ---------------------------------------------------------------------------
// SOCKET.IO — auth via handshake token, join relevant rooms
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
  // join a room with every contact so messages route both ways
  const contacts = db.getContacts(socket.userId);
  contacts.forEach(c => socket.join(roomFor(socket.userId, c.id)));

  socket.on("meeting:join", (pin) => {
    if (pin) socket.join(`meeting:${pin}`);
  });

  socket.on("contact:added", (contactId) => {
    socket.join(roomFor(socket.userId, contactId));
  });
});

// fallback to index.html for the SPA
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

server.listen(PORT, () => {
  console.log(`SWIPE server running on http://localhost:${PORT}`);
});
