require("dotenv").config();
const express = require("express");
const http = require("http");
const path = require("path");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Server } = require("socket.io");
const db = require("./db");

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  console.error("FATAL: JWT_SECRET is not set. Set it in Render's environment variables before starting the server.");
  process.exit(1);
}

const PORT = process.env.PORT || 3000;
const ALLOWED_ORIGIN = "https://swipe-app-wzqp.onrender.com";

const app = express();

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "https://cdnjs.cloudflare.com", "https://cdn.socket.io"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'", ALLOWED_ORIGIN, ALLOWED_ORIGIN.replace("https://", "wss://")]
    }
  }
}));

app.use(cors({ origin: ALLOWED_ORIGIN }));

app.use((req, res, next) => {
  res.setHeader(
    "Permissions-Policy",
    "geolocation=(), microphone=(), camera=(), payment=(), usb=(), fullscreen=(self)"
  );
  next();
});

app.use(express.json({ limit: "8mb" }));
app.use(express.static(path.join(__dirname, "public")));

const server = http.createServer(app);
const io = new Server(server, { cors: { origin: ALLOWED_ORIGIN } });

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many attempts from this device. Please wait a while and try again." }
});

const writeLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "You're sending requests too quickly. Please slow down." }
});

const MAX_ATTEMPTS = 5;
const LOCKOUT_MS = 15 * 60 * 1000;
const failedLogins = new Map();

function getLoginState(username) {
  return failedLogins.get(username) || { attempts: 0, lockedUntil: 0 };
}

function recordFailedLogin(username) {
  const state = getLoginState(username);
  state.attempts += 1;
  let justLocked = false;
  if (state.attempts >= MAX_ATTEMPTS) {
    state.lockedUntil = Date.now() + LOCKOUT_MS;
    state.attempts = 0;
    justLocked = true;
  }
  failedLogins.set(username, state);
  return justLocked;
}

function clearFailedLogins(username) {
  failedLogins.delete(username);
}

async function authMiddleware(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Missing token." });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const user = await db.getUserById(payload.uid);
    if (!user) return res.status(401).json({ error: "Account no longer exists." });
    if (user.banned_until && new Date(user.banned_until) > new Date()) {
      return res.status(403).json({ error: "This account has been suspended." });
    }
    req.userId = user.id;
    req.username = user.username;
    req.isAdmin = !!user.is_admin;
    next();
  } catch (e) {
    return res.status(401).json({ error: "Invalid or expired token." });
  }
}

function adminMiddleware(req, res, next) {
  if (!req.isAdmin) return res.status(403).json({ error: "Admins only." });
  next();
}

function safe(handler) {
  return (req, res) => {
    Promise.resolve(handler(req, res)).catch(err => {
      console.error(err);
      res.status(500).json({ error: "Server error." });
    });
  };
}

app.post("/api/login", authLimiter, safe(async (req, res) => {
  const { username, password } = req.body || {};
  const clean = (username || "").trim().toLowerCase();

  const state = getLoginState(clean);
  if (state.lockedUntil && Date.now() < state.lockedUntil) {
    const secondsLeft = Math.ceil((state.lockedUntil - Date.now()) / 1000);
    const minutesLeft = Math.ceil(secondsLeft / 60);
    return res.status(429).json({ error: `Too many failed attempts. Try again in ${minutesLeft} minute(s).` });
  }

  const user = await db.getUserByUsername(clean);
  if (!user || !bcrypt.compareSync(password || "", user.password_hash)) {
    const justLocked = recordFailedLogin(clean);
    if (justLocked) {
      return res.status(429).json({ error: `Too many failed attempts. Try again in ${Math.ceil(LOCKOUT_MS / 60000)} minute(s).` });
    }
    return res.status(401).json({ error: "Invalid username or password." });
  }

  if (user.banned_until && new Date(user.banned_until) > new Date()) {
    return res.status(403).json({ error: "This account has been suspended." });
  }

  clearFailedLogins(clean);
  await db.updateLastLogin(user.id);
  const token = jwt.sign({ uid: user.id, username: user.username }, JWT_SECRET, { expiresIn: "30d" });
  res.json({ token, username: user.username, isAdmin: !!user.is_admin });
}));

app.get("/api/me", authMiddleware, safe(async (req, res) => {
  res.json({ username: req.username, isAdmin: req.isAdmin });
}));

app.post("/api/register", authLimiter, safe(async (req, res) => {
  const { username, password, securityQuestion, securityAnswer } = req.body || {};
  const clean = (username || "").trim().toLowerCase();

  if (!/^[a-z0-9_]{3,20}$/.test(clean)) {
    return res.status(400).json({ error: "Username must be 3-20 characters: letters, numbers, underscores only." });
  }
  if (!password || password.length < 6) {
    return res.status(400).json({ error: "Password must be at least 6 characters." });
  }
  if (!securityQuestion || !securityQuestion.trim()) {
    return res.status(400).json({ error: "Security question is required." });
  }
  if (!securityAnswer || !securityAnswer.trim()) {
    return res.status(400).json({ error: "Security answer is required." });
  }

  const existing = await db.getUserByUsername(clean);
  if (existing) {
    return res.status(409).json({ error: "That username is already taken." });
  }

  const password_hash = bcrypt.hashSync(password, 10);
  const security_answer_hash = bcrypt.hashSync(securityAnswer.trim().toLowerCase(), 10);
  const user = await db.createUser(clean, password_hash, securityQuestion.trim(), security_answer_hash);

  const token = jwt.sign({ uid: user.id, username: user.username }, JWT_SECRET, { expiresIn: "30d" });
  res.json({ token, username: user.username });
}));

app.get("/api/forgot-password/:username", authLimiter, safe(async (req, res) => {
  const clean = (req.params.username || "").trim().toLowerCase();
  const user = await db.getUserByUsername(clean);
  if (!user) return res.status(404).json({ error: "No account with that username." });
  res.json({ question: user.security_question });
}));

app.post("/api/forgot-password/reset", authLimiter, safe(async (req, res) => {
  const { username, answer, newPassword } = req.body || {};
  const clean = (username || "").trim().toLowerCase();
  const user = await db.getUserByUsername(clean);
  if (!user) return res.status(404).json({ error: "No account with that username." });

  const cleanAnswer = (answer || "").trim().toLowerCase();
  if (!bcrypt.compareSync(cleanAnswer, user.security_answer_hash)) {
    return res.status(401).json({ error: "That answer doesn't match." });
  }
  if (!newPassword || newPassword.length < 6) {
    return res.status(400).json({ error: "New password must be at least 6 characters." });
  }

  const password_hash = bcrypt.hashSync(newPassword, 10);
  await db.updatePassword(user.id, password_hash);
  clearFailedLogins(clean);
  res.json({ ok: true });
}));

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

app.post("/api/messages", authMiddleware, writeLimiter, safe(async (req, res) => {
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

app.get("/api/statuses", authMiddleware, safe(async (req, res) => {
  res.json({ statuses: await db.getStatuses(100) });
}));

app.post("/api/statuses", authMiddleware, writeLimiter, safe(async (req, res) => {
  const { text, image } = req.body || {};
  if (!text || !text.trim()) return res.status(400).json({ error: "Status text required." });
  const saved = await db.insertStatus({ user_id: req.userId, text: text.trim(), image });
  io.emit("status:new", { id: saved.id, username: req.username, text: text.trim(), image: image || null, created_at: saved.created_at });
  res.json({ ok: true });
}));

app.post("/api/meetings", authMiddleware, safe(async (req, res) => {
  const { pin } = req.body || {};
  const clean = (pin || "").trim();
  if (clean.length < 4) return res.status(400).json({ error: "PIN must be at least 4 characters." });
  if (await db.getMeeting(clean)) return res.status(409).json({ error: "That PIN is already in use. Pick another." });
  await db.createMeeting(clean, req.userId);
  res.json({ pin: clean });
}));

app.post("/api/meetings/:pin/join", authMiddleware, authLimiter, safe(async (req, res) => {
  const meeting = await db.getMeeting(req.params.pin);
  if (!meeting) return res.status(404).json({ error: "No meeting with that PIN." });
  res.json({ pin: meeting.pin });
}));

app.get("/api/meetings/:pin/messages", authMiddleware, safe(async (req, res) => {
  const meeting = await db.getMeeting(req.params.pin);
  if (!meeting) return res.status(404).json({ error: "No meeting with that PIN." });
  res.json({ messages: await db.getMeetingMessages(req.params.pin) });
}));

app.post("/api/meetings/:pin/messages", authMiddleware, writeLimiter, safe(async (req, res) => {
  const { numbers } = req.body || {};
  const meeting = await db.getMeeting(req.params.pin);
  if (!meeting) return res.status(404).json({ error: "No meeting with that PIN." });
  if (!Array.isArray(numbers) || numbers.length === 0) return res.status(400).json({ error: "Encoded numbers required." });

  const saved = await db.insertMeetingMessage({ pin: req.params.pin, sender_username: req.username, numbers });
  io.to(`meeting:${req.params.pin}`).emit("meeting:message", saved);
  res.json({ message: saved });
}));

// ---------------------------------------------------------------------
// ADMIN
// ---------------------------------------------------------------------

app.get("/api/admin/users", authMiddleware, adminMiddleware, safe(async (req, res) => {
  res.json({ users: await db.getAllUsersForAdmin() });
}));

app.post("/api/admin/users/:id/ban", authMiddleware, adminMiddleware, safe(async (req, res) => {
  const targetId = Number(req.params.id);
  if (targetId === req.userId) return res.status(400).json({ error: "You can't ban yourself." });

  const target = await db.getUserById(targetId);
  if (!target) return res.status(404).json({ error: "User not found." });

  const hours = Number(req.body?.hours);
  if (!hours || hours <= 0) return res.status(400).json({ error: "Provide a positive number of hours." });

  const bannedUntil = new Date(Date.now() + hours * 60 * 60 * 1000).toISOString();
  await db.banUserUntil(targetId, bannedUntil);
  res.json({ ok: true, banned_until: bannedUntil });
}));

app.post("/api/admin/users/:id/unban", authMiddleware, adminMiddleware, safe(async (req, res) => {
  const targetId = Number(req.params.id);
  const target = await db.getUserById(targetId);
  if (!target) return res.status(404).json({ error: "User not found." });
  await db.unbanUser(targetId);
  res.json({ ok: true });
}));

app.post("/api/admin/users/:id/password", authMiddleware, adminMiddleware, safe(async (req, res) => {
  const targetId = Number(req.params.id);
  const target = await db.getUserById(targetId);
  if (!target) return res.status(404).json({ error: "User not found." });

  const { newPassword } = req.body || {};
  if (!newPassword || newPassword.length < 6) {
    return res.status(400).json({ error: "New password must be at least 6 characters." });
  }
  const password_hash = bcrypt.hashSync(newPassword, 10);
  await db.adminSetPassword(targetId, password_hash);
  res.json({ ok: true });
}));

app.delete("/api/admin/users/:id", authMiddleware, adminMiddleware, safe(async (req, res) => {
  const targetId = Number(req.params.id);
  if (targetId === req.userId) return res.status(400).json({ error: "You can't delete your own account." });

  const target = await db.getUserById(targetId);
  if (!target) return res.status(404).json({ error: "User not found." });

  await db.deleteUserCascade(targetId);
  res.json({ ok: true });
}));

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

io.on("connection", async (socket) => {
  try {
    const contacts = await db.getContacts(socket.userId);
    contacts.forEach(c => socket.join(roomFor(socket.userId, c.id)));
  } catch (e) {
    console.error("Error joining contact rooms:", e);
  }

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

db.connect()
  .then(() => {
    server.listen(PORT, () => {
      console.log(`SWIPE server running on http://localhost:${PORT}`);
    });
  })
  .catch(err => {
    console.error("Failed to connect to MongoDB. Server not started.");
    console.error(err);
    process.exit(1);
  });
