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

// ---------------------------------------------------------------------------
// BRUTE-FORCE LOCKOUT — tracks failed login attempts per username in memory.
// After MAX_ATTEMPTS failures, that username is locked for LOCKOUT_MS.
// (Resets if the server restarts — acceptable tradeoff for simplicity.)
// ---------------------------------------------------------------------------
const MAX_ATTEMPTS = 5;
const LOCKOUT_MS = 15 * 60 * 1000; // 15 minutes
const failedLogins = new Map(); // username -> { attempts, lockedUntil }

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

// Wraps an async route handler so thrown errors / rejected promises don't
// crash the server — they get turned into a 500 response instead.
function safe(handler) {
  return (req, res) => {
    Promise.resolve(handler(req, res)).catch(err => {
      console.error(err);
      res.status(500).json({ error: "Server error." });
    });
  };
}

// ---------------------------------------------------------------------------
// AUTH ROUTES
// ---------------------------------------------------------------------------
app.post("/api/login", safe(async (req, res) => {
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

  clearFailedLogins(clean);
  const token = jwt.sign({ uid: user.id, username: user.username }, JWT_SECRET, { expiresIn: "30d" });
  res.json({ token, username: user.username });
}));

app.post("/api/register", safe(async (req, res) => {
  const { username, password } = req.body || {};
  const clean = (username || "").trim().toLowerCase();

  if (!/^[a-z0-9_]{3,20}$/.test(clean)) {
    return res.status(400).json({ error: "Username must be 3-20 characters: letters, numbers, underscores only." });
  }
  if (!password || password.length < 6) {
    return res.status(400).json({ error: "Password must be at least 6 characters." });
  }

  const existing = await db.getUserByUsername(clean);
  if (existing) {
    return res.status(409).json({ error: "That username is already taken." });
  }

  const password_hash = bcrypt.hashSync(password, 10);
  const user = await db.createUser(clean, password_hash);

  const token = jwt.sign({ uid: user.id, username: user.username }, JWT_SECRET, { expiresIn: "30d" });
  res.json({ token, username: user.username });
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
// MESSAGES (1:1 chat) — server only ever stores/relays number arrays,
// never the plaintext or the formula. Friends agree on the formula out of band.
// ---------------------------------------------------------------------------
function roomFor(idA, idB) {
  const [a, b]
