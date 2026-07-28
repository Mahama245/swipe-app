// db.js — a tiny JSON-file-backed database. No native compilation required
// (this is what avoids the Visual Studio / node-gyp build errors that
// better-sqlite3 needs on Windows). Fine for a friends-group-scale app.

const fs = require("fs");
const path = require("path");

const DB_PATH = path.join(__dirname, "data", "db.json");

function emptyDb() {
  return {
    counters: { user: 0, message: 0, status: 0, meeting_message: 0 },
    users: [],           // { id, username, password_hash, created_at }
    contacts: [],        // { user_id, contact_id, created_at }
    messages: [],        // { id, sender_id, receiver_id, kind, numbers, image, created_at }
    statuses: [],        // { id, user_id, text, image, created_at }
    meetings: [],        // { pin, host_id, created_at }
    meeting_messages: [] // { id, pin, sender_username, numbers, created_at }
  };
}

let state = null;

function load() {
  if (state) return state;
  if (fs.existsSync(DB_PATH)) {
    try {
      state = JSON.parse(fs.readFileSync(DB_PATH, "utf8"));
    } catch (e) {
      state = emptyDb();
    }
  } else {
    state = emptyDb();
  }
  return state;
}

function save() {
  fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
  fs.writeFileSync(DB_PATH, JSON.stringify(state, null, 2));
}

function nextId(kind) {
  state.counters[kind] = (state.counters[kind] || 0) + 1;
  return state.counters[kind];
}

// ---------------------------------------------------------------------------
// USERS
// ---------------------------------------------------------------------------
function getUserByUsername(username) {
  load();
  return state.users.find(u => u.username === username) || null;
}
function getUserById(id) {
  load();
  return state.users.find(u => u.id === id) || null;
}
function createUser(username, password_hash) {
  load();
  const user = { id: nextId("user"), username, password_hash, created_at: new Date().toISOString() };
  state.users.push(user);
  save();
  return user;
}

// ---------------------------------------------------------------------------
// CONTACTS (mutual)
// ---------------------------------------------------------------------------
function addContactPair(userId, contactId) {
  load();
  const exists1 = state.contacts.some(c => c.user_id === userId && c.contact_id === contactId);
  if (!exists1) state.contacts.push({ user_id: userId, contact_id: contactId, created_at: new Date().toISOString() });
  const exists2 = state.contacts.some(c => c.user_id === contactId && c.contact_id === userId);
  if (!exists2) state.contacts.push({ user_id: contactId, contact_id: userId, created_at: new Date().toISOString() });
  save();
}
function getContacts(userId) {
  load();
  return state.contacts
    .filter(c => c.user_id === userId)
    .map(c => getUserById(c.contact_id))
    .filter(Boolean)
    .map(u => ({ id: u.id, username: u.username }))
    .sort((a, b) => a.username.localeCompare(b.username));
}

// ---------------------------------------------------------------------------
// MESSAGES (1:1)
// ---------------------------------------------------------------------------
function getMessagesBetween(idA, idB) {
  load();
  return state.messages
    .filter(m => (m.sender_id === idA && m.receiver_id === idB) || (m.sender_id === idB && m.receiver_id === idA))
    .sort((a, b) => a.id - b.id);
}
function insertMessage({ sender_id, receiver_id, kind, numbers, image }) {
  load();
  const msg = {
    id: nextId("message"),
    sender_id, receiver_id, kind,
    numbers: numbers || null,
    image: image || null,
    created_at: new Date().toISOString()
  };
  state.messages.push(msg);
  save();
  return msg;
}

// ---------------------------------------------------------------------------
// STATUSES
// ---------------------------------------------------------------------------
function getStatuses(limit) {
  load();
  return state.statuses
    .slice()
    .sort((a, b) => b.id - a.id)
    .slice(0, limit || 100)
    .map(s => ({ ...s, username: getUserById(s.user_id)?.username || "unknown" }));
}
function insertStatus({ user_id, text, image }) {
  load();
  const status = { id: nextId("status"), user_id, text, image: image || null, created_at: new Date().toISOString() };
  state.statuses.push(status);
  save();
  return status;
}

// ---------------------------------------------------------------------------
// MEETINGS
// ---------------------------------------------------------------------------
function getMeeting(pin) {
  load();
  return state.meetings.find(m => m.pin === pin) || null;
}
function createMeeting(pin, host_id) {
  load();
  const meeting = { pin, host_id, created_at: new Date().toISOString() };
  state.meetings.push(meeting);
  save();
  return meeting;
}
function getMeetingMessages(pin) {
  load();
  return state.meeting_messages.filter(m => m.pin === pin).sort((a, b) => a.id - b.id);
}
function insertMeetingMessage({ pin, sender_username, numbers }) {
  load();
  const msg = { id: nextId("meeting_message"), pin, sender_username, numbers, created_at: new Date().toISOString() };
  state.meeting_messages.push(msg);
  save();
  return msg;
}

module.exports = {
  getUserByUsername, getUserById, createUser,
  addContactPair, getContacts,
  getMessagesBetween, insertMessage,
  getStatuses, insertStatus,
  getMeeting, createMeeting, getMeetingMessages, insertMeetingMessage
};
