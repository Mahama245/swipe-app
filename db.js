// db.js — MongoDB Atlas backed database layer for SWIPE.
// Replaces the old JSON-file version. All functions are now ASYNC
// (they return Promises), because talking to MongoDB is asynchronous.
// server.js has been updated to `await` every call into this file.

const { MongoClient } = require("mongodb");

const MONGODB_URI = process.env.MONGODB_URI;
if (!MONGODB_URI) {
  throw new Error("MONGODB_URI is not set. Add it to your .env file (local) or Render environment variables (production).");
}

const client = new MongoClient(MONGODB_URI);

let db = null;
let usersCol, contactsCol, messagesCol, statusesCol, meetingsCol, meetingMessagesCol, countersCol;

// ---------------------------------------------------------------------------
// CONNECTION
// ---------------------------------------------------------------------------
async function connect() {
  if (db) return db; // already connected, reuse
  await client.connect();
  db = client.db("swipe"); // database name inside your Atlas cluster

  usersCol = db.collection("users");
  contactsCol = db.collection("contacts");
  messagesCol = db.collection("messages");
  statusesCol = db.collection("statuses");
  meetingsCol = db.collection("meetings");
  meetingMessagesCol = db.collection("meeting_messages");
  countersCol = db.collection("counters");

  // Indexes — keep lookups fast and enforce uniqueness where it matters.
  await usersCol.createIndex({ username: 1 }, { unique: true });
  await contactsCol.createIndex({ user_id: 1, contact_id: 1 }, { unique: true });
  await messagesCol.createIndex({ sender_id: 1, receiver_id: 1 });
  await meetingsCol.createIndex({ pin: 1 }, { unique: true });
  await meetingMessagesCol.createIndex({ pin: 1 });

  console.log("Connected to MongoDB Atlas (database: swipe)");
  return db;
}

// Mimics the old auto-incrementing numeric IDs (1, 2, 3...) so the rest of
// the app — which sorts/compares ids as numbers — doesn't need to change.
async function nextId(kind) {
  const result = await countersCol.findOneAndUpdate(
    { _id: kind },
    { $inc: { seq: 1 } },
    { upsert: true, returnDocument: "after" }
  );
  return result.value.seq;
}

// ---------------------------------------------------------------------------
// USERS
// ---------------------------------------------------------------------------
async function getUserByUsername(username) {
  return usersCol.findOne({ username });
}
async function getUserById(id) {
  return usersCol.findOne({ id });
}
async function createUser(username, password_hash) {
  const user = { id: await nextId("user"), username, password_hash, created_at: new Date().toISOString() };
  await usersCol.insertOne(user);
  return user;
}

// ---------------------------------------------------------------------------
// CONTACTS (mutual)
// ---------------------------------------------------------------------------
async function addContactPair(userId, contactId) {
  const now = new Date().toISOString();
  await contactsCol.updateOne(
    { user_id: userId, contact_id: contactId },
    { $setOnInsert: { user_id: userId, contact_id: contactId, created_at: now } },
    { upsert: true }
  );
  await contactsCol.updateOne(
    { user_id: contactId, contact_id: userId },
    { $setOnInsert: { user_id: contactId, contact_id: userId, created_at: now } },
    { upsert: true }
  );
}
async function getContacts(userId) {
  const rows = await contactsCol.find({ user_id: userId }).toArray();
  const users = await Promise.all(rows.map(c => getUserById(c.contact_id)));
  return users
    .filter(Boolean)
    .map(u => ({ id: u.id, username: u.username }))
    .sort((a, b) => a.username.localeCompare(b.username));
}

// ---------------------------------------------------------------------------
// MESSAGES (1:1)
// ---------------------------------------------------------------------------
async function getMessagesBetween(idA, idB) {
  const rows = await messagesCol.find({
    $or: [
      { sender_id: idA, receiver_id: idB },
      { sender_id: idB, receiver_id: idA }
    ]
  }).toArray();
  return rows.sort((a, b) => a.id - b.id);
}
async function insertMessage({ sender_id, receiver_id, kind, numbers, image }) {
  const msg = {
    id: await nextId("message"),
    sender_id, receiver_id, kind,
    numbers: numbers || null,
    image: image || null,
    created_at: new Date().toISOString()
  };
  await messagesCol.insertOne(msg);
  return msg;
}

// ---------------------------------------------------------------------------
// STATUSES
// ---------------------------------------------------------------------------
async function getStatuses(limit) {
  const rows = await statusesCol.find({}).sort({ id: -1 }).limit(limit || 100).toArray();
  const out = [];
  for (const s of rows) {
    const u = await getUserById(s.user_id);
    out.push({ ...s, username: u?.username || "unknown" });
  }
  return out;
}
async function insertStatus({ user_id, text, image }) {
  const status = { id: await nextId("status"), user_id, text, image: image || null, created_at: new Date().toISOString() };
  await statusesCol.insertOne(status);
  return status;
}

// ---------------------------------------------------------------------------
// MEETINGS
// ---------------------------------------------------------------------------
async function getMeeting(pin) {
  return meetingsCol.findOne({ pin });
}
async function createMeeting(pin, host_id) {
  const meeting = { pin, host_id, created_at: new Date().toISOString() };
  await meetingsCol.insertOne(meeting);
  return meeting;
}
async function getMeetingMessages(pin) {
  const rows = await meetingMessagesCol.find({ pin }).toArray();
  return rows.sort((a, b) => a.id - b.id);
}
async function insertMeetingMessage({ pin, sender_username, numbers }) {
  const msg = { id: await nextId("meeting_message"), pin, sender_username, numbers, created_at: new Date().toISOString() };
  await meetingMessagesCol.insertOne(msg);
  return msg;
}

module.exports = {
  connect,
  getUserByUsername, getUserById, createUser,
  addContactPair, getContacts,
  getMessagesBetween, insertMessage,
  getStatuses, insertStatus,
  getMeeting, createMeeting, getMeetingMessages, insertMeetingMessage
};
