// db.js — MongoDB-backed persistence (MongoDB Atlas free tier).
// Replaces the old JSON-file database, which reset every time Render
// restarted the server (Render's free tier disk is NOT persistent —
// that was the "friends disappear on re-login" bug).
//
// Also stores WebAuthn (Face ID / fingerprint / Windows Hello) credentials
// per user, for biometric login.
//
// All functions below are ASYNC (return Promises) — server.js awaits them.

const mongoose = require("mongoose");

const MONGODB_URI = process.env.MONGODB_URI;

if (!MONGODB_URI) {
  console.error("FATAL: MONGODB_URI environment variable is not set.");
  console.error("Set it in your .env file locally, or in Render's Environment tab.");
  process.exit(1);
}

mongoose.connect(MONGODB_URI)
  .then(() => console.log("Connected to MongoDB."))
  .catch(err => {
    console.error("MongoDB connection failed:", err.message);
    process.exit(1);
  });

// ---------------------------------------------------------------------------
// SCHEMAS
// ---------------------------------------------------------------------------
const CounterSchema = new mongoose.Schema({
  _id: String,
  seq: { type: Number, default: 0 }
});
const Counter = mongoose.model("Counter", CounterSchema);

const UserSchema = new mongoose.Schema({
  id: { type: Number, unique: true },
  username: { type: String, unique: true, index: true },
  password_hash: String,
  is_admin: { type: Boolean, default: false },
  created_at: { type: Date, default: Date.now }
});
const User = mongoose.model("User", UserSchema);

const ContactSchema = new mongoose.Schema({
  user_id: Number,
  contact_id: Number,
  created_at: { type: Date, default: Date.now }
});
const Contact = mongoose.model("Contact", ContactSchema);

const MessageSchema = new mongoose.Schema({
  id: { type: Number, unique: true },
  sender_id: Number,
  receiver_id: Number,
  kind: String,
  numbers: mongoose.Schema.Types.Mixed,
  image: String,
  created_at: { type: Date, default: Date.now }
});
const Message = mongoose.model("Message", MessageSchema);

const StatusSchema = new mongoose.Schema({
  id: { type: Number, unique: true },
  user_id: Number,
  text: String,
  image: String,
  created_at: { type: Date, default: Date.now }
});
const Status = mongoose.model("Status", StatusSchema);

const MeetingSchema = new mongoose.Schema({
  pin: { type: String, unique: true },
  host_id: Number,
  status: { type: String, enum: ["OPEN", "CLOSED"], default: "OPEN" },
  closed_at: { type: Date, default: null },
  closed_by: { type: Number, default: null },
  // Usernames granted access back into a CLOSED meeting via an approved
  // request (or a bulk "let everyone back in" action by an admin). The host
  // does NOT automatically keep access after closing — once closed, only an
  // admin has standing access; everyone else, including the original host,
  // must request it again like anyone else.
  approved_usernames: { type: [String], default: [] },
  // Everyone who has ever successfully joined this meeting (host included).
  // Used both for the admin's "let everyone back in" bulk action and for
  // enforcing the host's optional headcount cap.
  participants: { type: [String], default: [] },
  // Optional cap the host sets on how many distinct people may be in the
  // meeting at once. null = unlimited. Once reached, new joins are blocked
  // until the host or an admin resets it (clears the participants list).
  max_participants: { type: Number, default: null },
  created_at: { type: Date, default: Date.now }
});
const Meeting = mongoose.model("Meeting", MeetingSchema);

const MeetingAccessRequestSchema = new mongoose.Schema({
  id: { type: Number, unique: true },
  pin: String,
  requester_id: Number,
  requester_username: String,
  status: { type: String, enum: ["PENDING", "APPROVED", "DENIED"], default: "PENDING" },
  created_at: { type: Date, default: Date.now },
  resolved_at: { type: Date, default: null },
  resolved_by: { type: Number, default: null }
});
const MeetingAccessRequest = mongoose.model("MeetingAccessRequest", MeetingAccessRequestSchema);

const MeetingMessageSchema = new mongoose.Schema({
  id: { type: Number, unique: true },
  pin: String,
  sender_username: String,
  numbers: mongoose.Schema.Types.Mixed,
  created_at: { type: Date, default: Date.now }
});
const MeetingMessage = mongoose.model("MeetingMessage", MeetingMessageSchema);

// WebAuthn credentials (Face ID / fingerprint / Windows Hello).
// The server NEVER sees biometric data — only a public key + counter.
const AuthenticatorSchema = new mongoose.Schema({
  user_id: { type: Number, index: true },
  credential_id: { type: String, unique: true }, // base64url
  public_key: String,                             // base64url
  counter: { type: Number, default: 0 },
  device_type: String,
  backed_up: Boolean,
  transports: [String],
  nickname: String,                                // e.g. "Mahama's iPhone"
  created_at: { type: Date, default: Date.now }
});
const Authenticator = mongoose.model("Authenticator", AuthenticatorSchema);

// temporary storage for in-flight WebAuthn challenges — TTL index auto-cleans
const ChallengeSchema = new mongoose.Schema({
  user_id: { type: Number, index: true },
  challenge: String,
  created_at: { type: Date, default: Date.now, expires: 300 } // auto-delete after 5 min
});
const Challenge = mongoose.model("Challenge", ChallengeSchema);

// ---------------------------------------------------------------------------
// ID COUNTERS (mimics the old auto-increment behaviour)
// ---------------------------------------------------------------------------
async function nextId(kind) {
  const doc = await Counter.findByIdAndUpdate(
    kind,
    { $inc: { seq: 1 } },
    { new: true, upsert: true }
  );
  return doc.seq;
}

// ---------------------------------------------------------------------------
// USERS
// ---------------------------------------------------------------------------
async function getUserByUsername(username) {
  return User.findOne({ username }).lean();
}
async function getUserById(id) {
  return User.findOne({ id }).lean();
}
async function createUser(username, password_hash) {
  const id = await nextId("user");
  const user = await User.create({ id, username, password_hash });
  return user.toObject();
}

// Ensures the designated bootstrap admin username always has admin rights,
// even if their account was created before this feature existed. Called on
// every login rather than only at signup so it's self-healing.
async function ensureBootstrapAdmin(username) {
  const bootstrapUsername = (process.env.BOOTSTRAP_ADMIN_USERNAME || "mahama245").toLowerCase();
  if (username !== bootstrapUsername) return;
  await User.updateOne({ username }, { is_admin: true });
}

// ---------------------------------------------------------------------------
// CONTACTS (mutual)
// ---------------------------------------------------------------------------
async function addContactPair(userId, contactId) {
  const exists1 = await Contact.findOne({ user_id: userId, contact_id: contactId });
  if (!exists1) await Contact.create({ user_id: userId, contact_id: contactId });
  const exists2 = await Contact.findOne({ user_id: contactId, contact_id: userId });
  if (!exists2) await Contact.create({ user_id: contactId, contact_id: userId });
}
async function getContacts(userId) {
  const rows = await Contact.find({ user_id: userId }).lean();
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
  return Message.find({
    $or: [
      { sender_id: idA, receiver_id: idB },
      { sender_id: idB, receiver_id: idA }
    ]
  }).sort({ id: 1 }).lean();
}
async function insertMessage({ sender_id, receiver_id, kind, numbers, image }) {
  const id = await nextId("message");
  const msg = await Message.create({
    id, sender_id, receiver_id, kind,
    numbers: numbers || null,
    image: image || null
  });
  return msg.toObject();
}

// ---------------------------------------------------------------------------
// STATUSES
// ---------------------------------------------------------------------------
async function getStatuses(limit) {
  const rows = await Status.find().sort({ id: -1 }).limit(limit || 100).lean();
  return Promise.all(rows.map(async s => ({
    ...s,
    username: (await getUserById(s.user_id))?.username || "unknown"
  })));
}
async function insertStatus({ user_id, text, image }) {
  const id = await nextId("status");
  const status = await Status.create({ id, user_id, text, image: image || null });
  return status.toObject();
}

// ---------------------------------------------------------------------------
// MEETINGS
// ---------------------------------------------------------------------------
async function getMeeting(pin) {
  return Meeting.findOne({ pin }).lean();
}
async function createMeeting(pin, host_id, host_username, max_participants) {
  const meeting = await Meeting.create({
    pin,
    host_id,
    participants: host_username ? [host_username] : [],
    max_participants: max_participants != null ? max_participants : null,
  });
  return meeting.toObject();
}
async function closeMeeting(pin, closed_by) {
  const meeting = await Meeting.findOneAndUpdate(
    { pin },
    { status: "CLOSED", closed_at: new Date(), closed_by, approved_usernames: [] },
    { new: true }
  );
  return meeting ? meeting.toObject() : null;
}
// True if this user may currently get into the meeting: it's still open,
// they're an admin, or they were specifically approved back in after a
// closure. The original host does NOT get automatic access back — once
// closed, they're treated the same as anyone else and must request access.
async function canAccessMeeting(meeting, username, isAdmin) {
  if (isAdmin) return true;
  if (meeting.status === "OPEN") return true;
  return (meeting.approved_usernames || []).includes(username);
}

// Records that this user is "in" the meeting, for headcount purposes.
// Returns { ok: true } or { ok: false, reason: "full" } if the host's cap
// has been reached and this is a brand-new participant (people already
// counted can always continue, since they already hold a seat).
async function joinAsParticipant(pin, username) {
  const meeting = await Meeting.findOne({ pin });
  if (!meeting) return { ok: false, reason: "not_found" };
  if (meeting.participants.includes(username)) return { ok: true };
  if (meeting.max_participants != null && meeting.participants.length >= meeting.max_participants) {
    return { ok: false, reason: "full" };
  }
  meeting.participants.push(username);
  await meeting.save();
  return { ok: true };
}
async function setMeetingCapacity(pin, max_participants) {
  const meeting = await Meeting.findOneAndUpdate({ pin }, { max_participants }, { new: true });
  return meeting ? meeting.toObject() : null;
}
// Clears the headcount so joins are allowed again up to the same cap.
// Does not change who's approved/closed — just the seat count.
async function resetMeetingCapacity(pin) {
  const meeting = await Meeting.findOneAndUpdate({ pin }, { participants: [] }, { new: true });
  return meeting ? meeting.toObject() : null;
}
// Admin bulk action: let every past participant back into a closed meeting
// at once, instead of approving each one's request individually.
async function reopenMeetingForAllParticipants(pin) {
  const meeting = await Meeting.findOne({ pin });
  if (!meeting) return null;
  meeting.approved_usernames = Array.from(new Set([...(meeting.approved_usernames || []), ...meeting.participants]));
  await meeting.save();
  return meeting.toObject();
}

async function getMeetingMessages(pin) {
  return MeetingMessage.find({ pin }).sort({ id: 1 }).lean();
}
async function insertMeetingMessage({ pin, sender_username, numbers }) {
  const id = await nextId("meeting_message");
  const msg = await MeetingMessage.create({ id, pin, sender_username, numbers });
  return msg.toObject();
}

// ---------------------------------------------------------------------------
// MEETING ACCESS REQUESTS
// ---------------------------------------------------------------------------
async function createAccessRequest(pin, requester_id, requester_username) {
  const existing = await MeetingAccessRequest.findOne({ pin, requester_username, status: "PENDING" });
  if (existing) return existing.toObject();
  const id = await nextId("meeting_access_request");
  const request = await MeetingAccessRequest.create({ id, pin, requester_id, requester_username });
  return request.toObject();
}
async function getPendingAccessRequests() {
  return MeetingAccessRequest.find({ status: "PENDING" }).sort({ created_at: -1 }).lean();
}
async function resolveAccessRequest(id, approve, resolved_by) {
  const request = await MeetingAccessRequest.findOne({ id });
  if (!request) return null;
  request.status = approve ? "APPROVED" : "DENIED";
  request.resolved_at = new Date();
  request.resolved_by = resolved_by;
  await request.save();
  if (approve) {
    await Meeting.updateOne({ pin: request.pin }, { $addToSet: { approved_usernames: request.requester_username } });
  }
  return request.toObject();
}

// ---------------------------------------------------------------------------
// WEBAUTHN (biometric login)
// ---------------------------------------------------------------------------
async function saveChallenge(user_id, challenge) {
  await Challenge.deleteMany({ user_id: user_id ?? null });
  await Challenge.create({ user_id: user_id ?? null, challenge });
}
async function getChallenge(user_id) {
  const row = await Challenge.findOne({ user_id: user_id ?? null }).sort({ created_at: -1 }).lean();
  return row ? row.challenge : null;
}
async function clearChallenge(user_id) {
  await Challenge.deleteMany({ user_id: user_id ?? null });
}
async function addAuthenticator({ user_id, credential_id, public_key, counter, device_type, backed_up, transports, nickname }) {
  const auth = await Authenticator.create({
    user_id, credential_id, public_key, counter,
    device_type, backed_up, transports: transports || [], nickname: nickname || "This device"
  });
  return auth.toObject();
}
async function getAuthenticatorsByUser(user_id) {
  return Authenticator.find({ user_id }).lean();
}
async function getAuthenticatorByCredentialId(credential_id) {
  return Authenticator.findOne({ credential_id }).lean();
}
async function updateAuthenticatorCounter(credential_id, counter) {
  await Authenticator.updateOne({ credential_id }, { counter });
}
async function deleteAuthenticator(user_id, credential_id) {
  await Authenticator.deleteOne({ user_id, credential_id });
}

module.exports = {
  getUserByUsername, getUserById, createUser, ensureBootstrapAdmin,
  addContactPair, getContacts,
  getMessagesBetween, insertMessage,
  getStatuses, insertStatus,
  getMeeting, createMeeting, closeMeeting, canAccessMeeting, getMeetingMessages, insertMeetingMessage,
  joinAsParticipant, setMeetingCapacity, resetMeetingCapacity, reopenMeetingForAllParticipants,
  createAccessRequest, getPendingAccessRequests, resolveAccessRequest,
  saveChallenge, getChallenge, clearChallenge,
  addAuthenticator, getAuthenticatorsByUser, getAuthenticatorByCredentialId,
  updateAuthenticatorCounter, deleteAuthenticator
};
