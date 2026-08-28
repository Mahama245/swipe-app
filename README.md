# SWIPE — Real, Hosted Version

This is now a real app: accounts, passwords, a database, and live message delivery
between real users — not a local simulation. Here's what changed and how to get
it online so your friends can use it.

## What's new vs. the prototype

- **Real accounts**: sign up with a username + password. Passwords are hashed
  (bcrypt), sessions use JWT tokens.
- **Real, permanent database**: MongoDB Atlas (free tier) — data survives
  server restarts and redeploys. (The old JSON-file version lost everyone's
  accounts every time Render restarted, because Render's free disk isn't
  persistent. That's fixed now.)
- **Face ID / fingerprint / Windows Hello login** via WebAuthn — after
  logging in once with a password, tap "Enable Face ID / Fingerprint" and
  future logins can skip the password entirely. Your device checks your
  face/fingerprint locally; the server only ever stores a public key, never
  any biometric data.
- **Real contacts**: add a friend by their exact username (not a made-up name).
  Adding someone is mutual — they see you in their contact list too.
- **Real message delivery**: messages are stored in the database and pushed
  instantly to the other person over a live connection (Socket.io), whether
  they're online right now or check back later.
- **The cipher is still yours**: the server only ever stores/relays the encoded
  *numbers* — never the plaintext, and never the formula. You and your friend
  still have to agree on the formula (e.g. `2x+1/2`) some other way, same as
  before. That's the whole "encoded messaging" gimmick, now for real.
- **Status posts** are shared with everyone (like a public feed).
- **Meetings** use a PIN to create a shared room; the formula still stays
  off the server, shared by you directly with participants.

## Project structure

```
swipe-app/
  server.js        <- backend (Express + Socket.io + MongoDB + WebAuthn)
  db.js             <- all database access (MongoDB via Mongoose)
  package.json
  public/
    index.html      <- the whole frontend (login screen + chat UI)
  .env.example      <- copy to .env for local dev
```

## One-time setup: MongoDB Atlas (free forever)

1. Create a free account at https://www.mongodb.com/cloud/atlas/register
2. Create a free **M0 cluster** (any region close to you is fine).
3. **Database Access** → add a database user (e.g. username `Swipeadmin`),
   generate/set a password, save it somewhere safe.
4. **Network Access** → add IP address → allow access from anywhere
   (`0.0.0.0/0`) — fine for a small friends app.
5. **Database → Connect → Drivers → Node.js** → copy the connection string.
   It looks like:
   `mongodb+srv://Swipeadmin:<password>@swipecluster.xxxxx.mongodb.net/?retryWrites=true&w=majority`
   Replace `<password>` with your real password, and add `/swipe` before the
   `?` so it points at a database named `swipe`.
6. That full string is your `MONGODB_URI`.

## Running it locally (to test before you deploy)

You need [Node.js](https://nodejs.org) 18+ installed.

```bash
cd swipe-app
npm install
cp .env.example .env
# edit .env and paste in your MONGODB_URI from the Atlas step above
npm start
```

Then open **http://localhost:3000** — sign up, open a second browser (or an
incognito window) and sign up as a second user, add each other as contacts,
and chat.

## Putting it online for real

### Render.com (recommended, simplest, free)

1. Create a free account at https://render.com
2. Push this folder to a GitHub repo (see below if you haven't used Git).
3. On Render: **New → Web Service** → connect your GitHub repo.
4. Settings:
   - **Build command**: `npm install`
   - **Start command**: `npm start`
5. Add environment variables (Dashboard → your service → Environment):
   - `JWT_SECRET` = any long random string
   - `MONGODB_URI` = your full Atlas connection string from above
   - `RP_ID` = your Render domain with no `https://`, e.g. `swipe-app-wzqp.onrender.com`
   - `ORIGIN` = your full Render URL with `https://`, e.g. `https://swipe-app-wzqp.onrender.com`
6. Deploy. Render gives you a public URL — send that link to your friends.

⚠️ `RP_ID` and `ORIGIN` matter specifically for Face ID/fingerprint login to
work — WebAuthn checks that the domain matches exactly. If you ever move to
a custom domain, update both.

### If you haven't used GitHub yet

```bash
cd swipe-app
git init
git add .
git commit -m "SWIPE - real version"
```
Then create an empty repo on github.com and follow the "push an existing
repository" instructions it shows you.

## Security notes (things you should know as the person running this)

- Change `JWT_SECRET` to your own random value in production — don't use the
  default in `server.js`.
- Passwords are hashed, never stored in plain text.
- This is a fun/learning project, not a bank. Don't have anyone put sensitive
  real secrets through it — the "encoding" is a personal math cipher, not
  real cryptography.

## What to try first

1. Deploy it (Option A above).
2. Sign up yourself, then have one friend sign up.
3. Add each other by username.
4. Agree on a formula out loud/in person (e.g. `3x+2`) and send a message —
   watch it show up instantly on their end as a string of numbers, then
   decode it together.
