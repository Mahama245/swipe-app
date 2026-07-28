# SWIPE — Real, Hosted Version

This is now a real app: accounts, passwords, a database, and live message delivery
between real users — not a local simulation. Here's what changed and how to get
it online so your friends can use it.

## What's new vs. the prototype

- **Real accounts**: sign up with a username + password. Passwords are hashed
  (bcrypt), sessions use JWT tokens.
- **Real contacts**: add a friend by their exact username (not a made-up name).
  Adding someone is mutual — they see you in their contact list too.
- **Real message delivery**: messages are stored in a database and pushed
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
  server.js        <- backend (Express + Socket.io + SQLite)
  package.json
  public/
    index.html      <- the whole frontend (login screen + chat UI)
  data/
    swipe.db         <- created automatically on first run
```

## Running it locally (to test before you deploy)

You need [Node.js](https://nodejs.org) 18+ installed.

```bash
cd swipe-app
npm install
npm start
```

Then open **http://localhost:3000** — sign up, open a second browser (or an
incognito window) and sign up as a second user, add each other as contacts,
and chat.

## Putting it online for real (free options)

You need actual hosting since this has a backend + database. Two easy, free
ways to do this:

### Option A: Render.com (recommended, simplest)

1. Create a free account at https://render.com
2. Push this folder to a GitHub repo (see below if you haven't used Git).
3. On Render: **New → Web Service** → connect your GitHub repo.
4. Settings:
   - **Build command**: `npm install`
   - **Start command**: `npm start`
5. Add an environment variable: `JWT_SECRET` = any long random string (this
   signs login sessions — keep it secret).
6. Deploy. Render gives you a public URL like `https://swipe-xxxx.onrender.com`
   — send that link to your friends.

⚠️ One catch on Render's free tier: the SQLite database file lives on disk,
and free-tier disks aren't guaranteed to persist forever across redeploys.
For a class project / friends-only demo this is fine. If you want your data
to survive long-term, the fix later is switching to Render's free PostgreSQL
add-on instead of SQLite — ask me when you're ready and I'll wire that up.

### Option B: Railway.app

Same idea as Render — connect your GitHub repo, it auto-detects Node.js,
set the `JWT_SECRET` environment variable, deploy, get a public URL.

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
