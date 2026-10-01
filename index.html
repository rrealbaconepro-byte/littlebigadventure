const express = require("express");
const path = require("path");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const { initializeApp, cert, getApps } = require("firebase-admin/app");
const { getFirestore, FieldValue } = require("firebase-admin/firestore");

// --------------------------------------------------
// Firebase Admin
// --------------------------------------------------

if (!process.env.FIREBASE_SERVICE_ACCOUNT_JSON) {
  throw new Error("Missing FIREBASE_SERVICE_ACCOUNT_JSON");
}

let serviceAccount;
try {
  serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_JSON);
} catch (error) {
  throw new Error("FIREBASE_SERVICE_ACCOUNT_JSON is not valid JSON");
}

const firebaseApp = getApps().length
  ? getApps()[0]
  : initializeApp({ credential: cert(serviceAccount) });

const db = getFirestore(firebaseApp);

// A fallback is generated per server process. Set LBA_SESSION_SECRET in
// Render for sessions to survive restarts/deploys.
const SESSION_SECRET = process.env.LBA_SESSION_SECRET || crypto.randomBytes(48).toString("hex");
const SESSION_COOKIE = "lba_session";

// --------------------------------------------------
// Express
// --------------------------------------------------

const app = express();
app.use(express.json({ limit: "256kb" }));
app.use(express.urlencoded({ extended: true, limit: "256kb" }));
app.use(express.static(__dirname));

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

function cleanString(value, max = 1000) {
  if (typeof value !== "string") return "";
  return value.trim().slice(0, max);
}

function getCookie(req, name) {
  const header = req.headers.cookie || "";
  const parts = header.split(";").map(v => v.trim());
  for (const part of parts) {
    const eq = part.indexOf("=");
    if (eq === -1) continue;
    if (decodeURIComponent(part.slice(0, eq)) === name) {
      return decodeURIComponent(part.slice(eq + 1));
    }
  }
  return null;
}

function setSessionCookie(res, token) {
  res.setHeader(
    "Set-Cookie",
    `${SESSION_COOKIE}=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=2592000`
  );
}

function clearSessionCookie(res) {
  res.setHeader(
    "Set-Cookie",
    `${SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`
  );
}

function makeSession(userId) {
  return jwt.sign({ uid: userId }, SESSION_SECRET, { expiresIn: "30d" });
}

async function getUserFromRequest(req) {
  const token = getCookie(req, SESSION_COOKIE);
  if (!token) return null;

  try {
    const decoded = jwt.verify(token, SESSION_SECRET);
    if (!decoded.uid) return null;

    const snap = await db.collection("users").doc(decoded.uid).get();
    if (!snap.exists) return null;

    return { id: snap.id, ...snap.data() };
  } catch (_) {
    return null;
  }
}

async function requireAuth(req, res, next) {
  const user = await getUserFromRequest(req);
  if (!user) {
    return res.status(401).json({ error: "You must be logged in" });
  }
  req.user = user;
  next();
}

function publicUser(user) {
  return {
    id: user.id,
    username: user.username || "Player",
    email: user.email || null,
    createdAt: user.createdAt || null
  };
}

// --------------------------------------------------
// Status / Firebase test
// --------------------------------------------------

app.get("/api/status", (req, res) => {
  res.json({ online: true, service: "LittleBigAdventure", firebase: true });
});

app.get("/api/firebase-test", async (req, res) => {
  try {
    const testRef = db.collection("_system").doc("server");
    await testRef.set({
      online: true,
      service: "LittleBigAdventure",
      updatedAt: FieldValue.serverTimestamp()
    }, { merge: true });
    const snapshot = await testRef.get();
    res.json({ connected: true, firestore: true, data: snapshot.data() });
  } catch (error) {
    console.error("Firebase error:", error);
    res.status(500).json({ connected: false, firestore: false, error: "Firebase connection failed" });
  }
});

// --------------------------------------------------
// Account auth - stored in Firestore, no browser Firebase API key needed
// --------------------------------------------------

app.post("/api/auth/signup", async (req, res) => {
  try {
    const username = cleanString(req.body.username, 24);
    const password = typeof req.body.password === "string" ? req.body.password : "";
    const email = cleanString(req.body.email, 254) || null;

    if (!/^[a-zA-Z0-9_.-]{3,24}$/.test(username)) {
      return res.status(400).json({ error: "Username must be 3-24 characters and use letters, numbers, _, . or -." });
    }
    if (password.length < 6 || password.length > 200) {
      return res.status(400).json({ error: "Password must be at least 6 characters." });
    }

    const usernameKey = username.toLowerCase();
    const usernameRef = db.collection("usernames").doc(usernameKey);
    const existing = await usernameRef.get();
    if (existing.exists) {
      return res.status(409).json({ error: "That username is already taken." });
    }

    const userRef = db.collection("users").doc();
    const passwordHash = await bcrypt.hash(password, 12);
    const now = FieldValue.serverTimestamp();

    await db.runTransaction(async transaction => {
      const taken = await transaction.get(usernameRef);
      if (taken.exists) throw new Error("USERNAME_TAKEN");

      transaction.set(userRef, {
        username,
        usernameLower: usernameKey,
        email,
        passwordHash,
        createdAt: now,
        updatedAt: now
      });

      transaction.set(usernameRef, {
        userId: userRef.id,
        createdAt: now
      });
    });

    setSessionCookie(res, makeSession(userRef.id));
    res.json({ success: true, user: { id: userRef.id, username, email } });
  } catch (error) {
    if (error.message === "USERNAME_TAKEN") {
      return res.status(409).json({ error: "That username is already taken." });
    }
    console.error("Signup error:", error);
    res.status(500).json({ error: "Could not create account" });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const username = cleanString(req.body.username, 24);
    const password = typeof req.body.password === "string" ? req.body.password : "";

    const usernameSnap = await db.collection("usernames").doc(username.toLowerCase()).get();
    if (!usernameSnap.exists) {
      return res.status(401).json({ error: "Incorrect username or password." });
    }

    const userId = usernameSnap.data().userId;
    const userSnap = await db.collection("users").doc(userId).get();
    if (!userSnap.exists) {
      return res.status(401).json({ error: "Incorrect username or password." });
    }

    const user = { id: userSnap.id, ...userSnap.data() };
    const valid = await bcrypt.compare(password, user.passwordHash || "");
    if (!valid) {
      return res.status(401).json({ error: "Incorrect username or password." });
    }

    setSessionCookie(res, makeSession(user.id));
    res.json({ success: true, user: publicUser(user) });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ error: "Could not log in" });
  }
});

app.post("/api/auth/logout", (req, res) => {
  clearSessionCookie(res);
  res.json({ success: true });
});

app.get("/api/auth/me", async (req, res) => {
  const user = await getUserFromRequest(req);
  if (!user) return res.status(401).json({ authenticated: false });
  res.json({ authenticated: true, user: publicUser(user) });
});

// --------------------------------------------------
// Profile
// --------------------------------------------------

app.post("/api/profile", requireAuth, async (req, res) => {
  try {
    const username = cleanString(req.body.username, 24);
    const email = cleanString(req.body.email, 254) || null;

    const data = { updatedAt: FieldValue.serverTimestamp() };
    if (username) data.username = username;
    if (email !== undefined) data.email = email;

    await db.collection("users").doc(req.user.id).set(data, { merge: true });
    res.json({ success: true });
  } catch (error) {
    console.error("Profile write error:", error);
    res.status(500).json({ error: "Failed to save profile" });
  }
});

app.get("/api/profile/me", requireAuth, async (req, res) => {
  res.json({ profile: publicUser(req.user) });
});

// --------------------------------------------------
// Levels
// --------------------------------------------------

app.post("/api/levels", requireAuth, async (req, res) => {
  try {
    const title = cleanString(req.body.title || req.body.name, 80);
    const description = cleanString(req.body.description, 1000);
    if (!title) return res.status(400).json({ error: "Level title is required" });

    const ref = db.collection("levels").doc();
    const data = {
      title,
      description,
      creatorId: req.user.id,
      creator: req.user.username,
      plays: 0,
      hearts: 0,
      createdAt: FieldValue.serverTimestamp(),
      updatedAt: FieldValue.serverTimestamp()
    };

    await ref.set(data);
    res.json({ success: true, level: { id: ref.id, ...data } });
  } catch (error) {
    console.error("Level create error:", error);
    res.status(500).json({ error: "Failed to create level" });
  }
});

app.get("/api/levels", async (req, res) => {
  try {
    const snap = await db.collection("levels").orderBy("createdAt", "desc").limit(30).get();
    const levels = snap.docs.map(doc => ({ id: doc.id, ...doc.data() }));
    res.json({ levels });
  } catch (error) {
    console.error("Level list error:", error);
    res.status(500).json({ error: "Failed to load levels" });
  }
});

app.get("/api/levels/:id", async (req, res) => {
  try {
    const snap = await db.collection("levels").doc(req.params.id).get();
    if (!snap.exists) return res.status(404).json({ error: "Level not found" });
    res.json({ level: { id: snap.id, ...snap.data() } });
  } catch (error) {
    console.error("Level read error:", error);
    res.status(500).json({ error: "Failed to load level" });
  }
});

app.patch("/api/levels/:id", requireAuth, async (req, res) => {
  try {
    const ref = db.collection("levels").doc(req.params.id);
    const snap = await ref.get();
    if (!snap.exists) return res.status(404).json({ error: "Level not found" });
    if (snap.data().creatorId !== req.user.id) return res.status(403).json({ error: "Not your level" });

    const update = { updatedAt: FieldValue.serverTimestamp() };
    if (req.body.title !== undefined) update.title = cleanString(req.body.title, 80);
    if (req.body.description !== undefined) update.description = cleanString(req.body.description, 1000);
    await ref.update(update);
    res.json({ success: true });
  } catch (error) {
    console.error("Level update error:", error);
    res.status(500).json({ error: "Failed to update level" });
  }
});

// --------------------------------------------------
// Posts
// --------------------------------------------------

app.post("/api/posts", requireAuth, async (req, res) => {
  try {
    const text = cleanString(req.body.text, 1000);
    if (!text) return res.status(400).json({ error: "Post text is required" });

    const ref = db.collection("posts").doc();
    await ref.set({
      text,
      authorId: req.user.id,
      author: req.user.username,
      createdAt: FieldValue.serverTimestamp()
    });

    res.json({ success: true, post: { id: ref.id, text, author: req.user.username } });
  } catch (error) {
    console.error("Post create error:", error);
    res.status(500).json({ error: "Failed to create post" });
  }
});

app.get("/api/posts", async (req, res) => {
  try {
    const snap = await db.collection("posts").orderBy("createdAt", "desc").limit(30).get();
    const posts = snap.docs.map(doc => ({ id: doc.id, ...doc.data() }));
    res.json({ posts });
  } catch (error) {
    console.error("Post list error:", error);
    res.status(500).json({ error: "Failed to load posts" });
  }
});

// --------------------------------------------------
// 404
// --------------------------------------------------

app.use((req, res) => {
  if (req.path.startsWith("/api/")) {
    return res.status(404).json({ error: "API endpoint not found" });
  }
  res.sendFile(path.join(__dirname, "index.html"));
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`LittleBigAdventure server running on port ${PORT}`);
  console.log("Firebase Admin connected");
});
