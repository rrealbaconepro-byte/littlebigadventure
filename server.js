const express = require("express");
const path = require("path");
const cookieParser = require("cookie-parser");
const { initializeApp, cert } = require("firebase-admin/app");
const { getAuth, getFirestore, FieldValue } = require("firebase-admin");

const app = express();
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

if (!process.env.FIREBASE_SERVICE_ACCOUNT_JSON) {
  throw new Error("Missing FIREBASE_SERVICE_ACCOUNT_JSON");
}

let serviceAccount;
try {
  serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_JSON);
} catch {
  throw new Error("FIREBASE_SERVICE_ACCOUNT_JSON is not valid JSON");
}

initializeApp({ credential: cert(serviceAccount) });
const auth = getAuth();
const db = getFirestore();

function clean(v) { return String(v ?? "").trim(); }
function lower(v) { return clean(v).toLowerCase(); }

function error(res, status, message) {
  return res.status(status).json({ success: false, error: message });
}

// Firebase is the source of truth.
// Every important operation follows:
// READ -> VALIDATE -> WRITE -> READ BACK

async function readDoc(collection, id) {
  if (!id) return null;
  const snap = await db.collection(collection).doc(String(id)).get();
  return snap.exists ? { id: snap.id, data: snap.data() || {} } : null;
}

async function readCollection(collection, limit = 500) {
  const snap = await db.collection(collection).limit(limit).get();
  return snap.docs.map(d => ({ id: d.id, ...d.data() }));
}

async function getNextUserId() {
  const ref = db.collection("_system").doc("user_counter");

  return db.runTransaction(async tx => {
    const snap = await tx.get(ref);
    const current = Number(snap.data()?.last_user_id || 0);
    const next = current + 1;

    tx.set(ref, {
      last_user_id: next,
      updated_at: FieldValue.serverTimestamp()
    }, { merge: true });

    return next;
  });
}

async function ensureUserId(profileId, profile) {
  const existing = Number(profile.user_id);
  if (Number.isInteger(existing) && existing > 0) return existing;

  const profiles = await readCollection("profiles");
  const ordered = profiles.sort((a, b) => {
    const at = a.created_at?.toMillis?.() || 0;
    const bt = b.created_at?.toMillis?.() || 0;
    return at - bt;
  });

  const index = ordered.findIndex(p => p.id === profileId);
  const id = index >= 0 ? index + 1 : await getNextUserId();

  await db.collection("profiles").doc(profileId).set({
    user_id: id,
    updated_at: FieldValue.serverTimestamp()
  }, { merge: true });

  return id;
}

async function findProfile(identifier) {
  const value = clean(identifier);
  if (!value) return null;

  const direct = await readDoc("profiles", value);
  if (direct) return direct;

  const numeric = Number(value);
  if (Number.isInteger(numeric)) {
    for (const field of ["user_id", "profile_id", "id"]) {
      const snap = await db.collection("profiles")
        .where(field, "==", numeric).limit(1).get();
      if (!snap.empty) {
        const d = snap.docs[0];
        return { id: d.id, data: d.data() };
      }
    }
  }

  const byName = await db.collection("profiles")
    .where("username_lower", "==", lower(value))
    .limit(1).get();

  if (!byName.empty) {
    const d = byName.docs[0];
    return { id: d.id, data: d.data() };
  }

  const profiles = await readCollection("profiles");
  const old = profiles.find(p => lower(p.username) === lower(value));
  return old ? { id: old.id, data: old } : null;
}

async function currentUser(req) {
  if (req.cookies?.session) {
    try {
      const decoded = await auth.verifySessionCookie(req.cookies.session, true);
      const profile = await readDoc("profiles", decoded.uid);
      return { uid: decoded.uid, profile: profile?.data || null };
    } catch {}
  }

  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : req.headers["x-firebase-token"];

  if (token) {
    try {
      const decoded = await auth.verifyIdToken(token);
      const profile = await readDoc("profiles", decoded.uid);
      return { uid: decoded.uid, profile: profile?.data || null };
    } catch {}
  }

  return null;
}

async function requireUser(req, res) {
  const user = await currentUser(req);
  if (!user) {
    error(res, 401, "You must be logged in.");
    return null;
  }
  return user;
}

app.get("/api/status", async (req, res) => {
  try {
    const snap = await db.collection("_system").doc("server").get();
    res.json({
      online: true,
      service: "LittleBigAdventure",
      firebase: true,
      firebase_readable: true,
      firebase_document_exists: snap.exists
    });
  } catch {
    res.status(503).json({
      online: true,
      service: "LittleBigAdventure",
      firebase: false,
      firebase_readable: false
    });
  }
});

app.get("/api/firebase-test", async (req, res) => {
  try {
    const ref = db.collection("_system").doc("server");

    // READ
    const before = await ref.get();

    // WRITE
    await ref.set({
      online: true,
      service: "LittleBigAdventure",
      updatedAt: FieldValue.serverTimestamp()
    }, { merge: true });

    // READ BACK
    const after = await ref.get();

    res.json({
      connected: true,
      firestore: true,
      read_before_write: before.exists,
      write_successful: true,
      read_after_write: after.exists,
      data: after.data()
    });
  } catch (e) {
    console.error(e);
    error(res, 500, "Firebase connection failed.");
  }
});

async function createSession(res, idToken) {
  const expiresIn = 1000 * 60 * 60 * 24 * 5;
  const cookie = await auth.createSessionCookie(idToken, { expiresIn });

  res.cookie("session", cookie, {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    maxAge: expiresIn,
    path: "/"
  });
}

async function signIn(email, password) {
  const key = process.env.FIREBASE_WEB_API_KEY ||
    "AIzaSyAKAvsFCZ840VtMEV7w1t-ie_uil-KWuCk";

  const response = await fetch(
    `https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${encodeURIComponent(key)}`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        email,
        password,
        returnSecureToken: true
      })
    }
  );

  const data = await response.json();
  if (!response.ok) {
    throw new Error(data.error?.message || "Login failed.");
  }
  return data;
}

app.post("/api/auth/signup", async (req, res) => {
  try {
    const username = clean(req.body.username);
    const password = String(req.body.password || "");
    const email = clean(req.body.email);

    if (!username || !password) return error(res, 400, "Username and password are required.");
    if (password.length < 6) return error(res, 400, "Password must be at least 6 characters.");

    // READ FIRST
    const existing = await db.collection("profiles")
      .where("username_lower", "==", lower(username))
      .limit(1).get();

    if (!existing.empty) return error(res, 409, "Username is already taken.");

    const firebaseUser = await auth.createUser({
      email: email || undefined,
      password,
      displayName: username
    });

    const userId = await getNextUserId();

    // WRITE
    await db.collection("profiles").doc(firebaseUser.uid).set({
      uid: firebaseUser.uid,
      user_id: userId,
      username,
      username_lower: lower(username),
      display_name: username,
      email: email || "",
      auth_email: email || "",
      bio: "no username",
      avatar_url: "",
      created_at: FieldValue.serverTimestamp(),
      updated_at: FieldValue.serverTimestamp()
    });

    // READ BACK
    const saved = await readDoc("profiles", firebaseUser.uid);
    if (!saved) return error(res, 500, "Profile could not be read back.");

    if (email) {
      const token = await signIn(email, password);
      await createSession(res, token.idToken);
    }

    res.json({
      success: true,
      user: {
        uid: firebaseUser.uid,
        user_id: saved.data.user_id,
        username: saved.data.username
      }
    });
  } catch (e) {
    console.error("Signup:", e);
    error(res, 500, e.message || "Failed to create account.");
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const username = clean(req.body.username);
    const password = String(req.body.password || "");
    const found = await findProfile(username);

    if (!found) return error(res, 401, "Invalid username or password.");

    const email = found.data.auth_email || found.data.email;
    if (!email) return error(res, 401, "This account has no login email.");

    const token = await signIn(email, password);
    await createSession(res, token.idToken);

    const saved = await readDoc("profiles", token.localId);

    res.json({
      success: true,
      user: {
        uid: token.localId,
        user_id: saved?.data?.user_id || null,
        username: saved?.data?.username || username,
        display_name: saved?.data?.display_name || username
      }
    });
  } catch (e) {
    console.error("Login:", e);
    error(res, 401, "Invalid username or password.");
  }
});

app.get("/api/auth/me", async (req, res) => {
  try {
    const user = await currentUser(req);
    if (!user) return res.json({ authenticated: false, user: null });

    const profile = await readDoc("profiles", user.uid);

    res.json({
      authenticated: true,
      user: {
        uid: user.uid,
        user_id: profile?.data?.user_id || null,
        username: profile?.data?.username || "No username",
        display_name: profile?.data?.display_name || profile?.data?.username || "No username",
        bio: profile?.data?.bio || "",
        avatar_url: profile?.data?.avatar_url || ""
      }
    });
  } catch {
    error(res, 500, "Failed to read account.");
  }
});

app.post("/api/auth/logout", (req, res) => {
  res.clearCookie("session", {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    path: "/"
  });
  res.json({ success: true });
});

// ---------------- PLAYERS ----------------

app.get("/api/players", async (req, res) => {
  try {
    const profiles = await readCollection("profiles");
    res.json({
      players: profiles.map(p => ({
        id: p.id,
        uid: p.uid || p.id,
        user_id: p.user_id || null,
        username: p.username || "No username found",
        display_name: p.display_name || p.username || "No username found",
        avatar_url: p.avatar_url || ""
      }))
    });
  } catch (e) {
    console.error(e);
    error(res, 500, "Failed to read players.");
  }
});

// ---------------- PROFILES ----------------

async function levelsForProfile(profileId, profile, userId) {
  const levels = await readCollection("levels");

  return levels.filter(level => {
    const creatorUid = level.uid || level.creator_uid || level.creator_user_id || level.user_id;
    const creatorUserId = level.creator_user_id || level.user_id;
    const creatorName = lower(level.username || level.creator_username || level.creator);

    return creatorUid === (profile.uid || profileId) ||
      String(creatorUserId) === String(userId) ||
      creatorName === lower(profile.username);
  });
}

async function postsForProfile(profileId, profile, userId) {
  const posts = await readCollection("posts");

  return posts.filter(post => {
    const authorUid = post.uid || post.author_uid || post.author_user_id || post.user_id;
    const authorUserId = post.author_user_id || post.user_id;
    const authorName = lower(post.username || post.author_username || post.author);

    return authorUid === (profile.uid || profileId) ||
      String(authorUserId) === String(userId) ||
      authorName === lower(profile.username);
  });
}

async function profilePayload(identifier) {
  const found = await findProfile(identifier);
  if (!found) return null;

  const userId = await ensureUserId(found.id, found.data);
  const levels = await levelsForProfile(found.id, found.data, userId);
  const posts = await postsForProfile(found.id, found.data, userId);

  const followers = await db.collection("follows")
    .where("following_uid", "==", found.id).get();

  const following = await db.collection("follows")
    .where("follower_uid", "==", found.id).get();

  const friends = await db.collection("friends")
    .where("users", "array-contains", found.id).get();

  return {
    id: found.id,
    uid: found.data.uid || found.id,
    user_id: userId,
    username: found.data.username || "No username",
    display_name: found.data.display_name || found.data.username || "No username",
    bio: found.data.bio || "no username",
    avatar_url: found.data.avatar_url || "",
    levels,
    posts,
    followers: followers.size,
    following: following.size,
    friends: friends.size
  };
}

app.get("/api/profile/:id", async (req, res) => {
  try {
    const profile = await profilePayload(req.params.id);
    if (!profile) return res.status(404).json({ found: false, profile: null });
    res.json({ found: true, profile });
  } catch (e) {
    console.error("Profile:", e);
    error(res, 500, "Failed to read profile.");
  }
});

app.get("/api/profiles/:id", async (req, res) => {
  try {
    const profile = await profilePayload(req.params.id);
    if (!profile) return res.status(404).json({ found: false, profile: null });
    res.json({ found: true, profile });
  } catch (e) {
    console.error("Profile:", e);
    error(res, 500, "Failed to read profile.");
  }
});

// ---------------- POSTS ----------------

async function findPost(identifier) {
  const value = clean(identifier);
  if (!value) return null;

  const direct = await readDoc("posts", value);
  if (direct) return direct;

  for (const field of ["post_id", "id", "postId"]) {
    const snap = await db.collection("posts").where(field, "==", value).limit(1).get();
    if (!snap.empty) {
      const d = snap.docs[0];
      return { id: d.id, data: d.data() };
    }
  }

  return null;
}

async function readReplies(postId) {
  const output = [];
  const seen = new Set();

  for (const collection of ["post_replies", "replies"]) {
    const snap = await db.collection(collection)
      .where("post_id", "==", String(postId)).get();

    for (const d of snap.docs) {
      if (!seen.has(d.id)) {
        seen.add(d.id);
        output.push({ id: d.id, ...d.data() });
      }
    }
  }

  output.sort((a, b) =>
    (a.created_at?.toMillis?.() || 0) -
    (b.created_at?.toMillis?.() || 0)
  );

  return output;
}

async function postPayload(identifier) {
  const found = await findPost(identifier);
  if (!found) return null;

  const post = found.data;
  const authorUid = post.uid || post.author_uid || post.author_user_id || post.user_id;
  const authorProfile = authorUid ? await readDoc("profiles", authorUid) : null;

  return {
    id: found.id,
    title: post.title || post.text || "No post found",
    text: post.text || post.body || "no post",
    author: authorProfile?.data?.display_name || authorProfile?.data?.username || post.author || post.username || "No username found",
    author_user_id: authorProfile?.data?.user_id || post.author_user_id || post.user_id || "?",
    author_uid: authorProfile?.id || authorUid || "",
    avatar_url: authorProfile?.data?.avatar_url || post.avatar_url || "",
    created_at: post.created_at || post.createdAt || null,
    replies: await readReplies(found.id)
  };
}

app.get("/api/posts", async (req, res) => {
  try {
    const posts = await readCollection("posts");
    posts.sort((a, b) =>
      (b.created_at?.toMillis?.() || 0) -
      (a.created_at?.toMillis?.() || 0)
    );
    res.json({ posts });
  } catch (e) {
    console.error(e);
    error(res, 500, "Failed to read posts.");
  }
});

app.get("/api/posts/:id", async (req, res) => {
  try {
    const post = await postPayload(req.params.id);
    if (!post) return res.status(404).json({ found: false, post: null });
    res.json({ found: true, post });
  } catch (e) {
    console.error("Post:", e);
    error(res, 500, "Failed to read post.");
  }
});

app.post("/api/posts", async (req, res) => {
  try {
    const user = await requireUser(req, res);
    if (!user) return;

    const text = clean(req.body.text);
    if (!text) return error(res, 400, "Post cannot be empty.");

    const profile = await readDoc("profiles", user.uid);
    if (!profile) return error(res, 404, "Your profile could not be found.");

    const userId = await ensureUserId(user.uid, profile.data);
    const ref = db.collection("posts").doc();

    // WRITE
    await ref.set({
      uid: user.uid,
      user_id: userId,
      username: profile.data.username || "No username",
      author: profile.data.display_name || profile.data.username || "No username",
      avatar_url: profile.data.avatar_url || "",
      text,
      created_at: FieldValue.serverTimestamp(),
      updated_at: FieldValue.serverTimestamp()
    });

    // READ BACK
    const saved = await postPayload(ref.id);
    res.json({ success: true, post: saved });
  } catch (e) {
    console.error(e);
    error(res, 500, "Failed to create post.");
  }
});

app.post("/api/posts/:id/replies", async (req, res) => {
  try {
    const user = await requireUser(req, res);
    if (!user) return;

    const text = clean(req.body.text);
    if (!text) return error(res, 400, "Reply cannot be empty.");

    // READ POST FIRST
    const post = await findPost(req.params.id);
    if (!post) return error(res, 404, "Post not found.");

    const profile = await readDoc("profiles", user.uid);
    if (!profile) return error(res, 404, "Your profile could not be found.");

    const userId = await ensureUserId(user.uid, profile.data);

    // WRITE
    const ref = db.collection("post_replies").doc();
    await ref.set({
      post_id: String(post.id),
      uid: user.uid,
      user_id: userId,
      username: profile.data.username || "No username",
      author: profile.data.display_name || profile.data.username || "No username",
      text,
      created_at: FieldValue.serverTimestamp()
    });

    // READ BACK
    const replies = await readReplies(post.id);
    res.json({
      success: true,
      reply: { id: ref.id, post_id: post.id, text },
      replies
    });
  } catch (e) {
    console.error(e);
    error(res, 500, "Failed to create reply.");
  }
});

// ---------------- LEVELS ----------------

async function findLevel(identifier) {
  const value = clean(identifier);
  if (!value) return null;

  const direct = await readDoc("levels", value);
  if (direct) return direct;

  for (const field of ["level_id", "id", "levelId"]) {
    const textSnap = await db.collection("levels").where(field, "==", value).limit(1).get();
    if (!textSnap.empty) {
      const d = textSnap.docs[0];
      return { id: d.id, data: d.data() };
    }

    const numeric = Number(value);
    if (Number.isInteger(numeric)) {
      const numberSnap = await db.collection("levels").where(field, "==", numeric).limit(1).get();
      if (!numberSnap.empty) {
        const d = numberSnap.docs[0];
        return { id: d.id, data: d.data() };
      }
    }
  }

  return null;
}

async function levelPayload(identifier) {
  const found = await findLevel(identifier);
  if (!found) return null;

  const level = found.data;
  const creatorUid = level.uid || level.creator_uid || level.creator_user_id || level.user_id;
  const creatorProfile = creatorUid ? await findProfile(creatorUid) : null;

  return {
    id: found.id,
    name: level.name || level.title || "No level found",
    description: level.description || "no level",
    thumbnail_url: level.thumbnail_url || level.thumbnail || "",
    creator: creatorProfile?.data?.display_name || creatorProfile?.data?.username || level.creator || level.creator_username || "No creator found",
    creator_username: creatorProfile?.data?.username || level.creator_username || level.username || "no username",
    creator_user_id: creatorProfile?.data?.user_id || level.creator_user_id || level.user_id || "?",
    creator_uid: creatorProfile?.id || creatorUid || "",
    hearts: Number(level.hearts || 0),
    likes: Number(level.likes || 0),
    followers: Number(level.followers || 0),
    plays: Number(level.plays || 0),
    created_at: level.created_at || level.createdAt || null
  };
}

app.get("/api/levels", async (req, res) => {
  try {
    const levels = await readCollection("levels");
    levels.sort((a, b) =>
      (b.created_at?.toMillis?.() || 0) -
      (a.created_at?.toMillis?.() || 0)
    );
    res.json({ levels });
  } catch (e) {
    console.error(e);
    error(res, 500, "Failed to read levels.");
  }
});

app.get("/api/levels/:id", async (req, res) => {
  try {
    const level = await levelPayload(req.params.id);
    if (!level) return res.status(404).json({ found: false, level: null });
    res.json({ found: true, level });
  } catch (e) {
    console.error("Level:", e);
    error(res, 500, "Failed to read level.");
  }
});

app.post("/api/levels", async (req, res) => {
  try {
    const user = await requireUser(req, res);
    if (!user) return;

    const name = clean(req.body.name);
    if (!name) return error(res, 400, "Level name is required.");

    const profile = await readDoc("profiles", user.uid);
    if (!profile) return error(res, 404, "Your profile could not be found.");

    const userId = await ensureUserId(user.uid, profile.data);

    // READ EXISTING DATA FIRST
    const existing = await levelsForProfile(user.uid, profile.data, userId);
    const duplicate = existing.find(l => lower(l.name) === lower(name));

    if (duplicate) {
      return res.json({
        success: true,
        already_exists: true,
        level: await levelPayload(duplicate.id)
      });
    }

    const ref = db.collection("levels").doc();

    // WRITE
    await ref.set({
      level_id: ref.id,
      name,
      description: "no level",
      thumbnail_url: "",
      uid: user.uid,
      user_id: userId,
      creator_uid: user.uid,
      creator_user_id: userId,
      username: profile.data.username || "No username",
      creator_username: profile.data.username || "No username",
      creator: profile.data.display_name || profile.data.username || "No creator found",
      hearts: 0,
      likes: 0,
      followers: 0,
      plays: 0,
      created_at: FieldValue.serverTimestamp(),
      updated_at: FieldValue.serverTimestamp()
    });

    // READ BACK
    const saved = await levelPayload(ref.id);
    if (!saved) return error(res, 500, "Level was written but could not be read back.");

    res.json({ success: true, level: saved });
  } catch (e) {
    console.error(e);
    error(res, 500, "Failed to create level.");
  }
});

// ---------------- FOLLOW / FRIEND ----------------

app.post("/api/profiles/:id/follow", async (req, res) => {
  try {
    const user = await requireUser(req, res);
    if (!user) return;

    const target = await findProfile(req.params.id);
    if (!target) return error(res, 404, "Profile not found.");
    if (target.id === user.uid) return error(res, 400, "You cannot follow yourself.");

    const id = `${user.uid}_${target.id}`;
    const ref = db.collection("follows").doc(id);

    // READ FIRST
    const before = await ref.get();

    if (before.exists) {
      await ref.delete();
      const after = await ref.get();
      return res.json({ success: true, following: after.exists });
    }

    // WRITE
    await ref.set({
      follower_uid: user.uid,
      following_uid: target.id,
      created_at: FieldValue.serverTimestamp()
    });

    // READ BACK
    const after = await ref.get();
    res.json({ success: true, following: after.exists });
  } catch (e) {
    console.error(e);
    error(res, 500, "Failed to update follow.");
  }
});

app.post("/api/profiles/:id/friend", async (req, res) => {
  try {
    const user = await requireUser(req, res);
    if (!user) return;

    const target = await findProfile(req.params.id);
    if (!target) return error(res, 404, "Profile not found.");
    if (target.id === user.uid) return error(res, 400, "You cannot friend yourself.");

    const snapshot = await db.collection("friends")
      .where("users", "array-contains", user.uid).get();

    const existing = snapshot.docs.find(d =>
      (d.data().users || []).includes(target.id)
    );

    if (existing) {
      await existing.ref.delete();
      const after = await existing.ref.get();
      return res.json({ success: true, friends: after.exists });
    }

    const ref = db.collection("friends").doc(`${user.uid}_${target.id}`);

    await ref.set({
      users: [user.uid, target.id],
      created_at: FieldValue.serverTimestamp()
    });

    const after = await ref.get();
    res.json({ success: true, friends: after.exists });
  } catch (e) {
    console.error(e);
    error(res, 500, "Failed to update friendship.");
  }
});

// ---------------- GENERIC DATA ----------------

app.get("/api/data/:collection/:id", async (req, res) => {
  try {
    const result = await readDoc(req.params.collection, req.params.id);
    if (!result) return res.status(404).json({ found: false });

    res.json({ found: true, id: result.id, data: result.data });
  } catch (e) {
    console.error(e);
    error(res, 500, "Failed to read Firebase.");
  }
});

app.post("/api/data/:collection/:id", async (req, res) => {
  try {
    if (!req.body || typeof req.body !== "object") {
      return error(res, 400, "JSON body required.");
    }

    const ref = db.collection(req.params.collection).doc(req.params.id);

    // READ
    const before = await ref.get();

    // WRITE
    await ref.set({
      ...req.body,
      updatedAt: FieldValue.serverTimestamp()
    }, { merge: true });

    // READ BACK
    const after = await ref.get();

    res.json({
      success: true,
      existed_before: before.exists,
      found_after_write: after.exists,
      collection: req.params.collection,
      id: after.id,
      data: after.data()
    });
  } catch (e) {
    console.error(e);
    error(res, 500, "Failed to write Firebase.");
  }
});

app.delete("/api/data/:collection/:id", async (req, res) => {
  try {
    const ref = db.collection(req.params.collection).doc(req.params.id);
    const before = await ref.get();

    if (!before.exists) {
      return res.status(404).json({
        success: false,
        deleted: false,
        error: "Document not found."
      });
    }

    await ref.delete();

    const after = await ref.get();

    res.json({
      success: true,
      deleted: !after.exists,
      collection: req.params.collection,
      id: req.params.id
    });
  } catch (e) {
    console.error(e);
    error(res, 500, "Failed to delete Firebase document.");
  }
});

// ---------------- STATIC FILES ----------------

app.use(express.static(__dirname, { extensions: ["html"] }));

app.get(["/Level.html", "/level.html"], (req, res) =>
  res.sendFile(path.join(__dirname, "level.html"))
);

app.get(["/Profile.html", "/profile.html"], (req, res) =>
  res.sendFile(path.join(__dirname, "profile.html"))
);

app.get(["/Post.html", "/post.html"], (req, res) =>
  res.sendFile(path.join(__dirname, "post.html"))
);

app.get("/", (req, res) =>
  res.sendFile(path.join(__dirname, "index.html"))
);

app.use((req, res) =>
  res.status(404).json({ error: "Not Found" })
);

const PORT = Number(process.env.PORT) || 10000;

app.listen(PORT, "0.0.0.0", () => {
  console.log("========================================");
  console.log("LittleBigAdventure server started");
  console.log("Port: " + PORT);
  console.log("Firebase-first mode: ON");
  console.log("READ -> VALIDATE -> WRITE -> READ BACK");
  console.log("========================================");
});
