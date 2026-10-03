const express = require("express");
const cookieParser = require("cookie-parser");

const { initializeApp, cert } = require("firebase-admin/app");
const { getAuth } = require("firebase-admin/auth");
const { getFirestore, FieldValue } = require("firebase-admin/firestore");

// ==================================================
// FIREBASE ADMIN
// ==================================================

if (!process.env.FIREBASE_SERVICE_ACCOUNT_JSON) {
  throw new Error("Missing FIREBASE_SERVICE_ACCOUNT_JSON");
}

let serviceAccount;

try {
  serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_JSON);
} catch {
  throw new Error("FIREBASE_SERVICE_ACCOUNT_JSON is not valid JSON");
}

initializeApp({
  credential: cert(serviceAccount)
});

const auth = getAuth();
const db = getFirestore();

// ==================================================
// EXPRESS
// ==================================================

const app = express();

app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// ==================================================
// HELPERS
// ==================================================

function clean(value) {
  return String(value ?? "").trim();
}

async function getCurrentUser(req) {
  try {
    const session = req.cookies?.session;

    if (session) {
      return await auth.verifySessionCookie(session, true);
    }

    const authorization = req.headers.authorization || "";

    if (authorization.startsWith("Bearer ")) {
      return await auth.verifyIdToken(
        authorization.substring(7)
      );
    }

    const token = req.headers["x-firebase-token"];

    if (token) {
      return await auth.verifyIdToken(token);
    }

    return null;
  } catch {
    return null;
  }
}

async function requireUser(req, res) {
  const user = await getCurrentUser(req);

  if (!user) {
    res.status(401).json({
      success: false,
      error: "You must be logged in"
    });
    return null;
  }

  return user;
}

async function getProfileByUid(uid) {
  const snap = await db.collection("profiles").doc(uid).get();

  if (!snap.exists) return null;

  return {
    id: snap.id,
    ...snap.data()
  };
}

async function getProfileByUserId(userId) {
  const numberId = Number(userId);

  if (!Number.isInteger(numberId)) return null;

  const snap = await db
    .collection("profiles")
    .where("user_id", "==", numberId)
    .limit(1)
    .get();

  if (snap.empty) return null;

  return {
    id: snap.docs[0].id,
    ...snap.docs[0].data()
  };
}

async function findProfileByUsername(username) {
  const usernameLower = clean(username).toLowerCase();

  const snap = await db
    .collection("profiles")
    .where("username_lower", "==", usernameLower)
    .limit(1)
    .get();

  if (snap.empty) return null;

  return {
    id: snap.docs[0].id,
    ...snap.docs[0].data()
  };
}

async function getNextUserId() {
  const ref = db.collection("_system").doc("user_counter");

  return db.runTransaction(async transaction => {
    const snap = await transaction.get(ref);

    const nextId =
      snap.exists && Number(snap.data().next_id)
        ? Number(snap.data().next_id)
        : 1;

    transaction.set(
      ref,
      {
        next_id: nextId + 1,
        updated_at: FieldValue.serverTimestamp()
      },
      { merge: true }
    );

    return nextId;
  });
}

// ==================================================
// STATUS
// ==================================================

app.get("/api/status", (req, res) => {
  res.json({
    online: true,
    service: "LittleBigAdventure",
    firebase: true
  });
});

// ==================================================
// FIREBASE TEST
// ==================================================

app.get("/api/firebase-test", async (req, res) => {
  try {
    const ref = db.collection("_system").doc("server");

    await ref.set(
      {
        online: true,
        service: "LittleBigAdventure",
        updatedAt: FieldValue.serverTimestamp()
      },
      { merge: true }
    );

    const snap = await ref.get();

    res.json({
      connected: true,
      firestore: true,
      data: snap.data()
    });
  } catch (error) {
    console.error("Firebase error:", error);

    res.status(500).json({
      connected: false,
      firestore: false,
      error: "Firebase connection failed"
    });
  }
});

// ==================================================
// SIGN UP
// ==================================================

app.post("/api/auth/signup", async (req, res) => {
  try {
    const username = clean(req.body.username);
    const password = String(req.body.password || "");
    const email = clean(req.body.email);

    if (!username) {
      return res.status(400).json({
        success: false,
        error: "Username is required"
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        success: false,
        error: "Password must be at least 6 characters"
      });
    }

    const existing = await findProfileByUsername(username);

    if (existing) {
      return res.status(409).json({
        success: false,
        error: "Username is already taken"
      });
    }

    const userId = await getNextUserId();

    const user = await auth.createUser({
      ...(email ? { email } : {}),
      password,
      displayName: username
    });

    await db.collection("profiles").doc(user.uid).set({
      uid: user.uid,
      user_id: userId,
      username,
      username_lower: username.toLowerCase(),
      display_name: username,
      email: email || "",
      auth_email: user.email || "",
      bio: "",
      avatar_url: "",
      created_at: FieldValue.serverTimestamp(),
      updated_at: FieldValue.serverTimestamp()
    });

    res.json({
      success: true,
      user: {
        uid: user.uid,
        user_id: userId,
        username,
        display_name: username,
        email: email || "",
        bio: "",
        avatar_url: ""
      }
    });
  } catch (error) {
    console.error("Signup error:", error);

    res.status(500).json({
      success: false,
      error: error.message || "Failed to create account"
    });
  }
});

// ==================================================
// CURRENT USER
// ==================================================

app.get("/api/auth/me", async (req, res) => {
  try {
    const user = await getCurrentUser(req);

    if (!user) {
      return res.json({ loggedIn: false });
    }

    const profile = await getProfileByUid(user.uid);

    res.json({
      loggedIn: true,
      user: profile || {
        uid: user.uid,
        email: user.email || ""
      }
    });
  } catch {
    res.json({ loggedIn: false });
  }
});

// ==================================================
// LOGOUT
// ==================================================

app.post("/api/auth/logout", (req, res) => {
  res.clearCookie("session");

  res.json({
    success: true
  });
});

// ==================================================
// PROFILES
// ==================================================

app.get("/api/profiles/:id", async (req, res) => {
  try {
    const profile = await getProfileByUserId(req.params.id);

    if (!profile) {
      return res.status(404).json({
        found: false,
        error: "Profile not found"
      });
    }

    const postsSnap = await db
      .collection("profile_posts")
      .where("profile_user_id", "==", Number(profile.user_id))
      .get();

    const levelsSnap = await db
      .collection("levels")
      .where("creator_user_id", "==", Number(profile.user_id))
      .get();

    res.json({
      found: true,
      profile: {
        user_id: profile.user_id,
        username: profile.username || "",
        display_name: profile.display_name || profile.username || "",
        bio: profile.bio || "",
        avatar_url: profile.avatar_url || "",
        created_at: profile.created_at || null
      },
      posts: postsSnap.docs.map(doc => ({
        id: doc.id,
        ...doc.data()
      })),
      levels: levelsSnap.docs.map(doc => ({
        id: doc.id,
        ...doc.data()
      }))
    });
  } catch (error) {
    console.error("Profile error:", error);

    res.status(500).json({
      found: false,
      error: "Failed to load profile"
    });
  }
});

app.post("/api/profile/update", async (req, res) => {
  const user = await requireUser(req, res);
  if (!user) return;

  try {
    const updates = {
      updated_at: FieldValue.serverTimestamp()
    };

    if (req.body.display_name !== undefined) {
      updates.display_name = clean(req.body.display_name).slice(0, 40);
    }

    if (req.body.bio !== undefined) {
      updates.bio = clean(req.body.bio).slice(0, 500);
    }

    if (req.body.avatar_url !== undefined) {
      updates.avatar_url = clean(req.body.avatar_url).slice(0, 1000);
    }

    await db
      .collection("profiles")
      .doc(user.uid)
      .set(updates, { merge: true });

    res.json({ success: true });
  } catch (error) {
    console.error("Profile update error:", error);

    res.status(500).json({
      success: false,
      error: "Failed to update profile"
    });
  }
});

// ==================================================
// POSTS
// ==================================================

app.get("/api/posts", async (req, res) => {
  try {
    const snap = await db
      .collection("posts")
      .orderBy("created_at", "desc")
      .limit(50)
      .get();

    res.json({
      found: true,
      posts: snap.docs.map(doc => ({
        id: doc.id,
        ...doc.data()
      }))
    });
  } catch (error) {
    console.error("Posts error:", error);

    res.status(500).json({
      found: false,
      posts: []
    });
  }
});

app.get("/api/posts/:id", async (req, res) => {
  try {
    const snap = await db
      .collection("posts")
      .doc(String(req.params.id))
      .get();

    if (!snap.exists) {
      return res.status(404).json({
        found: false,
        title: "No post found",
        author: "No username found",
        text: "no post",
        replies: []
      });
    }

    const repliesSnap = await db
      .collection("post_replies")
      .where("post_id", "==", String(req.params.id))
      .get();

    res.json({
      found: true,
      post: {
        id: snap.id,
        ...snap.data()
      },
      replies: repliesSnap.docs.map(doc => ({
        id: doc.id,
        ...doc.data()
      }))
    });
  } catch (error) {
    console.error("Post error:", error);

    res.status(500).json({
      found: false,
      error: "Failed to load post"
    });
  }
});

app.post("/api/posts", async (req, res) => {
  const user = await requireUser(req, res);
  if (!user) return;

  try {
    const profile = await getProfileByUid(user.uid);
    const text = clean(req.body.text);

    if (!text) {
      return res.status(400).json({
        success: false,
        error: "Post text is required"
      });
    }

    const ref = db.collection("posts").doc();

    await ref.set({
      uid: user.uid,
      user_id: profile?.user_id || null,
      author: profile?.display_name || profile?.username || "Player",
      avatar_url: profile?.avatar_url || "",
      text: text.slice(0, 2000),
      created_at: FieldValue.serverTimestamp()
    });

    res.json({
      success: true,
      id: ref.id
    });
  } catch (error) {
    console.error("Create post error:", error);

    res.status(500).json({
      success: false,
      error: "Failed to create post"
    });
  }
});

app.post("/api/posts/:id/replies", async (req, res) => {
  const user = await requireUser(req, res);
  if (!user) return;

  try {
    const postSnap = await db
      .collection("posts")
      .doc(String(req.params.id))
      .get();

    if (!postSnap.exists) {
      return res.status(404).json({
        success: false,
        error: "Post not found"
      });
    }

    const profile = await getProfileByUid(user.uid);
    const text = clean(req.body.text);

    if (!text) {
      return res.status(400).json({
        success: false,
        error: "Reply text is required"
      });
    }

    const ref = db.collection("post_replies").doc();

    await ref.set({
      post_id: String(req.params.id),
      uid: user.uid,
      user_id: profile?.user_id || null,
      author: profile?.display_name || profile?.username || "Player",
      avatar_url: profile?.avatar_url || "",
      text: text.slice(0, 2000),
      created_at: FieldValue.serverTimestamp()
    });

    res.json({
      success: true,
      id: ref.id
    });
  } catch (error) {
    console.error("Reply error:", error);

    res.status(500).json({
      success: false,
      error: "Failed to create reply"
    });
  }
});

// ==================================================
// LEVELS
// ==================================================

app.get("/api/levels", async (req, res) => {
  try {
    const snap = await db
      .collection("levels")
      .orderBy("created_at", "desc")
      .limit(50)
      .get();

    res.json({
      found: true,
      levels: snap.docs.map(doc => ({
        id: doc.id,
        ...doc.data()
      }))
    });
  } catch (error) {
    console.error("Levels error:", error);

    res.status(500).json({
      found: false,
      levels: []
    });
  }
});

app.get("/api/levels/:id", async (req, res) => {
  try {
    const snap = await db
      .collection("levels")
      .doc(String(req.params.id))
      .get();

    if (!snap.exists) {
      return res.status(404).json({
        found: false,
        id: req.params.id,
        name: "No level found",
        description: "no level",
        creator: "No creator found",
        creator_username: "no username",
        creator_user_id: "?",
        hearts: 0,
        likes: 0,
        followers: 0,
        plays: 0
      });
    }

    res.json({
      found: true,
      id: snap.id,
      ...snap.data()
    });
  } catch (error) {
    console.error("Level error:", error);

    res.status(500).json({
      found: false,
      error: "Failed to load level"
    });
  }
});

app.post("/api/levels", async (req, res) => {
  const user = await requireUser(req, res);
  if (!user) return;

  try {
    const profile = await getProfileByUid(user.uid);
    const name = clean(req.body.name);

    if (!name) {
      return res.status(400).json({
        success: false,
        error: "Level name is required"
      });
    }

    const ref = db.collection("levels").doc();

    await ref.set({
      name: name.slice(0, 100),
      description: clean(req.body.description).slice(0, 2000),
      thumbnail_url: clean(req.body.thumbnail_url).slice(0, 1000),
      uid: user.uid,
      creator_user_id: profile?.user_id || null,
      creator: profile?.display_name || profile?.username || "Player",
      creator_username: profile?.username || "Player",
      hearts: 0,
      likes: 0,
      followers: 0,
      plays: 0,
      created_at: FieldValue.serverTimestamp(),
      updated_at: FieldValue.serverTimestamp()
    });

    res.json({
      success: true,
      id: ref.id
    });
  } catch (error) {
    console.error("Create level error:", error);

    res.status(500).json({
      success: false,
      error: "Failed to create level"
    });
  }
});

// ==================================================
// GENERIC FIRESTORE API
// ==================================================

app.get("/api/data/:collection/:id", async (req, res) => {
  try {
    const snap = await db
      .collection(req.params.collection)
      .doc(req.params.id)
      .get();

    if (!snap.exists) {
      return res.status(404).json({ found: false });
    }

    res.json({
      found: true,
      id: snap.id,
      data: snap.data()
    });
  } catch (error) {
    console.error("Firestore read error:", error);

    res.status(500).json({
      found: false,
      error: "Failed to read Firestore"
    });
  }
});

app.post("/api/data/:collection/:id", async (req, res) => {
  const user = await requireUser(req, res);
  if (!user) return;

  try {
    await db
      .collection(req.params.collection)
      .doc(req.params.id)
      .set(
        {
          ...req.body,
          updatedAt: FieldValue.serverTimestamp()
        },
        { merge: true }
      );

    res.json({
      success: true,
      collection: req.params.collection,
      id: req.params.id
    });
  } catch (error) {
    console.error("Firestore write error:", error);

    res.status(500).json({
      success: false,
      error: "Failed to write Firestore"
    });
  }
});

app.delete("/api/data/:collection/:id", async (req, res) => {
  const user = await requireUser(req, res);
  if (!user) return;

  try {
    await db
      .collection(req.params.collection)
      .doc(req.params.id)
      .delete();

    res.json({
      success: true,
      deleted: true,
      collection: req.params.collection,
      id: req.params.id
    });
  } catch (error) {
    console.error("Firestore delete error:", error);

    res.status(500).json({
      success: false,
      error: "Failed to delete Firestore document"
    });
  }
});

// ==================================================
// STATIC WEBSITE
// ==================================================

app.use(express.static(__dirname));

app.get("/", (req, res) => {
  res.sendFile(__dirname + "/index.html");
});

// ==================================================
// 404
// ==================================================

app.use((req, res) => {
  res.status(404).json({
    error: "Not Found"
  });
});

// ==================================================
// START SERVER
// ==================================================

const PORT = process.env.PORT || 10000;

app.listen(PORT, "0.0.0.0", () => {
  console.log("========================================");
  console.log("LittleBigAdventure server started");
  console.log("Port: " + PORT);
  console.log("Firebase Admin: connected");
  console.log("========================================");
});
