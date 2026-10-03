const express = require("express");
const path = require("path");
const cookieParser = require("cookie-parser");

const {
  initializeApp,
  cert,
  getApps
} = require("firebase-admin/app");

const { getAuth } = require("firebase-admin/auth");

const {
  getFirestore,
  FieldValue
} = require("firebase-admin/firestore");

// ==================================================
// FIREBASE ADMIN
// ==================================================

const serviceAccountRaw = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;

if (!serviceAccountRaw) {
  throw new Error("Missing FIREBASE_SERVICE_ACCOUNT_JSON");
}

let serviceAccount;

try {
  serviceAccount = JSON.parse(serviceAccountRaw);
} catch (error) {
  throw new Error("FIREBASE_SERVICE_ACCOUNT_JSON is not valid JSON");
}

if (!getApps().length) {
  initializeApp({
    credential: cert(serviceAccount)
  });
}

const db = getFirestore();
const auth = getAuth();

// ==================================================
// EXPRESS
// ==================================================

const app = express();

app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// ==================================================
// AUTH HELPERS
// ==================================================

async function getCurrentUser(req) {
  const sessionCookie = req.cookies?.session;

  if (sessionCookie) {
    try {
      return await auth.verifySessionCookie(sessionCookie, true);
    } catch (error) {
      // Continue to Bearer token.
    }
  }

  const authorization = req.headers.authorization || "";

  if (authorization.startsWith("Bearer ")) {
    try {
      return await auth.verifyIdToken(
        authorization.substring(7).trim()
      );
    } catch (error) {
      return null;
    }
  }

  const firebaseToken = req.headers["x-firebase-token"];

  if (firebaseToken) {
    try {
      return await auth.verifyIdToken(String(firebaseToken));
    } catch (error) {
      return null;
    }
  }

  return null;
}

async function requireUser(req, res) {
  const user = await getCurrentUser(req);

  if (!user) {
    res.status(401).json({
      error: "You must be logged in"
    });
    return null;
  }

  return user;
}

function cleanUsername(value) {
  return String(value || "")
    .trim()
    .replace(/[^a-zA-Z0-9_.-]/g, "")
    .slice(0, 30);
}

function cleanEmail(value) {
  return String(value || "").trim().toLowerCase();
}

function createPrivateAuthEmail(username) {
  return `${username.toLowerCase()}@lba.local`;
}

// ==================================================
// USER ID SYSTEM
// ==================================================
//
// New accounts receive a permanent numeric User ID.
// Existing older profiles without user_id are resolved by
// their original created_at order as a compatibility fallback.
//

async function getNextUserId() {
  const ref = db.collection("_system").doc("user_counter");

  return db.runTransaction(async transaction => {
    const snapshot = await transaction.get(ref);

    const current =
      snapshot.exists && Number(snapshot.data().next_id)
        ? Number(snapshot.data().next_id)
        : 1;

    transaction.set(
      ref,
      {
        next_id: current + 1,
        updated_at: FieldValue.serverTimestamp()
      },
      { merge: true }
    );

    return current;
  });
}

async function getProfileByUid(uid) {
  const snapshot = await db
    .collection("profiles")
    .doc(String(uid))
    .get();

  if (!snapshot.exists) {
    return null;
  }

  return {
    id: snapshot.id,
    ...snapshot.data()
  };
}

async function getProfileByNumericId(userId) {
  const numericId = Number(userId);

  if (!Number.isInteger(numericId) || numericId < 1) {
    return null;
  }

  // First use the permanent user_id field.
  const direct = await db
    .collection("profiles")
    .where("user_id", "==", numericId)
    .limit(1)
    .get();

  if (!direct.empty) {
    const doc = direct.docs[0];

    return {
      id: doc.id,
      ...doc.data()
    };
  }

  // Compatibility with accounts created before numeric IDs
  // were added: created_at order represents account order.
  try {
    const ordered = await db
      .collection("profiles")
      .orderBy("created_at", "asc")
      .get();

    if (numericId <= ordered.size) {
      const doc = ordered.docs[numericId - 1];

      return {
        id: doc.id,
        ...doc.data(),
        user_id: numericId
      };
    }
  } catch (error) {
    console.warn(
      "Could not resolve legacy numeric profile ID:",
      error.message
    );
  }

  return null;
}

async function getProfileByIdentifier(identifier) {
  const value = String(identifier || "").trim();

  if (!value) return null;

  // Firebase UID / document ID.
  const byUid = await getProfileByUid(value);

  if (byUid) {
    return byUid;
  }

  // Numeric User ID.
  if (/^\d+$/.test(value)) {
    return await getProfileByNumericId(value);
  }

  // Username compatibility.
  const usernameSnapshot = await db
    .collection("profiles")
    .where("username_lower", "==", value.toLowerCase())
    .limit(1)
    .get();

  if (!usernameSnapshot.empty) {
    const doc = usernameSnapshot.docs[0];

    return {
      id: doc.id,
      ...doc.data()
    };
  }

  return null;
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

    const snapshot = await ref.get();

    res.json({
      connected: true,
      firestore: true,
      data: snapshot.data()
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
// SESSION
// ==================================================

async function createSession(res, idToken) {
  const expiresIn = 1000 * 60 * 60 * 24 * 5;

  const sessionCookie = await auth.createSessionCookie(
    idToken,
    { expiresIn }
  );

  res.cookie("session", sessionCookie, {
    maxAge: expiresIn,
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    path: "/"
  });
}

// ==================================================
// SIGN UP
// ==================================================

app.post("/api/auth/signup", async (req, res) => {
  let userRecord = null;

  try {
    const username = cleanUsername(req.body.username);
    const password = String(req.body.password || "");
    const emailInput = cleanEmail(req.body.email);

    if (!username) {
      return res.status(400).json({
        error: "Username is required"
      });
    }

    if (username.length < 3) {
      return res.status(400).json({
        error: "Username must be at least 3 characters"
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        error: "Password must be at least 6 characters"
      });
    }

    if (
      emailInput &&
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailInput)
    ) {
      return res.status(400).json({
        error: "Please enter a valid email address"
      });
    }

    const existingProfile = await db
      .collection("profiles")
      .where(
        "username_lower",
        "==",
        username.toLowerCase()
      )
      .limit(1)
      .get();

    if (!existingProfile.empty) {
      return res.status(409).json({
        error: "Username is already taken"
      });
    }

    const authEmail =
      emailInput || createPrivateAuthEmail(username);

    userRecord = await auth.createUser({
      email: authEmail,
      password,
      displayName: username
    });

    // Reserve the numeric ID only after Firebase Auth succeeds.
    const userId = await getNextUserId();

    await db.collection("profiles").doc(userRecord.uid).set({
      uid: userRecord.uid,
      user_id: userId,
      username,
      username_lower: username.toLowerCase(),
      display_name: username,
      email: emailInput,
      auth_email: authEmail,
      bio: "",
      avatar_url: "",
      created_at: FieldValue.serverTimestamp(),
      updated_at: FieldValue.serverTimestamp()
    });

    const apiKey =
      process.env.FIREBASE_WEB_API_KEY ||
      "AIzaSyAKAvsFCZ840VtMEV7w1t-ie_uil-KWuCk";

    const signInResponse = await fetch(
      "https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=" +
        encodeURIComponent(apiKey),
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          email: authEmail,
          password,
          returnSecureToken: true
        })
      }
    );

    const signInData = await signInResponse.json();

    if (!signInResponse.ok || !signInData.idToken) {
      throw new Error(
        "Account created but login session could not be created"
      );
    }

    await createSession(res, signInData.idToken);

    res.status(201).json({
      success: true,
      user: {
        uid: userRecord.uid,
        user_id: userId,
        username,
        email: emailInput
      }
    });
  } catch (error) {
    console.error("Signup error:", error);

    if (userRecord) {
      try {
        await auth.deleteUser(userRecord.uid);
      } catch (deleteError) {
        console.error(
          "Could not roll back Firebase Auth user:",
          deleteError
        );
      }
    }

    res.status(500).json({
      success: false,
      error: "Failed to create account"
    });
  }
});

// ==================================================
// LOGIN
// ==================================================

app.post("/api/auth/login", async (req, res) => {
  try {
    const username = cleanUsername(req.body.username);
    const password = String(req.body.password || "");

    if (!username || !password) {
      return res.status(400).json({
        error: "Username and password are required"
      });
    }

    const profileQuery = await db
      .collection("profiles")
      .where(
        "username_lower",
        "==",
        username.toLowerCase()
      )
      .limit(1)
      .get();

    if (profileQuery.empty) {
      return res.status(401).json({
        error: "Invalid username or password"
      });
    }

    const profile = profileQuery.docs[0].data();

    const apiKey =
      process.env.FIREBASE_WEB_API_KEY ||
      "AIzaSyAKAvsFCZ840VtMEV7w1t-ie_uil-KWuCk";

    const response = await fetch(
      "https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=" +
        encodeURIComponent(apiKey),
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          email: profile.auth_email,
          password,
          returnSecureToken: true
        })
      }
    );

    const data = await response.json();

    if (!response.ok) {
      return res.status(401).json({
        error: "Invalid username or password"
      });
    }

    await createSession(res, data.idToken);

    res.json({
      success: true,
      user: {
        uid: data.localId,
        user_id: profile.user_id || null,
        username: profile.username,
        email: profile.email || ""
      }
    });
  } catch (error) {
    console.error("Login error:", error);

    res.status(500).json({
      success: false,
      error: "Login failed"
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
      return res.status(401).json({
        authenticated: false
      });
    }

    const profile = await getProfileByUid(user.uid);

    res.json({
      authenticated: true,
      user: {
        uid: user.uid,
        user_id: profile?.user_id || null,
        username:
          profile?.username ||
          user.name ||
          "",
        display_name:
          profile?.display_name ||
          profile?.username ||
          user.name ||
          "",
        email:
          profile?.email ||
          ""
      }
    });
  } catch (error) {
    console.error("Auth/me error:", error);

    res.status(500).json({
      authenticated: false,
      error: "Failed to get account"
    });
  }
});

// ==================================================
// LOGOUT
// ==================================================

app.post("/api/auth/logout", (req, res) => {
  res.clearCookie("session", {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    path: "/"
  });

  res.json({
    success: true
  });
});

// ==================================================
// PLAYERS
// ==================================================

app.get("/api/players", async (req, res) => {
  try {
    const snapshot = await db
      .collection("profiles")
      .orderBy("created_at", "desc")
      .limit(50)
      .get();

    const players = snapshot.docs.map(doc => {
      const data = doc.data();

      return {
        id: doc.id,
        uid: data.uid || doc.id,
        user_id: data.user_id || null,
        username: data.username || "",
        display_name:
          data.display_name ||
          data.username ||
          "",
        bio: data.bio || "",
        avatar_url: data.avatar_url || "",
        created_at: data.created_at || null
      };
    });

    res.json({ players });
  } catch (error) {
    console.error("Players error:", error);

    res.status(500).json({
      error: "Failed to load players",
      players: []
    });
  }
});

// ==================================================
// PROFILE
// Supports:
// /api/profile/1
// /api/profile/FIREBASE_UID
// /api/profile/username
// /api/profiles/1
// /api/profiles/FIREBASE_UID
// ==================================================

async function profileRoute(req, res) {
  try {
    const identifier = req.params.id;
    const profile = await getProfileByIdentifier(identifier);

    if (!profile) {
      return res.status(404).json({
        found: false,
        error: "Player not found"
      });
    }

    const userId =
      profile.user_id ||
      null;

    let profilePosts = [];

    if (userId !== null) {
      const profilePostsSnapshot = await db
        .collection("profile_posts")
        .where("profile_user_id", "==", Number(userId))
        .get();

      profilePosts = profilePostsSnapshot.docs.map(doc => ({
        id: doc.id,
        ...doc.data()
      }));
    }

    // Also support profile posts saved with uid instead of numeric ID.
    if (profilePosts.length === 0) {
      const byUidSnapshot = await db
        .collection("profile_posts")
        .where("profile_uid", "==", profile.uid || profile.id)
        .get();

      profilePosts = byUidSnapshot.docs.map(doc => ({
        id: doc.id,
        ...doc.data()
      }));
    }

    let levelsSnapshot;

    if (userId !== null) {
      levelsSnapshot = await db
        .collection("levels")
        .where(
          "creator_user_id",
          "==",
          Number(userId)
        )
        .get();
    } else {
      levelsSnapshot = await db
        .collection("levels")
        .where(
          "uid",
          "==",
          profile.uid || profile.id
        )
        .get();
    }

    // Compatibility for older levels that only have uid.
    if (levelsSnapshot.empty && (profile.uid || profile.id)) {
      levelsSnapshot = await db
        .collection("levels")
        .where(
          "uid",
          "==",
          profile.uid || profile.id
        )
        .get();
    }

    res.json({
      found: true,

      profile: {
        id: profile.id,
        uid: profile.uid || profile.id,
        user_id: userId,
        username: profile.username || "",
        display_name:
          profile.display_name ||
          profile.username ||
          "",
        bio: profile.bio || "",
        avatar_url: profile.avatar_url || "",
        email: profile.email || "",
        created_at: profile.created_at || null
      },

      posts: profilePosts,

      levels: levelsSnapshot.docs.map(doc => ({
        id: doc.id,
        ...doc.data()
      }))
    });
  } catch (error) {
    console.error("Profile read error:", error);

    res.status(500).json({
      found: false,
      error: "Failed to load profile"
    });
  }
}

app.get("/api/profile/:id", profileRoute);
app.get("/api/profiles/:id", profileRoute);

// ==================================================
// PROFILE UPDATE
// ==================================================

app.post("/api/profile/update", async (req, res) => {
  const user = await requireUser(req, res);

  if (!user) return;

  try {
    const updates = {
      updated_at: FieldValue.serverTimestamp()
    };

    if (req.body.display_name !== undefined) {
      updates.display_name =
        String(req.body.display_name)
          .trim()
          .slice(0, 40);
    }

    if (req.body.bio !== undefined) {
      updates.bio =
        String(req.body.bio)
          .trim()
          .slice(0, 500);
    }

    if (req.body.avatar_url !== undefined) {
      updates.avatar_url =
        String(req.body.avatar_url)
          .trim()
          .slice(0, 1000);
    }

    await db
      .collection("profiles")
      .doc(user.uid)
      .set(updates, { merge: true });

    res.json({
      success: true
    });
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
    const snapshot = await db
      .collection("posts")
      .orderBy("created_at", "desc")
      .limit(50)
      .get();

    const posts = snapshot.docs.map(doc => {
      const data = doc.data();

      return {
        id: doc.id,
        author: data.author || data.username || "",
        username: data.username || data.author || "",
        text: data.text || "",
        uid: data.uid || data.authorUid || "",
        user_id: data.user_id || null,
        avatar_url: data.avatar_url || "",
        created_at: data.created_at || data.createdAt || null
      };
    });

    res.json({ posts });
  } catch (error) {
    console.error("Posts read error:", error);

    res.status(500).json({
      error: "Failed to load posts",
      posts: []
    });
  }
});

app.get("/api/posts/:id", async (req, res) => {
  try {
    const postId = String(req.params.id);

    const snapshot = await db
      .collection("posts")
      .doc(postId)
      .get();

    if (!snapshot.exists) {
      return res.status(404).json({
        found: false,
        id: postId,
        title: "No post found",
        author: "No username found",
        text: "no post",
        replies: []
      });
    }

    const data = snapshot.data();

    const repliesSnapshot = await db
      .collection("post_replies")
      .where("post_id", "==", postId)
      .get();

    const replies = repliesSnapshot.docs.map(doc => ({
      id: doc.id,
      ...doc.data()
    }));

    res.json({
      found: true,

      post: {
        id: snapshot.id,
        title:
          data.title ||
          data.text?.slice(0, 80) ||
          "Post",
        author:
          data.author ||
          data.username ||
          "No username found",
        author_username:
          data.username ||
          data.author ||
          "no username",
        author_user_id:
          data.user_id ||
          null,
        uid:
          data.uid ||
          data.authorUid ||
          "",
        avatar_url:
          data.avatar_url ||
          "",
        text:
          data.text ||
          data.message ||
          "no post",
        created_at:
          data.created_at ||
          data.createdAt ||
          null
      },

      replies
    });
  } catch (error) {
    console.error("Post read error:", error);

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
    const text = String(req.body.text || "").trim();

    if (!text) {
      return res.status(400).json({
        error: "Post text is required"
      });
    }

    if (text.length > 2000) {
      return res.status(400).json({
        error: "Post is too long"
      });
    }

    const profile = await getProfileByUid(user.uid);

    const username =
      profile?.username ||
      user.name ||
      user.email ||
      "Player";

    const postRef = db.collection("posts").doc();

    await postRef.set({
      uid: user.uid,
      user_id: profile?.user_id || null,
      author: username,
      username,
      avatar_url: profile?.avatar_url || "",
      text,
      created_at: FieldValue.serverTimestamp()
    });

    res.status(201).json({
      success: true,
      id: postRef.id
    });
  } catch (error) {
    console.error("Post create error:", error);

    res.status(500).json({
      success: false,
      error: "Failed to create post"
    });
  }
});

// ==================================================
// POST REPLIES
// ==================================================

app.post("/api/posts/:id/replies", async (req, res) => {
  const user = await requireUser(req, res);

  if (!user) return;

  try {
    const postId = String(req.params.id);

    const postSnapshot = await db
      .collection("posts")
      .doc(postId)
      .get();

    if (!postSnapshot.exists) {
      return res.status(404).json({
        error: "Post not found"
      });
    }

    const text = String(req.body.text || "").trim();

    if (!text) {
      return res.status(400).json({
        error: "Reply text is required"
      });
    }

    if (text.length > 2000) {
      return res.status(400).json({
        error: "Reply is too long"
      });
    }

    const profile = await getProfileByUid(user.uid);

    const replyRef = db
      .collection("post_replies")
      .doc();

    await replyRef.set({
      post_id: postId,
      uid: user.uid,
      user_id: profile?.user_id || null,
      author:
        profile?.display_name ||
        profile?.username ||
        user.name ||
        "Player",
      username:
        profile?.username ||
        user.name ||
        "Player",
      avatar_url:
        profile?.avatar_url ||
        "",
      text,
      created_at: FieldValue.serverTimestamp()
    });

    res.status(201).json({
      success: true,
      id: replyRef.id
    });
  } catch (error) {
    console.error("Reply create error:", error);

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
    const snapshot = await db
      .collection("levels")
      .orderBy("created_at", "desc")
      .limit(100)
      .get();

    const levels = snapshot.docs.map(doc => {
      const data = doc.data();

      return {
        id: doc.id,
        name:
          data.name ||
          data.title ||
          "",
        creator:
          data.creator ||
          data.username ||
          "",
        creator_username:
          data.creator_username ||
          data.username ||
          data.creator ||
          "",
        creator_user_id:
          data.creator_user_id ||
          data.user_id ||
          null,
        uid:
          data.uid ||
          data.creatorUid ||
          "",
        description:
          data.description ||
          "",
        thumbnail_url:
          data.thumbnail_url ||
          "",
        hearts:
          data.hearts || 0,
        likes:
          data.likes || 0,
        followers:
          data.followers || 0,
        plays:
          data.plays || 0,
        created_at:
          data.created_at ||
          data.createdAt ||
          null
      };
    });

    res.json({ levels });
  } catch (error) {
    console.error("Levels read error:", error);

    res.status(500).json({
      error: "Failed to load levels",
      levels: []
    });
  }
});

app.get("/api/levels/:id", async (req, res) => {
  try {
    const levelId = String(req.params.id);

    const snapshot = await db
      .collection("levels")
      .doc(levelId)
      .get();

    if (!snapshot.exists) {
      return res.status(404).json({
        found: false,
        id: levelId,
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

    const data = snapshot.data();

    res.json({
      found: true,
      id: snapshot.id,
      name:
        data.name ||
        data.title ||
        "No level found",
      title:
        data.title ||
        data.name ||
        "No level found",
      description:
        data.description ||
        "no level",
      creator:
        data.creator ||
        data.username ||
        "No creator found",
      creator_username:
        data.creator_username ||
        data.username ||
        data.creator ||
        "no username",
      creator_user_id:
        data.creator_user_id ||
        data.user_id ||
        "?",
      uid:
        data.uid ||
        data.creatorUid ||
        "",
      thumbnail_url:
        data.thumbnail_url ||
        "",
      hearts:
        data.hearts || 0,
      likes:
        data.likes || 0,
      followers:
        data.followers || 0,
      plays:
        data.plays || 0,
      created_at:
        data.created_at ||
        data.createdAt ||
        null
    });
  } catch (error) {
    console.error("Level read error:", error);

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
    const name = String(req.body.name || "").trim();
    const description =
      String(req.body.description || "").trim();

    if (!name) {
      return res.status(400).json({
        error: "Level name is required"
      });
    }

    if (name.length > 120) {
      return res.status(400).json({
        error: "Level name is too long"
      });
    }

    const profile = await getProfileByUid(user.uid);

    const username =
      profile?.username ||
      user.name ||
      user.email ||
      "Player";

    const levelRef = db.collection("levels").doc();

    await levelRef.set({
      uid: user.uid,
      creator_user_id: profile?.user_id || null,
      name,
      title: name,
      creator: username,
      creator_username: username,
      username,
      description,
      thumbnail_url:
        String(req.body.thumbnail_url || "").trim(),
      hearts: 0,
      likes: 0,
      followers: 0,
      plays: 0,
      created_at: FieldValue.serverTimestamp(),
      updated_at: FieldValue.serverTimestamp()
    });

    res.status(201).json({
      success: true,
      id: levelRef.id
    });
  } catch (error) {
    console.error("Level create error:", error);

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
    const snapshot = await db
      .collection(req.params.collection)
      .doc(req.params.id)
      .get();

    if (!snapshot.exists) {
      return res.status(404).json({
        found: false
      });
    }

    res.json({
      found: true,
      id: snapshot.id,
      data: snapshot.data()
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
    const { collection, id } = req.params;

    if (
      !req.body ||
      typeof req.body !== "object" ||
      Array.isArray(req.body)
    ) {
      return res.status(400).json({
        error: "JSON object required"
      });
    }

    await db
      .collection(collection)
      .doc(id)
      .set(
        {
          ...req.body,
          updatedAt: FieldValue.serverTimestamp()
        },
        { merge: true }
      );

    res.json({
      success: true,
      collection,
      id
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
    const { collection, id } = req.params;

    await db
      .collection(collection)
      .doc(id)
      .delete();

    res.json({
      success: true,
      deleted: true,
      collection,
      id
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
// PAGE ROUTES
// ==================================================
//
// Support both lowercase and uppercase filenames/URLs.
// This matters on Render/Linux because filenames are case-sensitive.
//

const publicPath = path.join(__dirname);

app.use(express.static(publicPath));

app.get(["/level.html", "/Level.html"], (req, res) => {
  res.sendFile(path.join(publicPath, "level.html"), error => {
    if (error) {
      res.sendFile(path.join(publicPath, "Level.html"));
    }
  });
});

app.get(["/profile.html", "/Profile.html"], (req, res) => {
  res.sendFile(path.join(publicPath, "profile.html"), error => {
    if (error) {
      res.sendFile(path.join(publicPath, "Profile.html"));
    }
  });
});

app.get(["/post.html", "/Post.html"], (req, res) => {
  res.sendFile(path.join(publicPath, "post.html"), error => {
    if (error) {
      res.sendFile(path.join(publicPath, "Post.html"));
    }
  });
});

app.get("/", (req, res) => {
  res.sendFile(path.join(publicPath, "index.html"));
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
  console.log("Profiles: numeric ID + UID supported");
  console.log("Posts: exact post ID supported");
  console.log("Levels: exact level ID supported");
  console.log("========================================");
});
