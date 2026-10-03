const express = require("express");
const path = require("path");
const cookieParser = require("cookie-parser");

const { initializeApp, cert } = require("firebase-admin/app");
const { getAuth } = require("firebase-admin/auth");
const {
  getFirestore,
  FieldValue
} = require("firebase-admin/firestore");

// ==================================================
// LittleBigAdventure
// Firebase-first server
//
// Flow:
// Browser -> Render server -> Firebase
//
// For important Firebase operations the server:
// 1. connects
// 2. reads current data
// 3. validates it
// 4. writes
// 5. reads back to verify
// 6. retries if the operation fails
// ==================================================

const app = express();

app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// ==================================================
// SETTINGS
// ==================================================

const PORT = process.env.PORT || 10000;
const RETRIES = Math.max(1, Number(process.env.FIREBASE_RETRIES || 3));
const RETRY_DELAY = Math.max(100, Number(process.env.FIREBASE_RETRY_DELAY_MS || 700));

const SESSION_COOKIE = "lba_session";
const SERVICE_NAME = "LittleBigAdventure";

// ==================================================
// FIREBASE ADMIN
// ==================================================

if (!process.env.FIREBASE_SERVICE_ACCOUNT_JSON) {
  throw new Error("Missing FIREBASE_SERVICE_ACCOUNT_JSON");
}

let serviceAccount;

try {
  serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_JSON);
} catch (error) {
  throw new Error("FIREBASE_SERVICE_ACCOUNT_JSON is not valid JSON");
}

initializeApp({
  credential: cert(serviceAccount)
});

const auth = getAuth();
const db = getFirestore();

// ==================================================
// HELPERS
// ==================================================

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function errorMessage(error) {
  return error && error.message ? error.message : String(error);
}

function isRetryable(error) {
  const code = String(
    error?.code ||
    error?.status ||
    error?.response?.status ||
    ""
  ).toLowerCase();

  const message = errorMessage(error).toLowerCase();

  if (code.includes("permission-denied")) return false;
  if (code.includes("unauthenticated")) return false;
  if (code.includes("invalid-argument")) return false;
  if (code.includes("not-found")) return false;
  if (code.includes("already-exists")) return false;

  if (message.includes("invalid password")) return false;
  if (message.includes("invalid username")) return false;
  if (message.includes("email already exists")) return false;

  return true;
}

// Run a Firebase operation again when it fails.
// This is deliberately small and predictable so Render does not get
// stuck in an endless retry loop.
async function firebaseRetry(label, operation, attempts = RETRIES) {
  let lastError;

  for (let attempt = 1; attempt <= attempts; attempt++) {
    try {
      return await operation();
    } catch (error) {
      lastError = error;

      console.error(
        `[Firebase] ${label} failed (${attempt}/${attempts}):`,
        errorMessage(error)
      );

      if (attempt >= attempts || !isRetryable(error)) {
        break;
      }

      await sleep(RETRY_DELAY * attempt);
    }
  }

  throw lastError;
}

// Read a Firestore document with retries.
async function readDoc(collection, id) {
  return firebaseRetry(
    `READ ${collection}/${id}`,
    async () => {
      const snapshot = await db.collection(collection).doc(String(id)).get();
      return snapshot;
    }
  );
}

// Write a Firestore document and immediately read it back.
// This is the main "make sure it actually worked" mechanism.
async function writeDocAndVerify(collection, id, data, options = {}) {
  return firebaseRetry(
    `WRITE+VERIFY ${collection}/${id}`,
    async () => {
      const ref = db.collection(collection).doc(String(id));

      await ref.set(data, options);

      const check = await ref.get();

      if (!check.exists) {
        throw new Error(
          `Firebase write verification failed for ${collection}/${id}`
        );
      }

      return check;
    }
  );
}

// Delete and verify the document is gone.
async function deleteDocAndVerify(collection, id) {
  return firebaseRetry(
    `DELETE+VERIFY ${collection}/${id}`,
    async () => {
      const ref = db.collection(collection).doc(String(id));

      await ref.delete();

      const check = await ref.get();

      if (check.exists) {
        throw new Error(
          `Firebase delete verification failed for ${collection}/${id}`
        );
      }

      return true;
    }
  );
}

function clean(value, fallback = "") {
  if (value === undefined || value === null) return fallback;
  return String(value).trim();
}

function normalizeUsername(value) {
  return clean(value).toLowerCase();
}

function publicProfile(data, idOverride = null) {
  if (!data) return null;

  return {
    id: data.user_id ?? idOverride ?? data.uid ?? null,
    user_id: data.user_id ?? idOverride ?? null,
    uid: data.uid ?? null,
    username: data.username || data.display_name || "No username found",
    display_name: data.display_name || data.username || "No username found",
    bio: data.bio || "no username",
    avatar_url: data.avatar_url || "",
    created_at: data.created_at || null,
    updated_at: data.updated_at || null,
    followers: Number(data.followers || 0),
    following: Number(data.following || 0),
    friends: Number(data.friends || 0)
  };
}

function publicLevel(data, id) {
  if (!data) return null;

  return {
    id: data.id || data.level_id || id,
    level_id: data.level_id || data.id || id,
    name: data.name || "No level found",
    description: data.description || "no level",
    thumbnail_url: data.thumbnail_url || data.thumbnail || "",
    creator: data.creator || data.creator_username || data.username || "No creator found",
    creator_username: data.creator_username || data.creator || data.username || "no username",
    creator_user_id:
      data.creator_user_id ??
      data.user_id ??
      data.uid ??
      "?",
    creator_uid: data.creator_uid || data.uid || "",
    hearts: Number(data.hearts || 0),
    likes: Number(data.likes || 0),
    followers: Number(data.followers || 0),
    plays: Number(data.plays || 0),
    created_at: data.created_at || null,
    updated_at: data.updated_at || null
  };
}

function publicPost(data, id) {
  if (!data) return null;

  return {
    id: data.id || data.post_id || id,
    post_id: data.post_id || data.id || id,
    uid: data.uid || "",
    user_id: data.user_id || data.profile_user_id || data.uid || "?",
    author: data.author || data.username || "No username found",
    username: data.username || data.author || "No username found",
    avatar_url: data.avatar_url || "",
    title: data.title || "",
    text: data.text || data.content || "no post",
    content: data.content || data.text || "no post",
    created_at: data.created_at || data.date || null,
    updated_at: data.updated_at || null
  };
}

// ==================================================
// AUTH HELPERS
// ==================================================

async function getCurrentUser(req) {
  const session = req.cookies?.[SESSION_COOKIE];

  if (session) {
    try {
      return await firebaseRetry(
        "VERIFY SESSION",
        () => auth.verifySessionCookie(session, true)
      );
    } catch (error) {
      // Continue and try bearer headers.
    }
  }

  const header = req.headers.authorization || "";
  const firebaseToken =
    header.startsWith("Bearer ")
      ? header.slice(7)
      : req.headers["x-firebase-token"];

  if (!firebaseToken) {
    return null;
  }

  try {
    return await firebaseRetry(
      "VERIFY FIREBASE TOKEN",
      () => auth.verifyIdToken(String(firebaseToken), true)
    );
  } catch (error) {
    return null;
  }
}

async function requireUser(req, res) {
  const user = await getCurrentUser(req);

  if (!user) {
    res.status(401).json({
      success: false,
      error: "Login required"
    });
    return null;
  }

  return user;
}

async function createSession(res, idToken) {
  const expiresIn = 1000 * 60 * 60 * 24 * 5;

  const sessionCookie = await firebaseRetry(
    "CREATE SESSION COOKIE",
    () => auth.createSessionCookie(idToken, { expiresIn })
  );

  res.cookie(SESSION_COOKIE, sessionCookie, {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    maxAge: expiresIn,
    path: "/"
  });
}

// ==================================================
// FIREBASE WEB AUTH REST
// ==================================================

async function signInWithPassword(email, password) {
  const apiKey =
    process.env.FIREBASE_WEB_API_KEY ||
    "AIzaSyAKAvsFCZ840VtMEV7w1t-ie_uil-KWuCk";

  if (!apiKey) {
    throw new Error("Missing FIREBASE_WEB_API_KEY");
  }

  return firebaseRetry(
    "FIREBASE PASSWORD SIGN-IN",
    async () => {
      const response = await fetch(
        `https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${encodeURIComponent(apiKey)}`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json"
          },
          body: JSON.stringify({
            email,
            password,
            returnSecureToken: true
          })
        }
      );

      const data = await response.json();

      if (!response.ok) {
        const message =
          data?.error?.message ||
          "Firebase sign-in failed";

        const error = new Error(message);

        if (response.status >= 400 && response.status < 500) {
          error.code = "invalid-argument";
        }

        throw error;
      }

      return data;
    }
  );
}

// ==================================================
// PROFILE LOOKUP
// ==================================================

async function findProfile(identifier) {
  const value = clean(identifier);

  if (!value) return null;

  // Direct Firebase UID.
  const direct = await readDoc("profiles", value);

  if (direct.exists) {
    return {
      id: direct.id,
      data: direct.data()
    };
  }

  // Numeric account ID.
  if (/^\d+$/.test(value)) {
    const query = await firebaseRetry(
      `FIND PROFILE USER ID ${value}`,
      () => db.collection("profiles")
        .where("user_id", "==", Number(value))
        .limit(1)
        .get()
    );

    if (!query.empty) {
      return {
        id: query.docs[0].id,
        data: query.docs[0].data()
      };
    }

    // Older accounts may not have user_id.
    // Creation order is used as a compatibility fallback.
    const ordered = await firebaseRetry(
      `FIND PROFILE BY CREATION ORDER ${value}`,
      () => db.collection("profiles")
        .orderBy("created_at", "asc")
        .get()
    );

    const index = Number(value) - 1;

    if (index >= 0 && index < ordered.docs.length) {
      const doc = ordered.docs[index];

      // Repair old profile with its numeric ID.
      const repaired = await writeDocAndVerify(
        "profiles",
        doc.id,
        {
          user_id: Number(value),
          updated_at: FieldValue.serverTimestamp()
        },
        { merge: true }
      );

      return {
        id: repaired.id,
        data: repaired.data()
      };
    }
  }

  // Username lookup.
  const usernameQuery = await firebaseRetry(
    `FIND PROFILE USERNAME ${value}`,
    () => db.collection("profiles")
      .where("username_lower", "==", normalizeUsername(value))
      .limit(1)
      .get()
  );

  if (!usernameQuery.empty) {
    return {
      id: usernameQuery.docs[0].id,
      data: usernameQuery.docs[0].data()
    };
  }

  return null;
}

// ==================================================
// STATUS
// ==================================================

app.get("/api/status", async (req, res) => {
  res.set("Cache-Control", "no-store");

  try {
    const serverRef = await readDoc("_system", "server");

    res.json({
      online: true,
      service: SERVICE_NAME,
      firebase: true,
      firebase_read: true,
      firebase_document_exists: serverRef.exists,
      retries: RETRIES
    });
  } catch (error) {
    res.status(503).json({
      online: false,
      service: SERVICE_NAME,
      firebase: false,
      error: "Firebase is temporarily unavailable"
    });
  }
});

// ==================================================
// FIREBASE TEST
// READ -> WRITE -> READ BACK
// ==================================================

app.get("/api/firebase-test", async (req, res) => {
  res.set("Cache-Control", "no-store");

  try {
    const before = await readDoc("_system", "server");

    const saved = await writeDocAndVerify(
      "_system",
      "server",
      {
        online: true,
        service: SERVICE_NAME,
        checkedAt: FieldValue.serverTimestamp()
      },
      { merge: true }
    );

    const after = await readDoc("_system", "server");

    res.json({
      connected: true,
      firestore: true,
      read_before: before.exists,
      write_verified: saved.exists,
      read_after: after.exists,
      data: after.data()
    });
  } catch (error) {
    console.error("Firebase test failed:", error);

    res.status(503).json({
      connected: false,
      firestore: false,
      error: "Firebase connection failed after retries"
    });
  }
});

// ==================================================
// SIGN UP
// ==================================================

app.post("/api/auth/signup", async (req, res) => {
  try {
    const username = clean(req.body?.username);
    const password = String(req.body?.password || "");
    const confirmPassword = String(req.body?.confirmPassword || "");
    const email = clean(req.body?.email);

    if (!username) {
      return res.status(400).json({
        success: false,
        error: "Username is required"
      });
    }

    if (!/^[A-Za-z0-9_]{3,30}$/.test(username)) {
      return res.status(400).json({
        success: false,
        error: "Username must be 3-30 characters and use letters, numbers, or _"
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        success: false,
        error: "Password must be at least 6 characters"
      });
    }

    if (password !== confirmPassword) {
      return res.status(400).json({
        success: false,
        error: "Passwords do not match"
      });
    }

    if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({
        success: false,
        error: "Invalid email"
      });
    }

    // READ current Firebase state first.
    const existing = await findProfile(username);

    if (existing) {
      return res.status(409).json({
        success: false,
        error: "Username already exists"
      });
    }

    let userRecord;

    try {
      userRecord = await firebaseRetry(
        "CREATE FIREBASE AUTH USER",
        () => auth.createUser({
          email: email || undefined,
          password,
          displayName: username
        })
      );
    } catch (error) {
      if (String(error.code || "").includes("email-already-exists")) {
        return res.status(409).json({
          success: false,
          error: "Email already exists"
        });
      }

      throw error;
    }

    // Assign the next permanent numeric account ID atomically.
    const counterRef = db.collection("_system").doc("user_counter");

    const userId = await firebaseRetry(
      "ALLOCATE USER ID",
      async () => {
        return db.runTransaction(async transaction => {
          const snap = await transaction.get(counterRef);
          const current = Number(snap.exists ? snap.data().next_user_id : 1);
          const next = Math.max(1, current);

          transaction.set(
            counterRef,
            {
              next_user_id: next + 1,
              updated_at: FieldValue.serverTimestamp()
            },
            { merge: true }
          );

          return next;
        });
      }
    );

    const profileData = {
      uid: userRecord.uid,
      user_id: userId,
      username,
      username_lower: normalizeUsername(username),
      display_name: username,
      bio: "no username",
      avatar_url: "",
      email: email || "",
      auth_email: email || userRecord.email || "",
      followers: 0,
      following: 0,
      friends: 0,
      created_at: FieldValue.serverTimestamp(),
      updated_at: FieldValue.serverTimestamp()
    };

    const profile = await writeDocAndVerify(
      "profiles",
      userRecord.uid,
      profileData,
      { merge: true }
    );

    // If Firebase Auth was created but the profile write failed,
    // retrying the whole signup would be unsafe. The server throws,
    // leaving the Auth user available for repair instead of creating duplicates.
    const signIn = await signInWithPassword(
      email || userRecord.email,
      password
    );

    await createSession(res, signIn.idToken);

    res.json({
      success: true,
      user: publicProfile(profile.data, userId)
    });
  } catch (error) {
    console.error("Signup error:", error);

    res.status(500).json({
      success: false,
      error: "Account creation failed after retries"
    });
  }
});

// ==================================================
// LOGIN
// ==================================================

app.post("/api/auth/login", async (req, res) => {
  try {
    const username = clean(req.body?.username);
    const password = String(req.body?.password || "");

    if (!username || !password) {
      return res.status(400).json({
        success: false,
        error: "Username and password are required"
      });
    }

    // READ Firebase profile first.
    const found = await findProfile(username);

    if (!found) {
      return res.status(401).json({
        success: false,
        error: "Invalid username or password"
      });
    }

    const profile = found.data;
    const email = profile.auth_email || profile.email;

    if (!email) {
      return res.status(500).json({
        success: false,
        error: "This account has no login email configured"
      });
    }

    const signIn = await signInWithPassword(email, password);

    await createSession(res, signIn.idToken);

    // READ the profile again after login.
    const verified = await findProfile(profile.uid || found.id);

    res.json({
      success: true,
      user: publicProfile(
        verified?.data || profile,
        profile.user_id || null
      )
    });
  } catch (error) {
    console.error("Login error:", error);

    res.status(401).json({
      success: false,
      error: "Invalid username or password"
    });
  }
});

// ==================================================
// CURRENT USER
// ==================================================

app.get("/api/auth/me", async (req, res) => {
  res.set("Cache-Control", "no-store");

  try {
    const user = await getCurrentUser(req);

    if (!user) {
      return res.status(401).json({
        loggedIn: false
      });
    }

    const profile = await findProfile(user.uid);

    res.json({
      loggedIn: true,
      user: profile
        ? publicProfile(profile.data, profile.data.user_id)
        : {
            uid: user.uid,
            username: user.name || user.email || "Unknown"
          }
    });
  } catch (error) {
    res.status(401).json({
      loggedIn: false
    });
  }
});

// ==================================================
// LOGOUT
// ==================================================

app.post("/api/auth/logout", (req, res) => {
  res.clearCookie(SESSION_COOKIE, {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    path: "/"
  });

  res.json({
    success: true,
    loggedOut: true
  });
});

// ==================================================
// PLAYERS
// ==================================================

app.get("/api/players", async (req, res) => {
  try {
    const snapshot = await firebaseRetry(
      "READ PLAYERS",
      () => db.collection("profiles")
        .orderBy("created_at", "desc")
        .limit(50)
        .get()
    );

    res.json(
      snapshot.docs.map(doc => publicProfile(
        doc.data(),
        doc.data().user_id || doc.id
      ))
    );
  } catch (error) {
    console.error("Players error:", error);

    res.status(503).json({
      error: "Failed to read players after retries"
    });
  }
});

// ==================================================
// PROFILE
// GET /api/profiles/:id
// GET /api/profile/:id
// ==================================================

async function profileResponse(req, res) {
  try {
    const found = await findProfile(req.params.id);

    if (!found) {
      return res.status(404).json({
        found: false,
        error: "Profile not found"
      });
    }

    const profile = publicProfile(
      found.data,
      found.data.user_id || req.params.id
    );

    // Read the user's levels.
    const levels = await findLevelsForProfile(found.id, found.data);

    // Read the user's posts.
    const posts = await findPostsForProfile(found.id, found.data);

    // Read social counts from actual relationship collections.
    const followersSnapshot = await firebaseRetry(
      "READ PROFILE FOLLOWERS",
      () => db.collection("follows")
        .where("following_uid", "==", found.id)
        .get()
    );

    const followingSnapshot = await firebaseRetry(
      "READ PROFILE FOLLOWING",
      () => db.collection("follows")
        .where("follower_uid", "==", found.id)
        .get()
    );

    const friendsSnapshot = await firebaseRetry(
      "READ PROFILE FRIENDS",
      () => db.collection("friends")
        .where("users", "array-contains", found.id)
        .get()
    );

    profile.followers = followersSnapshot.size;
    profile.following = followingSnapshot.size;
    profile.friends = friendsSnapshot.size;

    res.json({
      found: true,
      profile,
      levels,
      posts
    });
  } catch (error) {
    console.error("Profile read error:", error);

    res.status(503).json({
      found: false,
      error: "Profile could not be loaded after retries"
    });
  }
}

app.get("/api/profiles/:id", profileResponse);
app.get("/api/profile/:id", profileResponse);

// ==================================================
// PROFILE EDIT
// ==================================================

app.post("/api/profile/update", async (req, res) => {
  try {
    const user = await requireUser(req, res);
    if (!user) return;

    const profile = await findProfile(user.uid);

    if (!profile) {
      return res.status(404).json({
        success: false,
        error: "Profile not found"
      });
    }

    const updates = {};

    if (req.body?.display_name !== undefined) {
      const name = clean(req.body.display_name);

      if (name.length > 40) {
        return res.status(400).json({
          success: false,
          error: "Name is too long"
        });
      }

      updates.display_name = name || profile.data.username;
    }

    if (req.body?.bio !== undefined) {
      updates.bio = clean(req.body.bio).slice(0, 500);
    }

    if (req.body?.avatar_url !== undefined) {
      updates.avatar_url = clean(req.body.avatar_url).slice(0, 2000);
    }

    updates.updated_at = FieldValue.serverTimestamp();

    const saved = await writeDocAndVerify(
      "profiles",
      profile.id,
      updates,
      { merge: true }
    );

    res.json({
      success: true,
      profile: publicProfile(
        saved.data,
        saved.data.user_id || profile.id
      )
    });
  } catch (error) {
    console.error("Profile update error:", error);

    res.status(500).json({
      success: false,
      error: "Profile update failed after retries"
    });
  }
});

// ==================================================
// PASSWORD CHANGE
// ==================================================

app.post("/api/profile/password", async (req, res) => {
  try {
    const user = await requireUser(req, res);
    if (!user) return;

    const password = String(req.body?.password || "");

    if (password.length < 6) {
      return res.status(400).json({
        success: false,
        error: "Password must be at least 6 characters"
      });
    }

    await firebaseRetry(
      "UPDATE PASSWORD",
      () => auth.updateUser(user.uid, { password })
    );

    // Verify Auth account still exists.
    await firebaseRetry(
      "VERIFY PASSWORD ACCOUNT",
      () => auth.getUser(user.uid)
    );

    res.json({
      success: true,
      password_updated: true
    });
  } catch (error) {
    console.error("Password update error:", error);

    res.status(500).json({
      success: false,
      error: "Password update failed after retries"
    });
  }
});

// ==================================================
// LEVEL LOOKUP
// ==================================================

async function findLevel(identifier) {
  const value = clean(identifier);

  if (!value) return null;

  // Direct Firestore document ID.
  const direct = await readDoc("levels", value);

  if (direct.exists) {
    return {
      id: direct.id,
      data: direct.data()
    };
  }

  // Try common ID fields.
  const fields = ["level_id", "id", "levelId"];

  for (const field of fields) {
    const result = await firebaseRetry(
      `FIND LEVEL ${field} ${value}`,
      () => db.collection("levels")
        .where(field, "==", value)
        .limit(1)
        .get()
    );

    if (!result.empty) {
      return {
        id: result.docs[0].id,
        data: result.docs[0].data()
      };
    }

    if (/^\d+$/.test(value)) {
      const numeric = await firebaseRetry(
        `FIND LEVEL ${field} NUMBER ${value}`,
        () => db.collection("levels")
          .where(field, "==", Number(value))
          .limit(1)
          .get()
      );

      if (!numeric.empty) {
        return {
          id: numeric.docs[0].id,
          data: numeric.docs[0].data()
        };
      }
    }
  }

  // Older levels: creation-order compatibility.
  if (/^\d+$/.test(value)) {
    const ordered = await firebaseRetry(
      `FIND LEVEL BY CREATION ORDER ${value}`,
      () => db.collection("levels")
        .orderBy("created_at", "asc")
        .get()
    );

    const index = Number(value) - 1;

    if (index >= 0 && index < ordered.docs.length) {
      return {
        id: ordered.docs[index].id,
        data: ordered.docs[index].data()
      };
    }
  }

  return null;
}

// ==================================================
// LEVEL LIST
// ==================================================

app.get("/api/levels", async (req, res) => {
  try {
    const snapshot = await firebaseRetry(
      "READ LEVELS",
      () => db.collection("levels")
        .orderBy("created_at", "desc")
        .limit(100)
        .get()
    );

    const levels = snapshot.docs.map(doc =>
      publicLevel(doc.data(), doc.id)
    );

    res.json(levels);
  } catch (error) {
    console.error("Levels list error:", error);

    res.status(503).json({
      error: "Failed to read levels after retries"
    });
  }
});

// ==================================================
// EXACT LEVEL
// ==================================================

app.get("/api/levels/:id", async (req, res) => {
  try {
    const found = await findLevel(req.params.id);

    if (!found) {
      return res.status(404).json({
        found: false,
        error: "Level not found"
      });
    }

    res.json({
      found: true,
      level: publicLevel(found.data, found.id)
    });
  } catch (error) {
    console.error("Level read error:", error);

    res.status(503).json({
      found: false,
      error: "Level could not be loaded after retries"
    });
  }
});

// ==================================================
// CREATE LEVEL
// READ -> VALIDATE -> WRITE -> READ BACK
// ==================================================

app.post("/api/levels", async (req, res) => {
  try {
    const user = await requireUser(req, res);
    if (!user) return;

    const name = clean(req.body?.name);

    if (!name) {
      return res.status(400).json({
        success: false,
        error: "Level name is required"
      });
    }

    if (name.length > 100) {
      return res.status(400).json({
        success: false,
        error: "Level name is too long"
      });
    }

    const profile = await findProfile(user.uid);

    const creatorUsername =
      profile?.data?.username ||
      profile?.data?.display_name ||
      user.name ||
      "Unknown Player";

    const creatorUserId =
      profile?.data?.user_id ||
      profile?.id ||
      user.uid;

    // Use a Firestore-generated ID so every level has a unique stable URL.
    const ref = db.collection("levels").doc();

    const levelData = {
      id: ref.id,
      level_id: ref.id,
      name,
      description: clean(req.body?.description, "no level"),
      thumbnail_url: clean(req.body?.thumbnail_url),
      creator: creatorUsername,
      creator_username: creatorUsername,
      creator_user_id: creatorUserId,
      creator_uid: user.uid,
      uid: user.uid,
      hearts: 0,
      likes: 0,
      followers: 0,
      plays: 0,
      created_at: FieldValue.serverTimestamp(),
      updated_at: FieldValue.serverTimestamp()
    };

    const saved = await writeDocAndVerify(
      "levels",
      ref.id,
      levelData
    );

    res.json({
      success: true,
      level: publicLevel(saved.data, saved.id)
    });
  } catch (error) {
    console.error("Level create error:", error);

    res.status(500).json({
      success: false,
      error: "Level creation failed after retries"
    });
  }
});

// ==================================================
// LEVEL ACTIONS
// ==================================================

async function relationshipAction(req, res, collection, type) {
  try {
    const user = await requireUser(req, res);
    if (!user) return;

    const level = await findLevel(req.params.id);

    if (!level) {
      return res.status(404).json({
        success: false,
        error: "Level not found"
      });
    }

    const levelId = level.id;
    const relationshipId = `${user.uid}_${levelId}`;

    const ref = db.collection(collection).doc(relationshipId);

    const existing = await readDoc(collection, relationshipId);

    if (!existing.exists) {
      await writeDocAndVerify(
        collection,
        relationshipId,
        {
          uid: user.uid,
          user_id: user.uid,
          level_id: levelId,
          created_at: FieldValue.serverTimestamp()
        }
      );
    }

    const countField =
      type === "heart"
        ? "hearts"
        : type === "like"
          ? "likes"
          : "followers";

    const updatedLevel = await firebaseRetry(
      `UPDATE LEVEL ${countField}`,
      async () => {
        const levelRef = db.collection("levels").doc(levelId);

        await db.runTransaction(async transaction => {
          const snap = await transaction.get(levelRef);

          if (!snap.exists) {
            throw new Error("Level disappeared during update");
          }

          const current = Number(snap.data()[countField] || 0);

          transaction.update(levelRef, {
            [countField]: Math.max(0, current + (existing.exists ? 0 : 1)),
            updated_at: FieldValue.serverTimestamp()
          });
        });

        return levelRef.get();
      }
    );

    res.json({
      success: true,
      level: publicLevel(updatedLevel.data(), updatedLevel.id)
    });
  } catch (error) {
    console.error(`Level ${type} error:`, error);

    res.status(500).json({
      success: false,
      error: `Level ${type} failed after retries`
    });
  }
}

app.post("/api/levels/:id/heart", (req, res) =>
  relationshipAction(req, res, "level_hearts", "heart")
);

app.post("/api/levels/:id/like", (req, res) =>
  relationshipAction(req, res, "level_likes", "like")
);

app.post("/api/levels/:id/follow", (req, res) =>
  relationshipAction(req, res, "level_follows", "follow")
);

// ==================================================
// PROFILE LEVELS
// ==================================================

async function findLevelsForProfile(profileDocId, profileData) {
  const uid = profileData.uid || profileDocId;
  const userId = profileData.user_id;

  const seen = new Map();

  const queries = [
    ["creator_uid", uid],
    ["uid", uid]
  ];

  if (userId !== undefined && userId !== null) {
    queries.push(["creator_user_id", userId]);
    queries.push(["user_id", userId]);
  }

  for (const [field, value] of queries) {
    const snapshot = await firebaseRetry(
      `READ PROFILE LEVELS ${field}`,
      () => db.collection("levels")
        .where(field, "==", value)
        .limit(100)
        .get()
    );

    snapshot.docs.forEach(doc => {
      seen.set(doc.id, publicLevel(doc.data(), doc.id));
    });
  }

  // Username compatibility for older levels.
  const usernames = [
    profileData.username,
    profileData.display_name
  ].filter(Boolean);

  for (const username of usernames) {
    const snapshot = await firebaseRetry(
      "READ PROFILE LEVELS USERNAME",
      () => db.collection("levels")
        .where("creator", "==", username)
        .limit(100)
        .get()
    );

    snapshot.docs.forEach(doc => {
      seen.set(doc.id, publicLevel(doc.data(), doc.id));
    });
  }

  return Array.from(seen.values());
}

// ==================================================
// POSTS
// ==================================================

app.get("/api/posts", async (req, res) => {
  try {
    const snapshot = await firebaseRetry(
      "READ POSTS",
      () => db.collection("posts")
        .orderBy("created_at", "desc")
        .limit(100)
        .get()
    );

    res.json(
      snapshot.docs.map(doc =>
        publicPost(doc.data(), doc.id)
      )
    );
  } catch (error) {
    console.error("Posts list error:", error);

    res.status(503).json({
      error: "Failed to read posts after retries"
    });
  }
});

// ==================================================
// EXACT POST
// ==================================================

async function findPost(identifier) {
  const value = clean(identifier);

  if (!value) return null;

  const direct = await readDoc("posts", value);

  if (direct.exists) {
    return {
      id: direct.id,
      data: direct.data()
    };
  }

  for (const field of ["post_id", "id"]) {
    const result = await firebaseRetry(
      `FIND POST ${field}`,
      () => db.collection("posts")
        .where(field, "==", value)
        .limit(1)
        .get()
    );

    if (!result.empty) {
      return {
        id: result.docs[0].id,
        data: result.docs[0].data()
      };
    }
  }

  if (/^\d+$/.test(value)) {
    const ordered = await firebaseRetry(
      `FIND POST BY CREATION ORDER ${value}`,
      () => db.collection("posts")
        .orderBy("created_at", "asc")
        .get()
    );

    const index = Number(value) - 1;

    if (index >= 0 && index < ordered.docs.length) {
      return {
        id: ordered.docs[index].id,
        data: ordered.docs[index].data()
      };
    }
  }

  return null;
}

async function readReplies(postId) {
  const queries = [
    db.collection("post_replies")
      .where("post_id", "==", String(postId))
      .limit(200)
      .get()
  ];

  // Some older data may have stored the post ID as another type.
  if (/^\d+$/.test(String(postId))) {
    queries.push(
      db.collection("post_replies")
        .where("post_id", "==", Number(postId))
        .limit(200)
        .get()
    );
  }

  const snapshots = [];

  for (const query of queries) {
    snapshots.push(
      await firebaseRetry("READ POST REPLIES", () => query)
    );
  }

  const map = new Map();

  for (const snapshot of snapshots) {
    for (const doc of snapshot.docs) {
      const data = doc.data();

      map.set(doc.id, {
        id: doc.id,
        user_id: data.user_id || data.uid || "?",
        uid: data.uid || "",
        username: data.username || "No username found",
        avatar_url: data.avatar_url || "",
        text: data.text || data.content || "no reply",
        created_at: data.created_at || null
      });
    }
  }

  return Array.from(map.values()).sort((a, b) => {
    const aa = a.created_at?._seconds || 0;
    const bb = b.created_at?._seconds || 0;
    return aa - bb;
  });
}

async function postResponse(req, res) {
  try {
    const found = await findPost(req.params.id);

    if (!found) {
      return res.status(404).json({
        found: false,
        error: "Post not found",
        post: null,
        replies: []
      });
    }

    const post = publicPost(found.data, found.id);
    const replies = await readReplies(found.id);

    res.json({
      found: true,
      post,
      replies
    });
  } catch (error) {
    console.error("Post read error:", error);

    res.status(503).json({
      found: false,
      error: "Post could not be loaded after retries",
      post: null,
      replies: []
    });
  }
}

app.get("/api/posts/:id", postResponse);

// ==================================================
// CREATE POST
// ==================================================

app.post("/api/posts", async (req, res) => {
  try {
    const user = await requireUser(req, res);
    if (!user) return;

    const text = clean(req.body?.text || req.body?.content);

    if (!text) {
      return res.status(400).json({
        success: false,
        error: "Post text is required"
      });
    }

    if (text.length > 5000) {
      return res.status(400).json({
        success: false,
        error: "Post is too long"
      });
    }

    const profile = await findProfile(user.uid);

    const author =
      profile?.data?.username ||
      profile?.data?.display_name ||
      user.name ||
      "No username found";

    const userId =
      profile?.data?.user_id ||
      profile?.id ||
      user.uid;

    const ref = db.collection("posts").doc();

    const postData = {
      id: ref.id,
      post_id: ref.id,
      uid: user.uid,
      user_id: userId,
      author,
      username: author,
      avatar_url: profile?.data?.avatar_url || "",
      text,
      content: text,
      created_at: FieldValue.serverTimestamp(),
      updated_at: FieldValue.serverTimestamp()
    };

    const saved = await writeDocAndVerify(
      "posts",
      ref.id,
      postData
    );

    res.json({
      success: true,
      post: publicPost(saved.data, saved.id)
    });
  } catch (error) {
    console.error("Post create error:", error);

    res.status(500).json({
      success: false,
      error: "Post creation failed after retries"
    });
  }
});

// ==================================================
// REPLY TO POST
// READ POST -> WRITE REPLY -> READ REPLIES
// ==================================================

app.post("/api/posts/:id/replies", async (req, res) => {
  try {
    const user = await requireUser(req, res);
    if (!user) return;

    const post = await findPost(req.params.id);

    if (!post) {
      return res.status(404).json({
        success: false,
        error: "Post not found"
      });
    }

    const text = clean(req.body?.text || req.body?.content);

    if (!text) {
      return res.status(400).json({
        success: false,
        error: "Reply text is required"
      });
    }

    if (text.length > 2000) {
      return res.status(400).json({
        success: false,
        error: "Reply is too long"
      });
    }

    const profile = await findProfile(user.uid);

    const replyRef = db.collection("post_replies").doc();

    const replyData = {
      id: replyRef.id,
      post_id: post.id,
      post_uid: post.data.uid || "",
      uid: user.uid,
      user_id:
        profile?.data?.user_id ||
        profile?.id ||
        user.uid,
      username:
        profile?.data?.username ||
        profile?.data?.display_name ||
        user.name ||
        "No username found",
      avatar_url: profile?.data?.avatar_url || "",
      text,
      content: text,
      created_at: FieldValue.serverTimestamp()
    };

    await writeDocAndVerify(
      "post_replies",
      replyRef.id,
      replyData
    );

    // READ BACK ALL replies so the page gets the actual Firebase state.
    const replies = await readReplies(post.id);

    res.json({
      success: true,
      post_id: post.id,
      replies
    });
  } catch (error) {
    console.error("Reply error:", error);

    res.status(500).json({
      success: false,
      error: "Reply failed after retries"
    });
  }
});

// ==================================================
// PROFILE POSTS
// ==================================================

async function findPostsForProfile(profileDocId, profileData) {
  const uid = profileData.uid || profileDocId;
  const userId = profileData.user_id;

  const seen = new Map();

  const queries = [
    ["uid", uid],
    ["user_id", userId]
  ].filter(([, value]) => value !== undefined && value !== null);

  for (const [field, value] of queries) {
    const snapshot = await firebaseRetry(
      `READ PROFILE POSTS ${field}`,
      () => db.collection("posts")
        .where(field, "==", value)
        .limit(100)
        .get()
    );

    snapshot.docs.forEach(doc => {
      seen.set(doc.id, publicPost(doc.data(), doc.id));
    });
  }

  // Older posts may only have an author/username.
  for (const username of [
    profileData.username,
    profileData.display_name
  ].filter(Boolean)) {
    for (const field of ["author", "username"]) {
      const snapshot = await firebaseRetry(
        `READ PROFILE POSTS ${field}`,
        () => db.collection("posts")
          .where(field, "==", username)
          .limit(100)
          .get()
      );

      snapshot.docs.forEach(doc => {
        seen.set(doc.id, publicPost(doc.data(), doc.id));
      });
    }
  }

  return Array.from(seen.values()).sort((a, b) => {
    const aa = a.created_at?._seconds || 0;
    const bb = b.created_at?._seconds || 0;
    return bb - aa;
  });
}

// ==================================================
// FOLLOW / FRIEND SYSTEM
// ==================================================

app.post("/api/profiles/:id/follow", async (req, res) => {
  try {
    const user = await requireUser(req, res);
    if (!user) return;

    const target = await findProfile(req.params.id);

    if (!target) {
      return res.status(404).json({
        success: false,
        error: "Profile not found"
      });
    }

    if (target.id === user.uid) {
      return res.status(400).json({
        success: false,
        error: "You cannot follow yourself"
      });
    }

    const relationshipId = `${user.uid}_${target.id}`;
    const ref = db.collection("follows").doc(relationshipId);

    const existing = await readDoc("follows", relationshipId);

    if (existing.exists) {
      await deleteDocAndVerify("follows", relationshipId);

      return res.json({
        success: true,
        following: false
      });
    }

    await writeDocAndVerify(
      "follows",
      relationshipId,
      {
        follower_uid: user.uid,
        following_uid: target.id,
        created_at: FieldValue.serverTimestamp()
      }
    );

    res.json({
      success: true,
      following: true
    });
  } catch (error) {
    console.error("Follow error:", error);

    res.status(500).json({
      success: false,
      error: "Follow failed after retries"
    });
  }
});

app.post("/api/profiles/:id/friend", async (req, res) => {
  try {
    const user = await requireUser(req, res);
    if (!user) return;

    const target = await findProfile(req.params.id);

    if (!target) {
      return res.status(404).json({
        success: false,
        error: "Profile not found"
      });
    }

    if (target.id === user.uid) {
      return res.status(400).json({
        success: false,
        error: "You cannot friend yourself"
      });
    }

    const users = [user.uid, target.id].sort();
    const relationshipId = `${users[0]}_${users[1]}`;

    const existing = await readDoc("friends", relationshipId);

    if (existing.exists) {
      await deleteDocAndVerify("friends", relationshipId);

      return res.json({
        success: true,
        friends: false
      });
    }

    await writeDocAndVerify(
      "friends",
      relationshipId,
      {
        users,
        created_at: FieldValue.serverTimestamp()
      }
    );

    res.json({
      success: true,
      friends: true
    });
  } catch (error) {
    console.error("Friend error:", error);

    res.status(500).json({
      success: false,
      error: "Friend action failed after retries"
    });
  }
});

// ==================================================
// GENERIC FIRESTORE DATA API
// ==================================================

app.get("/api/data/:collection/:id", async (req, res) => {
  try {
    const snapshot = await readDoc(
      req.params.collection,
      req.params.id
    );

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
    console.error("Generic read error:", error);

    res.status(503).json({
      found: false,
      error: "Firebase read failed after retries"
    });
  }
});

app.post("/api/data/:collection/:id", async (req, res) => {
  try {
    if (!req.body || typeof req.body !== "object") {
      return res.status(400).json({
        error: "JSON body required"
      });
    }

    const saved = await writeDocAndVerify(
      req.params.collection,
      req.params.id,
      {
        ...req.body,
        updatedAt: FieldValue.serverTimestamp()
      },
      { merge: true }
    );

    res.json({
      success: true,
      collection: req.params.collection,
      id: saved.id,
      verified: true,
      data: saved.data()
    });
  } catch (error) {
    console.error("Generic write error:", error);

    res.status(503).json({
      success: false,
      error: "Firebase write failed after retries"
    });
  }
});

app.delete("/api/data/:collection/:id", async (req, res) => {
  try {
    await deleteDocAndVerify(
      req.params.collection,
      req.params.id
    );

    res.json({
      success: true,
      deleted: true,
      verified: true,
      collection: req.params.collection,
      id: req.params.id
    });
  } catch (error) {
    console.error("Generic delete error:", error);

    res.status(503).json({
      success: false,
      error: "Firebase delete failed after retries"
    });
  }
});

// ==================================================
// PAGE ALIASES
// Render/Linux is case-sensitive, so support both.
//
// /Level.html and /level.html
// /Profile.html and /profile.html
// /Post.html and /post.html
// ==================================================

app.get(["/Level.html", "/level.html"], (req, res) => {
  res.sendFile(path.join(__dirname, "Level.html"), error => {
    if (error) {
      res.sendFile(path.join(__dirname, "level.html"));
    }
  });
});

app.get(["/Profile.html", "/profile.html"], (req, res) => {
  res.sendFile(path.join(__dirname, "Profile.html"), error => {
    if (error) {
      res.sendFile(path.join(__dirname, "profile.html"));
    }
  });
});

app.get(["/Post.html", "/post.html"], (req, res) => {
  res.sendFile(path.join(__dirname, "Post.html"), error => {
    if (error) {
      res.sendFile(path.join(__dirname, "post.html"));
    }
  });
});

// ==================================================
// STATIC WEBSITE
// ==================================================

app.use(
  express.static(__dirname, {
    extensions: ["html"],
    maxAge: 0
  })
);

// Homepage.
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
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
// SERVER START
// ==================================================

app.listen(PORT, "0.0.0.0", () => {
  console.log("==============================================");
  console.log(`${SERVICE_NAME} server started`);
  console.log(`Port: ${PORT}`);
  console.log("Firebase Admin: connected");
  console.log(`Firebase retries: ${RETRIES}`);
  console.log("Write verification: enabled");
  console.log("Read-after-write verification: enabled");
  console.log("==============================================");
});
