const express = require("express");
const path = require("path");

const {
  initializeApp,
  cert,
  getApps
} = require("firebase-admin/app");

const {
  getAuth
} = require("firebase-admin/auth");

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

// ==================================================
// AUTH HELPERS
// ==================================================

async function getCurrentUser(req) {
  const sessionCookie = req.cookies?.session;

  if (sessionCookie) {
    try {
      return await auth.verifySessionCookie(sessionCookie, true);
    } catch (error) {
      // Continue and check Bearer token below.
    }
  }

  const authorization = req.headers.authorization || "";

  if (authorization.startsWith("Bearer ")) {
    const token = authorization.substring(7).trim();

    try {
      return await auth.verifyIdToken(token);
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
// CREATE SESSION COOKIE
// ==================================================

async function createSession(res, idToken) {
  const expiresIn = 1000 * 60 * 60 * 24 * 5;

  const sessionCookie = await auth.createSessionCookie(idToken, {
    expiresIn
  });

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

    if (emailInput && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailInput)) {
      return res.status(400).json({
        error: "Please enter a valid email address"
      });
    }

    const existingProfile = await db
      .collection("profiles")
      .where("username_lower", "==", username.toLowerCase())
      .limit(1)
      .get();

    if (!existingProfile.empty) {
      return res.status(409).json({
        error: "Username is already taken"
      });
    }

    const authEmail =
      emailInput || createPrivateAuthEmail(username);

    let userRecord;

    try {
      userRecord = await auth.createUser({
        email: authEmail,
        password,
        displayName: username
      });
    } catch (error) {
      if (error.code === "auth/email-already-exists") {
        return res.status(409).json({
          error: emailInput
            ? "That email is already in use"
            : "That username is already in use"
        });
      }

      throw error;
    }

    try {
      await db.collection("profiles").doc(userRecord.uid).set({
        uid: userRecord.uid,
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

      const customToken = await auth.createCustomToken(
        userRecord.uid
      );

      res.status(201).json({
        success: true,
        user: {
          uid: userRecord.uid,
          username,
          email: emailInput
        },
        customToken
      });
    } catch (error) {
      // Avoid leaving an Auth account behind if the profile write fails.
      try {
        await auth.deleteUser(userRecord.uid);
      } catch (deleteError) {
        console.error(
          "Could not roll back Firebase Auth user:",
          deleteError
        );
      }

      throw error;
    }
  } catch (error) {
    console.error("Signup error:", error);

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

    const apiKey = process.env.FIREBASE_WEB_API_KEY;

    if (!apiKey) {
      return res.status(500).json({
        error: "Missing FIREBASE_WEB_API_KEY"
      });
    }

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
      console.error("Firebase login error:", data);

      return res.status(401).json({
        error: "Invalid username or password"
      });
    }

    await createSession(res, data.idToken);

    res.json({
      success: true,
      user: {
        uid: data.localId,
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

    const profileSnapshot = await db
      .collection("profiles")
      .doc(user.uid)
      .get();

    if (!profileSnapshot.exists) {
      return res.json({
        authenticated: true,
        user: {
          uid: user.uid,
          username: user.name || "",
          email: user.email || ""
        }
      });
    }

    const profile = profileSnapshot.data();

    res.json({
      authenticated: true,
      user: {
        uid: user.uid,
        username: profile.username || user.name || "",
        email: profile.email || ""
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

    res.json({
      players
    });
  } catch (error) {
    console.error("Players error:", error);

    res.status(500).json({
      error: "Failed to load players",
      players: []
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
        text: data.text || "",
        uid: data.uid || "",
        created_at: data.created_at || null
      };
    });

    res.json({
      posts
    });
  } catch (error) {
    console.error("Posts read error:", error);

    res.status(500).json({
      error: "Failed to load posts",
      posts: []
    });
  }
});

app.post("/api/posts", async (req, res) => {
  try {
    const user = await requireUser(req, res);

    if (!user) {
      return;
    }

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

    const profileSnapshot = await db
      .collection("profiles")
      .doc(user.uid)
      .get();

    const profile = profileSnapshot.exists
      ? profileSnapshot.data()
      : {};

    const username =
      profile.username ||
      user.name ||
      user.email ||
      "Player";

    const postRef = db.collection("posts").doc();

    await postRef.set({
      uid: user.uid,
      author: username,
      username,
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
        name: data.name || data.title || "",
        creator:
          data.creator ||
          data.username ||
          "",
        description: data.description || "",
        uid: data.uid || "",
        created_at: data.created_at || null
      };
    });

    res.json({
      levels
    });
  } catch (error) {
    console.error("Levels read error:", error);

    res.status(500).json({
      error: "Failed to load levels",
      levels: []
    });
  }
});

app.post("/api/levels", async (req, res) => {
  try {
    const user = await requireUser(req, res);

    if (!user) {
      return;
    }

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

    const profileSnapshot = await db
      .collection("profiles")
      .doc(user.uid)
      .get();

    const profile = profileSnapshot.exists
      ? profileSnapshot.data()
      : {};

    const username =
      profile.username ||
      user.name ||
      user.email ||
      "Player";

    const levelRef = db.collection("levels").doc();

    await levelRef.set({
      uid: user.uid,
      name,
      title: name,
      creator: username,
      username,
      description,
      created_at: FieldValue.serverTimestamp()
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
    const { collection, id } = req.params;

    const snapshot = await db
      .collection(collection)
      .doc(id)
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
  try {
    const user = await requireUser(req, res);

    if (!user) {
      return;
    }

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
  try {
    const user = await requireUser(req, res);

    if (!user) {
      return;
    }

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
// STATIC WEBSITE
// ==================================================

const publicPath = path.join(__dirname);

app.use(express.static(publicPath));

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
  console.log("========================================");
});
