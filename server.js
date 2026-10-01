const express = require("express");
const path = require("path");

const {
  initializeApp,
  cert
} = require("firebase-admin/app");

const {
  getAuth
} = require("firebase-admin/auth");

const {
  getFirestore,
  FieldValue
} = require("firebase-admin/firestore");

const app = express();

const PORT = process.env.PORT || 10000;

/* =========================================================
   BASIC SERVER SETTINGS
========================================================= */

app.disable("x-powered-by");

app.use(
  express.json({
    limit: "256kb"
  })
);

/* =========================================================
   FIREBASE ADMIN
========================================================= */

const rawFirebase = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;

if (!rawFirebase) {
  throw new Error("Missing FIREBASE_SERVICE_ACCOUNT_JSON");
}

let serviceAccount;

try {
  serviceAccount = JSON.parse(rawFirebase);
} catch (error) {
  throw new Error(
    "FIREBASE_SERVICE_ACCOUNT_JSON is not valid JSON"
  );
}

initializeApp({
  credential: cert({
    projectId: serviceAccount.project_id,
    clientEmail: serviceAccount.client_email,
    privateKey: serviceAccount.private_key.replace(/\\n/g, "\n")
  })
});

const db = getFirestore();
const auth = getAuth();

/* =========================================================
   WEBSITE
========================================================= */

const indexPath = path.join(__dirname, "index.html");

app.get("/", (req, res) => {
  res.redirect("/index.html");
});

app.use(express.static(__dirname));

/* =========================================================
   SMALL HELPERS
========================================================= */

function cleanString(value, maxLength = 200) {
  if (typeof value !== "string") return "";
  return value.trim().slice(0, maxLength);
}

function cleanOptionalString(value, maxLength = 200) {
  if (typeof value !== "string") return null;
  const result = value.trim().slice(0, maxLength);
  return result || null;
}

function sendError(res, status, message) {
  return res.status(status).json({
    error: message
  });
}

/* =========================================================
   AUTHENTICATION
========================================================= */

async function requireAuth(req, res, next) {
  try {
    const header = req.headers.authorization || "";

    if (!header.startsWith("Bearer ")) {
      return sendError(res, 401, "Authentication required");
    }

    const token = header.slice(7).trim();

    if (!token) {
      return sendError(res, 401, "Authentication required");
    }

    const decoded = await auth.verifyIdToken(token);

    req.user = decoded;

    next();
  } catch (error) {
    console.error("Authentication error:", error.message);

    return sendError(res, 401, "Invalid or expired login");
  }
}

/* =========================================================
   SERVER STATUS
========================================================= */

app.get("/api/status", (req, res) => {
  res.json({
    online: true,
    service: "LittleBigAdventure",
    firebase: true
  });
});

/* =========================================================
   FIREBASE HEALTH
========================================================= */

app.get("/api/firebase-test", async (req, res) => {
  try {
    const ref = db.collection("_system").doc("server");

    await ref.set(
      {
        online: true,
        updatedAt: FieldValue.serverTimestamp()
      },
      {
        merge: true
      }
    );

    res.json({
      connected: true,
      firestore: true
    });
  } catch (error) {
    console.error("Firebase error:", error);

    return sendError(
      res,
      500,
      "Firebase connection failed"
    );
  }
});

/* =========================================================
   CREATE / UPDATE PROFILE
========================================================= */

app.post("/api/profile", requireAuth, async (req, res) => {
  try {
    const uid = req.user.uid;

    const gamerTag = cleanString(
      req.body.gamerTag,
      40
    );

    const username = cleanString(
      req.body.username,
      30
    );

    const email = cleanOptionalString(
      req.body.email,
      150
    );

    if (!gamerTag) {
      return sendError(res, 400, "Gamer Tag is required");
    }

    if (!username) {
      return sendError(res, 400, "Username is required");
    }

    const profileRef = db
      .collection("profiles")
      .doc(uid);

    /*
      Only store the actual profile fields.
      Do not store the Firebase token.
    */

    const data = {
      gamerTag,
      username,
      updatedAt: FieldValue.serverTimestamp()
    };

    if (email !== null) {
      data.email = email;
    }

    await profileRef.set(
      data,
      {
        merge: true
      }
    );

    res.json({
      saved: true,
      uid,
      gamerTag,
      username
    });
  } catch (error) {
    console.error("Profile save error:", error);

    return sendError(
      res,
      500,
      "Could not save profile"
    );
  }
});

/* =========================================================
   GET MY PROFILE
========================================================= */

app.get("/api/profile/me", requireAuth, async (req, res) => {
  try {
    const uid = req.user.uid;

    const snapshot = await db
      .collection("profiles")
      .doc(uid)
      .get();

    if (!snapshot.exists) {
      return res.json({
        exists: false
      });
    }

    const data = snapshot.data();

    res.json({
      exists: true,
      profile: {
        gamerTag: data.gamerTag || "",
        username: data.username || "",
        email: data.email || null
      }
    });
  } catch (error) {
    console.error("Profile read error:", error);

    return sendError(
      res,
      500,
      "Could not load profile"
    );
  }
});

/* =========================================================
   CREATE LEVEL
========================================================= */

app.post("/api/levels", requireAuth, async (req, res) => {
  try {
    const uid = req.user.uid;

    const title = cleanString(
      req.body.title,
      80
    );

    const description = cleanString(
      req.body.description,
      500
    );

    if (!title) {
      return sendError(
        res,
        400,
        "Level title is required"
      );
    }

    const levelRef = db
      .collection("levels")
      .doc();

    await levelRef.set({
      title,
      description,
      creatorId: uid,
      plays: 0,
      hearts: 0,
      createdAt: FieldValue.serverTimestamp(),
      updatedAt: FieldValue.serverTimestamp()
    });

    res.status(201).json({
      saved: true,
      levelId: levelRef.id
    });
  } catch (error) {
    console.error("Level creation error:", error);

    return sendError(
      res,
      500,
      "Could not create level"
    );
  }
});

/* =========================================================
   GET NEWEST LEVELS
========================================================= */

app.get("/api/levels", async (req, res) => {
  try {
    let limit = Number(req.query.limit);

    if (!Number.isFinite(limit)) {
      limit = 20;
    }

    limit = Math.min(
      Math.max(Math.floor(limit), 1),
      30
    );

    const snapshot = await db
      .collection("levels")
      .orderBy("createdAt", "desc")
      .limit(limit)
      .get();

    const levels = [];

    snapshot.forEach((doc) => {
      const data = doc.data();

      levels.push({
        id: doc.id,
        title: data.title || "",
        description: data.description || "",
        creatorId: data.creatorId || "",
        plays: data.plays || 0,
        hearts: data.hearts || 0
      });
    });

    res.json({
      levels
    });
  } catch (error) {
    console.error("Level read error:", error);

    return sendError(
      res,
      500,
      "Could not load levels"
    );
  }
});

/* =========================================================
   UPDATE MY LEVEL
========================================================= */

app.patch(
  "/api/levels/:id",
  requireAuth,
  async (req, res) => {
    try {
      const uid = req.user.uid;
      const levelId = cleanString(req.params.id, 100);

      if (!levelId) {
        return sendError(
          res,
          400,
          "Invalid level"
        );
      }

      const levelRef = db
        .collection("levels")
        .doc(levelId);

      const snapshot = await levelRef.get();

      if (!snapshot.exists) {
        return sendError(
          res,
          404,
          "Level not found"
        );
      }

      const existing = snapshot.data();

      if (existing.creatorId !== uid) {
        return sendError(
          res,
          403,
          "You do not own this level"
        );
      }

      /*
        Only update fields that were actually supplied.
        This keeps writes small.
      */

      const changes = {};

      if (typeof req.body.title === "string") {
        changes.title = cleanString(
          req.body.title,
          80
        );
      }

      if (typeof req.body.description === "string") {
        changes.description = cleanString(
          req.body.description,
          500
        );
      }

      if (Object.keys(changes).length === 0) {
        return res.json({
          saved: true,
          changed: false
        });
      }

      changes.updatedAt =
        FieldValue.serverTimestamp();

      await levelRef.update(changes);

      res.json({
        saved: true,
        changed: true
      });
    } catch (error) {
      console.error("Level update error:", error);

      return sendError(
        res,
        500,
        "Could not update level"
      );
    }
  }
);

/* =========================================================
   CREATE POST
========================================================= */

app.post("/api/posts", requireAuth, async (req, res) => {
  try {
    const uid = req.user.uid;

    const text = cleanString(
      req.body.text,
      1000
    );

    if (!text) {
      return sendError(
        res,
        400,
        "Post cannot be empty"
      );
    }

    const postRef = db
      .collection("posts")
      .doc();

    await postRef.set({
      authorId: uid,
      text,
      likes: 0,
      comments: 0,
      createdAt: FieldValue.serverTimestamp()
    });

    res.status(201).json({
      saved: true,
      postId: postRef.id
    });
  } catch (error) {
    console.error("Post creation error:", error);

    return sendError(
      res,
      500,
      "Could not create post"
    );
  }
});

/* =========================================================
   GET POSTS
========================================================= */

app.get("/api/posts", async (req, res) => {
  try {
    let limit = Number(req.query.limit);

    if (!Number.isFinite(limit)) {
      limit = 20;
    }

    limit = Math.min(
      Math.max(Math.floor(limit), 1),
      30
    );

    const snapshot = await db
      .collection("posts")
      .orderBy("createdAt", "desc")
      .limit(limit)
      .get();

    const posts = [];

    snapshot.forEach((doc) => {
      const data = doc.data();

      posts.push({
        id: doc.id,
        authorId: data.authorId || "",
        text: data.text || "",
        likes: data.likes || 0,
        comments: data.comments || 0
      });
    });

    res.json({
      posts
    });
  } catch (error) {
    console.error("Post read error:", error);

    return sendError(
      res,
      500,
      "Could not load posts"
    );
  }
});

/* =========================================================
   404
========================================================= */

app.use((req, res) => {
  res.status(404).json({
    error: "Not Found"
  });
});

/* =========================================================
   START SERVER
========================================================= */

app.listen(
  PORT,
  "0.0.0.0",
  () => {
    console.log(
      "LittleBigAdventure server started"
    );

    console.log(
      "Port: " + PORT
    );

    console.log(
      "Firebase Admin connected"
    );

    console.log(
      "Index: " + indexPath
    );
  }
);
