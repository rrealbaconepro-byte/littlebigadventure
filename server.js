const express = require("express");
const path = require("path");

const { initializeApp, cert } = require("firebase-admin/app");
const {
  getFirestore,
  FieldValue
} = require("firebase-admin/firestore");

// ==================================================
// FIREBASE ADMIN
// ==================================================

if (!process.env.FIREBASE_SERVICE_ACCOUNT_JSON) {
  throw new Error("Missing FIREBASE_SERVICE_ACCOUNT_JSON");
}

let serviceAccount;

try {
  serviceAccount = JSON.parse(
    process.env.FIREBASE_SERVICE_ACCOUNT_JSON
  );
} catch (error) {
  throw new Error(
    "FIREBASE_SERVICE_ACCOUNT_JSON is not valid JSON"
  );
}

initializeApp({
  credential: cert(serviceAccount)
});

const db = getFirestore();

// ==================================================
// EXPRESS
// ==================================================

const app = express();
const PORT = process.env.PORT || 10000;

app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));

// ==================================================
// STATUS
// ==================================================

app.get("/api/status", async (req, res) => {
  try {
    await db.collection("_system").doc("server").set(
      {
        online: true,
        service: "LittleBigAdventure",
        firebase: true,
        database: "Firestore",
        updatedAt: FieldValue.serverTimestamp()
      },
      { merge: true }
    );

    res.json({
      online: true,
      service: "LittleBigAdventure",
      firebase: true,
      database: "Firestore"
    });
  } catch (error) {
    console.error("Firebase status error:", error);

    res.status(500).json({
      online: false,
      service: "LittleBigAdventure",
      firebase: false,
      error: "Firebase connection failed"
    });
  }
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
    console.error("Firebase test error:", error);

    res.status(500).json({
      connected: false,
      firestore: false,
      error: "Firebase connection failed"
    });
  }
});

// ==================================================
// READ FIRESTORE DOCUMENT
// GET /api/data/users/USER_ID
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

// ==================================================
// WRITE FIRESTORE DOCUMENT
// POST /api/data/users/USER_ID
// ==================================================

app.post("/api/data/:collection/:id", async (req, res) => {
  try {
    const { collection, id } = req.params;

    if (!req.body || typeof req.body !== "object") {
      return res.status(400).json({
        success: false,
        error: "JSON body required"
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

// ==================================================
// DELETE FIRESTORE DOCUMENT
// DELETE /api/data/users/USER_ID
// ==================================================

app.delete("/api/data/:collection/:id", async (req, res) => {
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
// WEBSITE
// ==================================================

app.use(express.static(__dirname));

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
// START SERVER
// ==================================================

app.listen(PORT, "0.0.0.0", () => {
  console.log("========================================");
  console.log("LittleBigAdventure server started");
  console.log("Port: " + PORT);
  console.log("Firebase Admin: connected");
  console.log("Firestore: connected");
  console.log("========================================");
});
