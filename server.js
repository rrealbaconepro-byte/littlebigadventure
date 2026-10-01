```js
const express = require("express");

const { initializeApp, cert } = require("firebase-admin/app");
const {
  getFirestore,
  FieldValue
} = require("firebase-admin/firestore");

// ==================================================
// FIREBASE ADMIN
// ==================================================

if (!process.env.FIREBASE_PROJECT_ID) {
  throw new Error("Missing FIREBASE_PROJECT_ID");
}

if (!process.env.FIREBASE_CLIENT_EMAIL) {
  throw new Error("Missing FIREBASE_CLIENT_EMAIL");
}

if (!process.env.FIREBASE_PRIVATE_KEY) {
  throw new Error("Missing FIREBASE_PRIVATE_KEY");
}

initializeApp({
  credential: cert({
    projectId: process.env.FIREBASE_PROJECT_ID,
    clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
    privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, "\n")
  })
});

const db = getFirestore();

// ==================================================
// EXPRESS
// ==================================================

const app = express();

app.use(express.json({ limit: "1mb" }));

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
// READ FIRESTORE DOCUMENT
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
// ==================================================

app.post("/api/data/:collection/:id", async (req, res) => {
  try {
    const { collection, id } = req.params;

    if (!req.body || typeof req.body !== "object") {
      return res.status(400).json({
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
```
