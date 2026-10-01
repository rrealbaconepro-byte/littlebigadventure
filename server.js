const express = require("express");

const { initializeApp, cert } = require("firebase-admin/app");
const { getFirestore } = require("firebase-admin/firestore");

const app = express();

app.use(express.json({ limit: "1mb" }));

// ==========================================
// FIREBASE ADMIN
// ==========================================

const projectId = process.env.FIREBASE_PROJECT_ID;
const clientEmail = process.env.FIREBASE_CLIENT_EMAIL;
const privateKey = process.env.FIREBASE_PRIVATE_KEY;

if (!projectId) {
  throw new Error("Missing FIREBASE_PROJECT_ID");
}

if (!clientEmail) {
  throw new Error("Missing FIREBASE_CLIENT_EMAIL");
}

if (!privateKey) {
  throw new Error("Missing FIREBASE_PRIVATE_KEY");
}

initializeApp({
  credential: cert({
    projectId: projectId,
    clientEmail: clientEmail,
    privateKey: privateKey.replace(/\\n/g, "\n")
  })
});

const db = getFirestore();

// ==========================================
// STATUS
// ==========================================

app.get("/api/status", (req, res) => {
  res.json({
    online: true,
    service: "LittleBigAdventure",
    firebase: true
  });
});

// ==========================================
// FIREBASE CONNECTION TEST
// ==========================================

app.get("/api/firebase-test", async (req, res) => {
  try {
    const testRef = db.collection("_system").doc("server");

    await testRef.set({
      online: true,
      service: "LittleBigAdventure",
      updatedAt: new Date().toISOString()
    });

    const snapshot = await testRef.get();

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

// ==========================================
// HEALTH CHECK
// ==========================================

app.get("/health", (req, res) => {
  res.status(200).send("LittleBigAdventure is online");
});

// ==========================================
// 404
// ==========================================

app.use((req, res) => {
  res.status(404).json({
    error: "Not Found"
  });
});

// ==========================================
// START SERVER
// ==========================================

const PORT = process.env.PORT || 10000;

app.listen(PORT, "0.0.0.0", () => {
  console.log("================================");
  console.log("LittleBigAdventure server started");
  console.log("Port: " + PORT);
  console.log("Firebase Admin connected");
  console.log("================================");
});
