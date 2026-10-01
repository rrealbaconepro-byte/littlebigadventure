const express = require("express");

const { initializeApp, cert } = require("firebase-admin/app");
const { getFirestore } = require("firebase-admin/firestore");

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

const app = express();

app.use(express.json({ limit: "1mb" }));

app.get("/api/status", (req, res) => {
  res.json({
    online: true,
    service: "LittleBigAdventure",
    firebase: true
  });
});

app.get("/api/firebase-test", async (req, res) => {
  try {
    const ref = db.collection("_system").doc("server");

    await ref.set({
      online: true,
      service: "LittleBigAdventure",
      updatedAt: new Date()
    });

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

app.use((req, res) => {
  res.status(404).json({
    error: "Not Found"
  });
});

const PORT = process.env.PORT || 10000;

app.listen(PORT, "0.0.0.0", () => {
  console.log("LittleBigAdventure server started");
  console.log("Port: " + PORT);
  console.log("Firebase Admin: connected");
});
