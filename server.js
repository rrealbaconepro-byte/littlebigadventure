const express = require("express");
const { initializeApp, cert } = require("firebase-admin/app");
const { getFirestore } = require("firebase-admin/firestore");

const app = express();

app.use(express.json({ limit: "1mb" }));

const raw = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;

if (!raw) {
  throw new Error("Missing FIREBASE_SERVICE_ACCOUNT_JSON");
}

let serviceAccount;

try {
  serviceAccount = JSON.parse(raw);
} catch {
  throw new Error("FIREBASE_SERVICE_ACCOUNT_JSON is not valid JSON");
}

initializeApp({
  credential: cert({
    projectId: serviceAccount.project_id,
    clientEmail: serviceAccount.client_email,
    privateKey: serviceAccount.private_key.replace(/\\n/g, "\n")
  })
});

const db = getFirestore();

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
      updatedAt: new Date().toISOString()
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

app.get("/health", (req, res) => {
  res.status(200).send("LittleBigAdventure is online");
});

app.use((req, res) => {
  res.status(404).json({
    error: "Not Found"
  });
});

const PORT = process.env.PORT || 10000;

app.listen(PORT, "0.0.0.0", () => {
  console.log("LittleBigAdventure server started on port " + PORT);
});
