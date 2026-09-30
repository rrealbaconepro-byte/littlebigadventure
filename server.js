const express = require("express");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 10000;

// Serve static files
app.use(express.static(__dirname));

// Always load index.html at the homepage
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

// Status
app.get("/api/status", (req, res) => {
  res.json({
    online: true,
    name: "LittleBigAdventure",
    status: "online"
  });
});

// Start server
app.listen(PORT, "0.0.0.0", () => {
  console.log(`LittleBigAdventure running on port ${PORT}`);
});
