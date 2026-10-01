const express = require("express");
const path = require("path");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const { Pool } = require("pg");

const app = express();
const PORT = process.env.PORT || 10000;

// ==================================================
// DATABASE
// ==================================================

if (!process.env.DATABASE_URL) {
  throw new Error("Missing DATABASE_URL");
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl:
    process.env.NODE_ENV === "production"
      ? { rejectUnauthorized: false }
      : false
});

app.set("trust proxy", 1);

app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));

// ==================================================
// DATABASE SETUP
// ==================================================

async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(32) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      email VARCHAR(255),
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS sessions (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      token_hash TEXT UNIQUE NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS profiles (
      user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
      display_name VARCHAR(64),
      bio TEXT DEFAULT '',
      avatar_url TEXT DEFAULT '',
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS posts (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      content TEXT NOT NULL,
      image_url TEXT DEFAULT '',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS levels (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      title VARCHAR(100) NOT NULL,
      description TEXT DEFAULT '',
      image_url TEXT DEFAULT '',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS sessions_token_hash_idx
    ON sessions(token_hash);

    CREATE INDEX IF NOT EXISTS posts_created_at_idx
    ON posts(created_at DESC);

    CREATE INDEX IF NOT EXISTS levels_created_at_idx
    ON levels(created_at DESC);
  `);

  console.log("Render PostgreSQL connected");
}

// ==================================================
// SESSION HELPERS
// ==================================================

function hashToken(token) {
  return crypto
    .createHash("sha256")
    .update(token)
    .digest("hex");
}

function createToken() {
  return crypto.randomBytes(32).toString("hex");
}

function setSessionCookie(res, token) {
  const secure =
    process.env.NODE_ENV === "production"
      ? "; Secure"
      : "";

  res.setHeader(
    "Set-Cookie",
    `lba_session=${token}; Path=/; HttpOnly; SameSite=Lax${secure}`
  );
}

function clearSessionCookie(res) {
  res.setHeader(
    "Set-Cookie",
    "lba_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"
  );
}

function getSessionToken(req) {
  const cookieHeader = req.headers.cookie;

  if (!cookieHeader) {
    return null;
  }

  const cookies = {};

  cookieHeader.split(";").forEach((cookie) => {
    const index = cookie.indexOf("=");

    if (index === -1) {
      return;
    }

    const key = cookie.slice(0, index).trim();
    const value = cookie.slice(index + 1).trim();

    cookies[key] = decodeURIComponent(value);
  });

  return cookies.lba_session || null;
}

// ==================================================
// AUTH
// ==================================================

async function getUserFromRequest(req) {
  const token = getSessionToken(req);

  if (!token) {
    return null;
  }

  const tokenHash = hashToken(token);

  const result = await pool.query(
    `
    SELECT
      u.id,
      u.username,
      u.email,
      u.created_at
    FROM sessions s
    JOIN users u
      ON u.id = s.user_id
    WHERE s.token_hash = $1
    `,
    [tokenHash]
  );

  return result.rows[0] || null;
}

async function requireAuth(req, res, next) {
  try {
    const user = await getUserFromRequest(req);

    if (!user) {
      return res.status(401).json({
        authenticated: false,
        error: "Login required"
      });
    }

    req.user = user;
    next();
  } catch (error) {
    console.error("Authentication error:", error);

    res.status(500).json({
      error: "Authentication failed"
    });
  }
}

// ==================================================
// STATUS
// ==================================================

app.get("/api/status", async (req, res) => {
  try {
    await pool.query("SELECT 1");

    res.json({
      online: true,
      service: "LittleBigAdventure",
      database: true
    });
  } catch (error) {
    console.error("Database status error:", error);

    res.status(500).json({
      online: true,
      service: "LittleBigAdventure",
      database: false
    });
  }
});

// ==================================================
// SIGN UP
// ==================================================

app.post("/api/auth/signup", async (req, res) => {
  try {
    const {
      username,
      password,
      email = ""
    } = req.body;

    if (!username || !password) {
      return res.status(400).json({
        error: "Username and password are required"
      });
    }

    if (username.length < 3 || username.length > 32) {
      return res.status(400).json({
        error: "Username must be between 3 and 32 characters"
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        error: "Password must be at least 6 characters"
      });
    }

    if (!/^[a-zA-Z0-9_-]+$/.test(username)) {
      return res.status(400).json({
        error: "Username contains invalid characters"
      });
    }

    const existing = await pool.query(
      "SELECT id FROM users WHERE LOWER(username) = LOWER($1)",
      [username]
    );

    if (existing.rows.length > 0) {
      return res.status(409).json({
        error: "Username already exists"
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const userResult = await pool.query(
      `
      INSERT INTO users
        (username, password_hash, email)
      VALUES
        ($1, $2, $3)
      RETURNING id, username, email, created_at
      `,
      [
        username,
        passwordHash,
        email || null
      ]
    );

    const user = userResult.rows[0];

    await pool.query(
      `
      INSERT INTO profiles
        (user_id, display_name)
      VALUES
        ($1, $2)
      `,
      [user.id, user.username]
    );

    const token = createToken();

    await pool.query(
      `
      INSERT INTO sessions
        (user_id, token_hash)
      VALUES
        ($1, $2)
      `,
      [user.id, hashToken(token)]
    );

    setSessionCookie(res, token);

    res.json({
      success: true,
      user
    });
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
    const {
      username,
      password
    } = req.body;

    if (!username || !password) {
      return res.status(400).json({
        error: "Username and password are required"
      });
    }

    const result = await pool.query(
      `
      SELECT
        id,
        username,
        email,
        password_hash,
        created_at
      FROM users
      WHERE LOWER(username) = LOWER($1)
      `,
      [username]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({
        error: "Invalid username or password"
      });
    }

    const user = result.rows[0];

    const validPassword = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!validPassword) {
      return res.status(401).json({
        error: "Invalid username or password"
      });
    }

    await pool.query(
      "DELETE FROM sessions WHERE user_id = $1",
      [user.id]
    );

    const token = createToken();

    await pool.query(
      `
      INSERT INTO sessions
        (user_id, token_hash)
      VALUES
        ($1, $2)
      `,
      [user.id, hashToken(token)]
    );

    setSessionCookie(res, token);

    delete user.password_hash;

    res.json({
      success: true,
      user
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
// LOGOUT
// ==================================================

app.post("/api/auth/logout", async (req, res) => {
  try {
    const token = getSessionToken(req);

    if (token) {
      await pool.query(
        "DELETE FROM sessions WHERE token_hash = $1",
        [hashToken(token)]
      );
    }

    clearSessionCookie(res);

    res.json({
      success: true
    });
  } catch (error) {
    console.error("Logout error:", error);

    res.status(500).json({
      success: false,
      error: "Logout failed"
    });
  }
});

// ==================================================
// CURRENT USER
// ==================================================

app.get("/api/auth/me", async (req, res) => {
  try {
    const user = await getUserFromRequest(req);

    if (!user) {
      return res.json({
        authenticated: false,
        user: null
      });
    }

    res.json({
      authenticated: true,
      user
    });
  } catch (error) {
    console.error("Auth check error:", error);

    res.status(500).json({
      authenticated: false,
      error: "Authentication check failed"
    });
  }
});

// ==================================================
// MY PROFILE
// ==================================================

app.get("/api/profile/me", requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT
        u.id,
        u.username,
        u.email,
        u.created_at,
        p.display_name,
        p.bio,
        p.avatar_url
      FROM users u
      LEFT JOIN profiles p
        ON p.user_id = u.id
      WHERE u.id = $1
      `,
      [req.user.id]
    );

    res.json({
      profile: result.rows[0]
    });
  } catch (error) {
    console.error("Profile error:", error);

    res.status(500).json({
      error: "Failed to load profile"
    });
  }
});

// ==================================================
// UPDATE MY PROFILE
// ==================================================

app.post("/api/profile/me", requireAuth, async (req, res) => {
  try {
    const {
      displayName = "",
      bio = "",
      avatarUrl = ""
    } = req.body;

    await pool.query(
      `
      UPDATE profiles
      SET
        display_name = $1,
        bio = $2,
        avatar_url = $3,
        updated_at = CURRENT_TIMESTAMP
      WHERE user_id = $4
      `,
      [
        displayName,
        bio,
        avatarUrl,
        req.user.id
      ]
    );

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
// PUBLIC PROFILE
// ==================================================

app.get("/api/profile/:username", async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT
        u.id,
        u.username,
        u.created_at,
        p.display_name,
        p.bio,
        p.avatar_url
      FROM users u
      LEFT JOIN profiles p
        ON p.user_id = u.id
      WHERE LOWER(u.username) = LOWER($1)
      `,
      [req.params.username]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        error: "Player not found"
      });
    }

    res.json({
      profile: result.rows[0]
    });
  } catch (error) {
    console.error("Public profile error:", error);

    res.status(500).json({
      error: "Failed to load profile"
    });
  }
});

// ==================================================
// NEW PLAYERS
// ==================================================

app.get("/api/players", async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        u.username,
        p.display_name,
        p.avatar_url,
        u.created_at
      FROM users u
      LEFT JOIN profiles p
        ON p.user_id = u.id
      ORDER BY u.created_at DESC
      LIMIT 20
    `);

    res.json({
      players: result.rows
    });
  } catch (error) {
    console.error("Players error:", error);

    res.status(500).json({
      error: "Failed to load players"
    });
  }
});

// ==================================================
// POSTS
// ==================================================

app.get("/api/posts", async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        posts.id,
        posts.content,
        posts.image_url,
        posts.created_at,
        users.username,
        profiles.display_name,
        profiles.avatar_url
      FROM posts
      JOIN users
        ON users.id = posts.user_id
      LEFT JOIN profiles
        ON profiles.user_id = users.id
      ORDER BY posts.created_at DESC
      LIMIT 50
    `);

    res.json({
      posts: result.rows
    });
  } catch (error) {
    console.error("Posts error:", error);

    res.status(500).json({
      error: "Failed to load posts"
    });
  }
});

// ==================================================
// CREATE POST
// ==================================================

app.post("/api/posts", requireAuth, async (req, res) => {
  try {
    const {
      content,
      imageUrl = ""
    } = req.body;

    if (!content || !content.trim()) {
      return res.status(400).json({
        error: "Post cannot be empty"
      });
    }

    if (content.length > 2000) {
      return res.status(400).json({
        error: "Post is too long"
      });
    }

    const result = await pool.query(
      `
      INSERT INTO posts
        (user_id, content, image_url)
      VALUES
        ($1, $2, $3)
      RETURNING *
      `,
      [
        req.user.id,
        content.trim(),
        imageUrl
      ]
    );

    res.json({
      success: true,
      post: result.rows[0]
    });
  } catch (error) {
    console.error("Create post error:", error);

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
    const result = await pool.query(`
      SELECT
        levels.id,
        levels.title,
        levels.description,
        levels.image_url,
        levels.created_at,
        users.username
      FROM levels
      JOIN users
        ON users.id = levels.user_id
      ORDER BY levels.created_at DESC
      LIMIT 50
    `);

    res.json({
      levels: result.rows
    });
  } catch (error) {
    console.error("Levels error:", error);

    res.status(500).json({
      error: "Failed to load levels"
    });
  }
});

// ==================================================
// CREATE LEVEL
// ==================================================

app.post("/api/levels", requireAuth, async (req, res) => {
  try {
    const {
      title,
      description = "",
      imageUrl = ""
    } = req.body;

    if (!title || !title.trim()) {
      return res.status(400).json({
        error: "Level title is required"
      });
    }

    if (title.length > 100) {
      return res.status(400).json({
        error: "Level title is too long"
      });
    }

    const result = await pool.query(
      `
      INSERT INTO levels
        (user_id, title, description, image_url)
      VALUES
        ($1, $2, $3, $4)
      RETURNING *
      `,
      [
        req.user.id,
        title.trim(),
        description,
        imageUrl
      ]
    );

    res.json({
      success: true,
      level: result.rows[0]
    });
  } catch (error) {
    console.error("Create level error:", error);

    res.status(500).json({
      success: false,
      error: "Failed to create level"
    });
  }
});

// ==================================================
// SINGLE LEVEL
// ==================================================

app.get("/api/levels/:id", async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT
        levels.id,
        levels.title,
        levels.description,
        levels.image_url,
        levels.created_at,
        users.username
      FROM levels
      JOIN users
        ON users.id = levels.user_id
      WHERE levels.id = $1
      `,
      [req.params.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        error: "Level not found"
      });
    }

    res.json({
      level: result.rows[0]
    });
  } catch (error) {
    console.error("Level error:", error);

    res.status(500).json({
      error: "Failed to load level"
    });
  }
});

// ==================================================
// STATIC WEBSITE
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

async function startServer() {
  try {
    await initDatabase();

    app.listen(PORT, "0.0.0.0", () => {
      console.log("========================================");
      console.log("LittleBigAdventure server running");
      console.log("Port: " + PORT);
      console.log("Render PostgreSQL connected");
      console.log("========================================");
    });
  } catch (error) {
    console.error("Failed to start server:", error);
    process.exit(1);
  }
}

startServer();
