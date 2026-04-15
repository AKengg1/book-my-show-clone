// ─────────────────────────────────────────────────────────────────────────────
// DB SETUP (run once)
// ─────────────────────────────────────────────────────────────────────────────
//  CREATE TABLE seats (
//      id SERIAL PRIMARY KEY,
//      name VARCHAR(255),
//      isbooked INT DEFAULT 0
//  );
//  INSERT INTO seats (isbooked)
//  SELECT 0 FROM generate_series(1, 20);
//
//  CREATE TABLE users (
//      id SERIAL PRIMARY KEY,
//      name VARCHAR(255) NOT NULL,
//      email VARCHAR(255) UNIQUE NOT NULL,
//      password_hash VARCHAR(255) NOT NULL,
//      created_at TIMESTAMPTZ DEFAULT NOW()
//  );
// ─────────────────────────────────────────────────────────────────────────────

import express from "express";
import pg from "pg";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { dirname } from "path";
import { fileURLToPath } from "url";
import cors from "cors";

const __dirname = dirname(fileURLToPath(import.meta.url));
const port = process.env.PORT || 8080;

// ─── IMPORTANT: set this in your environment, never hardcode in production ───
const JWT_SECRET = process.env.JWT_SECRET || "change_this_secret_in_production";
const SALT_ROUNDS = 10;

const pool = new pg.Pool({
  host: "localhost",
  port: 5432,
  user: "postgres",
  password: "postgres",
  database: "sql_class_2_db",
  max: 20,
  connectionTimeoutMillis: 0,
  idleTimeoutMillis: 0,
});

const app = new express();
app.use(cors());
app.use(express.json()); // needed to parse JSON request bodies

// ─────────────────────────────────────────────────────────────────────────────
// AUTH MIDDLEWARE
// Reads "Authorization: Bearer <token>" header and attaches req.user
// ─────────────────────────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  const authHeader = req.headers["authorization"];
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Unauthorized: missing token" });
  }
  const token = authHeader.split(" ")[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded; // { id, name, email }
    next();
  } catch (err) {
    return res.status(401).json({ error: "Unauthorized: invalid or expired token" });
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// STATIC
// ─────────────────────────────────────────────────────────────────────────────
app.get("/", (req, res) => {
  res.sendFile(__dirname + "/index.html");
});

// ─────────────────────────────────────────────────────────────────────────────
// REGISTER  POST /register
// Body: { name, email, password }
// ─────────────────────────────────────────────────────────────────────────────
app.post("/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ error: "Name, email and password are required." });
    }
    if (password.length < 6) {
      return res.status(400).json({ error: "Password must be at least 6 characters." });
    }

    // Check if email already exists
    const existing = await pool.query("SELECT id FROM users WHERE email = $1", [email]);
    if (existing.rowCount > 0) {
      return res.status(409).json({ error: "Email already registered." });
    }

    // Hash password and insert
    const password_hash = await bcrypt.hash(password, SALT_ROUNDS);
    const result = await pool.query(
      "INSERT INTO users (name, email, password_hash) VALUES ($1, $2, $3) RETURNING id, name, email",
      [name, email, password_hash]
    );

    const user = result.rows[0];
    const token = jwt.sign({ id: user.id, name: user.name, email: user.email }, JWT_SECRET, {
      expiresIn: "7d",
    });

    res.status(201).json({ token, name: user.name, email: user.email });
  } catch (ex) {
    console.error(ex);
    res.status(500).json({ error: "Internal server error." });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// LOGIN  POST /login
// Body: { email, password }
// ─────────────────────────────────────────────────────────────────────────────
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required." });
    }

    const result = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    if (result.rowCount === 0) {
      return res.status(401).json({ error: "Invalid email or password." });
    }

    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
      return res.status(401).json({ error: "Invalid email or password." });
    }

    const token = jwt.sign({ id: user.id, name: user.name, email: user.email }, JWT_SECRET, {
      expiresIn: "7d",
    });

    res.json({ token, name: user.name, email: user.email });
  } catch (ex) {
    console.error(ex);
    res.status(500).json({ error: "Internal server error." });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// GET ALL SEATS  GET /seats  (protected)
// ─────────────────────────────────────────────────────────────────────────────
app.get("/seats", requireAuth, async (req, res) => {
  const result = await pool.query("SELECT * FROM seats");
  res.send(result.rows);
});

// ─────────────────────────────────────────────────────────────────────────────
// BOOK A SEAT  PUT /:id/:name  (protected)
// ─────────────────────────────────────────────────────────────────────────────
app.put("/:id/:name", requireAuth, async (req, res) => {
  try {
    const id = req.params.id;
    const name = req.params.name;

    const conn = await pool.connect();
    await conn.query("BEGIN");

    const sql = "SELECT * FROM seats WHERE id = $1 AND isbooked = 0 FOR UPDATE";
    const result = await conn.query(sql, [id]);

    if (result.rowCount === 0) {
      await conn.query("ROLLBACK");
      conn.release();
      return res.json({ error: "Seat already booked" });
    }

    const sqlU = "UPDATE seats SET isbooked = 1, name = $2 WHERE id = $1";
    const updateResult = await conn.query(sqlU, [id, name]);

    await conn.query("COMMIT");
    conn.release();
    res.send(updateResult);
  } catch (ex) {
    console.error(ex);
    res.status(500).json({ error: "Internal server error." });
  }
});

app.listen(port, () => console.log("Server starting on port: " + port));