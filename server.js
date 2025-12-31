require("dotenv").config();
const express = require("express");
const cors = require("cors");
const mysql = require("mysql");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
app.use(cors({ origin: "http://localhost:3000" }));
app.use(express.json());

// MySQL connection
const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "", 
  database: "food_app",
});

db.connect((err) => {
  if (err) console.error("MySQL error:", err);
  else console.log("MySQL connected");
});


const auth = (req, res, next) => {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ message: "No token provided" });

  const token = header.split(" ")[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    return res.status(401).json({ message: "Invalid token" });
  }
};


app.post("/api/register", async (req, res) => {
  const { name, email, password } = req.body;
  const hashed = await bcrypt.hash(password, 10);

  const sql = "INSERT INTO users (name, email, password) VALUES (?, ?, ?)";
  db.query(sql, [name, email, hashed], (err) => {
    if (err) return res.status(400).json({ message: "Email already exists" });
    res.json({ message: "Registered successfully" });
  });
});


app.post("/api/login", (req, res) => {
  const { email, password } = req.body;
  const sql = "SELECT * FROM users WHERE email = ?";
  
  db.query(sql, [email], async (err, results) => {
    if (err) return res.status(500).json({ message: "Database error" });
    if (!results.length) return res.status(401).json({ message: "Invalid credentials" });

    const user = results[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ message: "Invalid credentials" });

    const token = jwt.sign(
      { id: user.id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.json({
      token,
      user: { id: user.id, name: user.name, email: user.email },
    });
  });
});


app.get("/api/profile", auth, (req, res) => {
  res.json({ message: "Protected route accessed", user: req.user });
});

app.listen(5000, () => console.log("Server running on http://localhost:5000"));
