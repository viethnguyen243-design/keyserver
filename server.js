const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const fs = require("fs");
const path = require("path");

const app = express();
app.use(cors());
app.use(bodyParser.json());
app.use(express.static("public"));

const SECRET = "LixVip2026_BiMat";
const DB_FILE = path.join(__dirname, "public", "db.json");
const ADMIN = {
  username: "admin",
  passwordHash: bcrypt.hashSync("admin123", 10)
};

function loadDB() {
  if (!fs.existsSync(DB_FILE)) {
    fs.mkdirSync(path.dirname(DB_FILE), { recursive: true });
    fs.writeFileSync(DB_FILE, JSON.stringify({ keys: [] }));
  }
  try { return JSON.parse(fs.readFileSync(DB_FILE)); }
  catch (e) { return { keys: [] }; }
}
function saveDB(d) { fs.writeFileSync(DB_FILE, JSON.stringify(d, null, 2)); }

function auth(req, res, next) {
  const t = req.headers["authorization"];
  if (!t) return res.status(401).json({ error: "Chua dang nhap" });
  try { jwt.verify(t.replace("Bearer ", ""), SECRET); next(); }
  catch { res.status(401).json({ error: "Token sai" }); }
}

app.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  if (username !== ADMIN.username || !bcrypt.compareSync(password, ADMIN.passwordHash))
    return res.status(401).json({ error: "Sai tai khoan" });
  res.json({ token: jwt.sign({ username }, SECRET, { expiresIn: "7d" }) });
});

function durMs(t) {
  const M = { "1h":3600000, "1d":86400000, "1w":604800000, "1m":2592000000, "1y":31536000000 };
  return M[t] || null;
}
function randKey(n = 20) {
  const c = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let o = "";
  for (let i = 0; i < n; i++) o += c[Math.floor(Math.random() * c.length)];
  return o;
}

app.post("/api/create-key", auth, (req, res) => {
  const { duration, quantity, maxUses } = req.body;
  const db = loadDB();
  const qty = Math.max(1, Math.min(1000, parseInt(quantity) || 1));
  const max = Math.max(0, parseInt(maxUses) || 0);
  const ms = durMs(duration);
  const now = Date.now();
  const created = [];
  for (let i = 0; i < qty; i++) {
    const key = randKey();
    db.keys.push({ key, duration, createdAt: now, expiresAt: ms ? now + ms : null, maxUses: max, usedBy: [] });
    created.push(key);
  }
  saveDB(db);
  res.json({ success: true, keys: created });
});

app.delete("/api/delete-key/:key", auth, (req, res) => {
  const db = loadDB();
  const b = db.keys.length;
  db.keys = db.keys.filter(k => k.key !== req.params.key);
  saveDB(db);
  res.json({ success: true, deleted: b - db.keys.length });
});

app.get("/api/keys", auth, (req, res) => {
  res.json({ keys: loadDB().keys });
});

app.post("/api/check-key", (req, res) => {
  const { key, uid } = req.body;
  if (!uid) return res.json({ valid: false, reason: "Thieu UID" });
  const db = loadDB();
  const item = db.keys.find(k => k.key === key);
  if (!item) return res.json({ valid: false, reason: "Key khong ton tai" });
  if (item.expiresAt && Date.now() > item.expiresAt)
    return res.json({ valid: false, reason: "Key het han" });
  if (!Array.isArray(item.usedBy)) item.usedBy = [];
  if (item.usedBy.includes(uid)) return res.json({ valid: true, msg: "Da kich hoat" });
  if (item.maxUses === 1 && item.usedBy.length >= 1)
    return res.json({ valid: false, reason: "Key dung cho may khac" });
  if (item.maxUses > 1 && item.usedBy.length >= item.maxUses)
    return res.json({ valid: false, reason: "Key het slot" });
  item.usedBy.push(uid);
  saveDB(db);
  res.json({ valid: true, msg: "Kich hoat thanh cong" });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("Server chay port " + PORT));
