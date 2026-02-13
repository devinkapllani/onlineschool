import "dotenv/config";
import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import multer from "multer";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import crypto from "crypto";
import Database from "better-sqlite3";

const app = express();
const PORT = Number(process.env.PORT || 3000);
const APP_URL = process.env.APP_URL || `http://localhost:${PORT}`;
const JWT_SECRET = process.env.JWT_SECRET || "dev_secret_change_me";
const OPENAI_API_KEY = process.env.OPENAI_API_KEY || "";
const AI_MODEL = process.env.AI_MODEL || "gpt-4.1-mini";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// -------------------- STATIC --------------------
app.use(express.static(path.join(__dirname, "public")));
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

// -------------------- MIDDLEWARE --------------------
app.use(cors({ origin: APP_URL, credentials: true }));
app.use(express.json({ limit: "8mb" }));
app.use(cookieParser());

// -------------------- DB --------------------
const db = new Database("data.db");
db.pragma("journal_mode = WAL");

// tables
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  pass_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('student','teacher','admin')) DEFAULT 'student',
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS books (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  author TEXT NOT NULL,
  subject TEXT NOT NULL,
  level TEXT NOT NULL,
  year INTEGER,
  isbn TEXT,
  summary TEXT,
  topics_json TEXT DEFAULT '[]',
  cover_path TEXT,
  created_by INTEGER,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS quizzes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  book_id INTEGER NOT NULL,
  title TEXT NOT NULL,
  created_by INTEGER,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS quiz_questions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  quiz_id INTEGER NOT NULL,
  question TEXT NOT NULL,
  answer TEXT NOT NULL,
  points INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS groups (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  created_by INTEGER NOT NULL,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS group_members (
  group_id INTEGER NOT NULL,
  user_id INTEGER NOT NULL,
  PRIMARY KEY (group_id, user_id)
);

CREATE TABLE IF NOT EXISTS assignments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  group_id INTEGER NOT NULL,
  quiz_id INTEGER NOT NULL,
  title TEXT NOT NULL,
  due_date TEXT,
  created_by INTEGER NOT NULL,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS submissions (
  assignment_id INTEGER NOT NULL,
  student_id INTEGER NOT NULL,
  answers_json TEXT NOT NULL,
  auto_score INTEGER NOT NULL DEFAULT 0,
  auto_max INTEGER NOT NULL DEFAULT 0,
  teacher_score INTEGER,
  teacher_feedback TEXT,
  submitted_at TEXT DEFAULT (datetime('now')),
  PRIMARY KEY (assignment_id, student_id)
);
`);

function one(sql, params = []) {
  return db.prepare(sql).get(params);
}
function all(sql, params = []) {
  return db.prepare(sql).all(params);
}
function run(sql, params = []) {
  return db.prepare(sql).run(params);
}
function safeJsonParse(s, fallback) {
  try { return JSON.parse(s); } catch { return fallback; }
}
function ensureColumn(table, col, type) {
  const cols = all(`PRAGMA table_info(${table})`).map(r => r.name);
  if (!cols.includes(col)) {
    db.exec(`ALTER TABLE ${table} ADD COLUMN ${col} ${type}`);
  }
}

// --- migrations (safe) ---
ensureColumn("submissions", "teacher_max", "INTEGER");
ensureColumn("submissions", "ai_feedback", "TEXT");
ensureColumn("submissions", "graded_at", "TEXT");

// -------------------- AUTH HELPERS --------------------
function signSession(user) {
  return jwt.sign(
    { id: user.id, email: user.email, name: user.name, role: user.role },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}
function setSessionCookie(res, token) {
  res.cookie("session", token, {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 7 * 24 * 3600 * 1000
  });
}
function authMiddleware(req, res, next) {
  const token = req.cookies?.session;
  if (!token) return res.status(401).json({ error: "Not authenticated" });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "Invalid/expired session" });
  }
}
function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: "Not authenticated" });
    if (!roles.includes(req.user.role)) return res.status(403).json({ error: "Forbidden" });
    next();
  };
}

// -------------------- BOOTSTRAP ADMIN --------------------
(function bootstrapAdmin() {
  const exists = one("SELECT id FROM users WHERE role='admin' LIMIT 1");
  if (exists) return;

  const email = (process.env.BOOTSTRAP_ADMIN_EMAIL || "admin@school.local").toLowerCase();
  const pass = process.env.BOOTSTRAP_ADMIN_PASSWORD || "AdminPass123!";
  const name = process.env.BOOTSTRAP_ADMIN_NAME || "Main Admin";
  const pass_hash = bcrypt.hashSync(pass, 10);

  run("INSERT INTO users (name, email, pass_hash, role) VALUES (?, ?, ?, 'admin')", [
    name, email, pass_hash
  ]);

  console.log("\n[BOOTSTRAP] Admin created:");
  console.log(" Email:", email);
  console.log(" Password:", pass);
})();

// -------------------- UPLOADS (better filenames + extensions) --------------------
const uploadDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const ext = (path.extname(file.originalname || "") || ".jpg").toLowerCase();
    cb(null, `cover_${Date.now()}_${crypto.randomBytes(6).toString("hex")}${ext}`);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 6 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const ok = ["image/jpeg", "image/png", "image/webp", "image/jpg"].includes(file.mimetype);
    cb(ok ? null : new Error("Only JPG/PNG/WEBP allowed"), ok);
  }
});

// -------------------- PAGE GUARDS --------------------
app.get("/dashboard.html", authMiddleware, requireRole("teacher","admin"), (req, res) => {
  res.sendFile(path.join(__dirname, "public", "dashboard.html"));
});
app.get("/student.html", authMiddleware, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "student.html"));
});
app.get("/admin.html", authMiddleware, requireRole("admin"), (req, res) => {
  res.sendFile(path.join(__dirname, "public", "admin.html"));
});
app.get("/teacher.html", authMiddleware, requireRole("teacher","admin"), (req, res) => {
  res.sendFile(path.join(__dirname, "public", "teacher.html"));
});
// ===================== FIX: Admin role update (support POST + PUT) =====================
app.post("/api/admin/users/:id/role", authMiddleware, requireRole("admin"), (req, res) => {
  const id = Number(req.params.id);
  const { role } = req.body || {};
  if (!["student", "teacher", "admin"].includes(role)) {
    return res.status(400).json({ error: "Invalid role" });
  }
  run("UPDATE users SET role=? WHERE id=?", [role, id]);
  res.json({ ok: true });
});

// (keep your existing PUT if you want, but now POST works too)
app.put("/api/admin/users/:id/role", authMiddleware, requireRole("admin"), (req, res) => {
  const id = Number(req.params.id);
  const { role } = req.body || {};
  if (!["student", "teacher", "admin"].includes(role)) {
    return res.status(400).json({ error: "Invalid role" });
  }
  run("UPDATE users SET role=? WHERE id=?", [role, id]);
  res.json({ ok: true });
});


// ===================== FIX: Teacher grading center submissions endpoint =====================
// This fixes: Cannot GET /api/teacher/assignments/:id/submissions
app.get(
  "/api/teacher/assignments/:id/submissions",
  authMiddleware,
  requireRole("teacher", "admin"),
  (req, res) => {
    const assignmentId = Number(req.params.id);

    // Only the teacher who created the assignment can view submissions (admins can view all)
    if (req.user.role !== "admin") {
      const own = one("SELECT id FROM assignments WHERE id=? AND created_by=?", [assignmentId, req.user.id]);
      if (!own) return res.status(403).json({ error: "Forbidden" });
    }

    const rows = all(
      `
      SELECT
        s.assignment_id,
        s.student_id,
        u.name AS student_name,
        u.email AS student_email,
        s.answers_json,
        s.auto_score,
        s.auto_max,
        s.teacher_score,
        s.teacher_feedback,
        s.submitted_at
      FROM submissions s
      JOIN users u ON u.id = s.student_id
      WHERE s.assignment_id = ?
      ORDER BY s.submitted_at DESC
      `,
      [assignmentId]
    );

    const submissions = rows.map(r => ({
      assignment_id: r.assignment_id,
      student_id: r.student_id,
      student_name: r.student_name,
      student_email: r.student_email,
      answers: safeJsonParse(r.answers_json || "[]", []),
      auto_score: r.auto_score ?? 0,
      auto_max: r.auto_max ?? 0,
      teacher_score: r.teacher_score,
      teacher_feedback: r.teacher_feedback,
      submitted_at: r.submitted_at
    }));

    res.json({ submissions });
  }
);

app.get("/", (req, res) => res.redirect("/login.html"));

// -------------------- AUTH ROUTES --------------------
app.post("/api/auth/register", async (req, res) => {
  const { name, email, password } = req.body || {};
  if (!name || !email || !password) return res.status(400).json({ error: "Missing fields" });

  const emailNorm = String(email).toLowerCase().trim();
  if (String(password).length < 8) return res.status(400).json({ error: "Password must be at least 8 characters" });

  const exists = one("SELECT id FROM users WHERE email=?", [emailNorm]);
  if (exists) return res.status(409).json({ error: "Email already registered" });

  const pass_hash = await bcrypt.hash(String(password), 10);
  run("INSERT INTO users (name, email, pass_hash, role) VALUES (?, ?, ?, 'student')", [
    String(name).trim(), emailNorm, pass_hash
  ]);

  const user = one("SELECT id,name,email,role FROM users WHERE email=?", [emailNorm]);
  setSessionCookie(res, signSession(user));
  res.json({ ok: true, user });
});

app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: "Missing fields" });

  const emailNorm = String(email).toLowerCase().trim();
  const row = one("SELECT * FROM users WHERE email=?", [emailNorm]);
  if (!row) return res.status(401).json({ error: "Invalid email or password" });

  const ok = await bcrypt.compare(String(password), row.pass_hash);
  if (!ok) return res.status(401).json({ error: "Invalid email or password" });

  const user = { id: row.id, name: row.name, email: row.email, role: row.role };
  setSessionCookie(res, signSession(user));
  res.json({ ok: true, user });
});

app.post("/api/auth/logout", (req, res) => {
  res.clearCookie("session");
  res.json({ ok: true });
});

app.get("/api/auth/me", authMiddleware, (req, res) => {
  res.json({ user: req.user });
});

// -------------------- ADMIN API --------------------
app.get("/api/admin/users", authMiddleware, requireRole("admin"), (req, res) => {
  const users = all("SELECT id,name,email,role,created_at FROM users ORDER BY id DESC");
  res.json({ users });
});

// admin.html uses POST -> keep POST
app.post("/api/admin/users/:id/role", authMiddleware, requireRole("admin"), (req, res) => {
  const id = Number(req.params.id);
  const { role } = req.body || {};
  if (!["student", "teacher", "admin"].includes(role)) return res.status(400).json({ error: "Invalid role" });

  run("UPDATE users SET role=? WHERE id=?", [role, id]);
  res.json({ ok: true });
});

// -------------------- BOOKS --------------------
app.get("/api/books", authMiddleware, (req, res) => {
  const rows = all("SELECT * FROM books ORDER BY created_at DESC");
  res.json({
    books: rows.map(r => ({
      ...r,
      topics: safeJsonParse(r.topics_json || "[]", []),
      cover_url: r.cover_path ? `/uploads/${r.cover_path}` : null
    }))
  });
});

app.post("/api/books", authMiddleware, requireRole("teacher","admin"), upload.single("cover"), (req, res) => {
  const { title, author, subject, level, year, isbn, summary, topics } = req.body || {};
  if (!title || !author || !subject || !level) return res.status(400).json({ error: "Missing required fields" });

  const topicsArr = String(topics || "")
    .split(",")
    .map(s => s.trim())
    .filter(Boolean);

  const cover_path = req.file?.filename || null;

  run(
    `INSERT INTO books (title, author, subject, level, year, isbn, summary, topics_json, cover_path, created_by)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      String(title).trim(),
      String(author).trim(),
      String(subject).trim(),
      String(level).trim(),
      year ? Number(year) : null,
      isbn ? String(isbn).trim() : null,
      summary ? String(summary).trim() : null,
      JSON.stringify(topicsArr),
      cover_path,
      req.user.id
    ]
  );

  res.json({ ok: true });
});

app.put("/api/books/:id", authMiddleware, requireRole("teacher","admin"), upload.single("cover"), (req, res) => {
  const id = Number(req.params.id);
  const existing = one("SELECT * FROM books WHERE id=?", [id]);
  if (!existing) return res.status(404).json({ error: "Book not found" });

  const body = req.body || {};
  const title = body.title ?? existing.title;
  const author = body.author ?? existing.author;
  const subject = body.subject ?? existing.subject;
  const level = body.level ?? existing.level;
  const year = body.year !== undefined ? (body.year ? Number(body.year) : null) : existing.year;
  const isbn = body.isbn !== undefined ? (body.isbn ? String(body.isbn).trim() : null) : existing.isbn;
  const summary = body.summary !== undefined ? (body.summary ? String(body.summary).trim() : null) : existing.summary;
  const topicsArr =
    body.topics !== undefined
      ? String(body.topics || "").split(",").map(s => s.trim()).filter(Boolean)
      : safeJsonParse(existing.topics_json || "[]", []);

  let cover_path = existing.cover_path;
  if (req.file?.filename) {
    // delete old
    if (existing.cover_path) {
      const oldPath = path.join(uploadDir, existing.cover_path);
      if (fs.existsSync(oldPath)) fs.unlinkSync(oldPath);
    }
    cover_path = req.file.filename;
  }

  run(
    `UPDATE books
     SET title=?, author=?, subject=?, level=?, year=?, isbn=?, summary=?, topics_json=?, cover_path=?
     WHERE id=?`,
    [
      String(title).trim(),
      String(author).trim(),
      String(subject).trim(),
      String(level).trim(),
      year,
      isbn,
      summary,
      JSON.stringify(topicsArr),
      cover_path,
      id
    ]
  );

  res.json({ ok: true });
});

app.delete("/api/books/:id", authMiddleware, requireRole("teacher","admin"), (req, res) => {
  const id = Number(req.params.id);
  const book = one("SELECT * FROM books WHERE id=?", [id]);
  if (!book) return res.status(404).json({ error: "Book not found" });

  if (book.cover_path) {
    const p = path.join(uploadDir, book.cover_path);
    if (fs.existsSync(p)) fs.unlinkSync(p);
  }

  const quizIds = all("SELECT id FROM quizzes WHERE book_id=?", [id]).map(x => x.id);
  for (const qid of quizIds) {
    const assignmentIds = all("SELECT id FROM assignments WHERE quiz_id=?", [qid]).map(x => x.id);
    for (const aid of assignmentIds) run("DELETE FROM submissions WHERE assignment_id=?", [aid]);
    run("DELETE FROM assignments WHERE quiz_id=?", [qid]);
    run("DELETE FROM quiz_questions WHERE quiz_id=?", [qid]);
  }
  run("DELETE FROM quizzes WHERE book_id=?", [id]);
  run("DELETE FROM books WHERE id=?", [id]);

  res.json({ ok: true });
});

// -------------------- QUIZZES --------------------
app.get("/api/books/:bookId/quizzes", authMiddleware, (req, res) => {
  const bookId = Number(req.params.bookId);
  const quizzes = all("SELECT * FROM quizzes WHERE book_id=? ORDER BY created_at DESC", [bookId]);
  const withQuestions = quizzes.map(q => ({
    ...q,
    questions: all("SELECT id,question,answer,points FROM quiz_questions WHERE quiz_id=?", [q.id])
  }));
  res.json({ quizzes: withQuestions });
});

app.post("/api/books/:bookId/quizzes", authMiddleware, requireRole("teacher","admin"), (req, res) => {
  const bookId = Number(req.params.bookId);
  const { title, questions } = req.body || {};
  if (!title || !Array.isArray(questions) || !questions.length) {
    return res.status(400).json({ error: "Quiz title and questions required" });
  }

  const book = one("SELECT id FROM books WHERE id=?", [bookId]);
  if (!book) return res.status(404).json({ error: "Book not found" });

  run("INSERT INTO quizzes (book_id, title, created_by) VALUES (?, ?, ?)", [
    bookId, String(title).trim(), req.user.id
  ]);
  const quizId = one("SELECT last_insert_rowid() AS id")?.id;

  const clean = questions
    .map(q => ({
      question: String(q.question || "").trim(),
      answer: String(q.answer || "").trim(),
      points: q.points ? Number(q.points) : 1
    }))
    .filter(x => x.question && x.answer);

  if (!clean.length) return res.status(400).json({ error: "Each question needs question+answer" });

  for (const q of clean) {
    run("INSERT INTO quiz_questions (quiz_id, question, answer, points) VALUES (?, ?, ?, ?)", [
      quizId, q.question, q.answer, q.points
    ]);
  }

  res.json({ ok: true, quizId });
});

// -------------------- GROUPS (classrooms) --------------------
app.get("/api/groups", authMiddleware, requireRole("teacher","admin"), (req, res) => {
  const groups = all("SELECT * FROM groups WHERE created_by=? ORDER BY created_at DESC", [req.user.id]);
  res.json({ groups });
});

app.post("/api/groups", authMiddleware, requireRole("teacher","admin"), (req, res) => {
  const { name } = req.body || {};
  if (!name) return res.status(400).json({ error: "Group name required" });

  run("INSERT INTO groups (name, created_by) VALUES (?, ?)", [String(name).trim(), req.user.id]);
  const groupId = one("SELECT last_insert_rowid() AS id")?.id;
  res.json({ ok: true, groupId });
});

app.get("/api/groups/:groupId/members", authMiddleware, requireRole("teacher","admin"), (req, res) => {
  const groupId = Number(req.params.groupId);
  const members = all(
    `SELECT u.id,u.name,u.email,u.role
     FROM group_members gm JOIN users u ON u.id=gm.user_id
     WHERE gm.group_id=? ORDER BY u.name`,
    [groupId]
  );
  res.json({ members });
});

app.post("/api/groups/:groupId/members", authMiddleware, requireRole("teacher","admin"), (req, res) => {
  const groupId = Number(req.params.groupId);
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ error: "Student email required" });

  const user = one("SELECT id,role FROM users WHERE email=?", [String(email).toLowerCase().trim()]);
  if (!user) return res.status(404).json({ error: "User not found (student must register first)" });
  if (user.role !== "student") return res.status(400).json({ error: "Only students can be added" });

  try {
    run("INSERT INTO group_members (group_id, user_id) VALUES (?, ?)", [groupId, user.id]);
  } catch {
    return res.status(409).json({ error: "Student already in group" });
  }
  res.json({ ok: true });
});

// -------------------- ASSIGNMENTS --------------------
("/api/teacher/assignments", authMiddleware, requireRole("teacher","admin"), (req, res) => {
  const rows = all(
    `SELECT a.*, g.name AS group_name, q.title AS quiz_title
     FROM assignments a
     JOIN groups g ON g.id=a.group_id
     JOIN quizzes q ON q.id=a.quiz_id
     WHERE a.created_by=?
     ORDER BY a.created_at DESC`,
    [req.user.id]
  );
  res.json({ assignments: rows });
});

app.post("/api/assignments", authMiddleware, requireRole("teacher","admin"), (req, res) => {
  const { group_id, quiz_id, title, due_date } = req.body || {};
  if (!group_id || !quiz_id || !title) return res.status(400).json({ error: "Missing fields" });

  const group = one("SELECT id FROM groups WHERE id=? AND created_by=?", [Number(group_id), req.user.id]);
  if (!group) return res.status(404).json({ error: "Group not found" });

  const quiz = one("SELECT id FROM quizzes WHERE id=?", [Number(quiz_id)]);
  if (!quiz) return res.status(404).json({ error: "Quiz not found" });

  run(
    "INSERT INTO assignments (group_id, quiz_id, title, due_date, created_by) VALUES (?, ?, ?, ?, ?)",
    [Number(group_id), Number(quiz_id), String(title).trim(), due_date ? String(due_date) : null, req.user.id]
  );

  const assignmentId = one("SELECT last_insert_rowid() AS id")?.id;
  res.json({ ok: true, assignmentId });
});

// Student view assignments + include teacher+AI feedback
app.get("/api/my/assignments", authMiddleware, (req, res) => {
  const rows = all(
    `SELECT a.*, g.name AS group_name, q.title AS quiz_title
     FROM assignments a
     JOIN group_members gm ON gm.group_id=a.group_id
     JOIN groups g ON g.id=a.group_id
     JOIN quizzes q ON q.id=a.quiz_id
     WHERE gm.user_id=?
     ORDER BY a.created_at DESC`,
    [req.user.id]
  );

  const withStatus = rows.map(a => {
    const sub = one(
      `SELECT auto_score,auto_max,teacher_score,teacher_max,teacher_feedback,ai_feedback,submitted_at,graded_at
       FROM submissions
       WHERE assignment_id=? AND student_id=?`,
      [a.id, req.user.id]
    );
    return { ...a, submission: sub || null };
  });

  res.json({ assignments: withStatus });
});

// Load quiz for assignment (student member OR teacher owner)
app.get("/api/assignments/:id/quiz", authMiddleware, (req, res) => {
  const assignmentId = Number(req.params.id);

  const okMember = one(
    `SELECT a.id,a.title,a.due_date,a.quiz_id
     FROM assignments a
     JOIN group_members gm ON gm.group_id=a.group_id
     WHERE a.id=? AND gm.user_id=?`,
    [assignmentId, req.user.id]
  );

  const teacherOK = one("SELECT id,quiz_id,title,due_date FROM assignments WHERE id=? AND created_by=?", [
    assignmentId, req.user.id
  ]);

  const row = okMember || teacherOK;
  if (!row) return res.status(403).json({ error: "Forbidden" });

  const quiz = one("SELECT id,title FROM quizzes WHERE id=?", [row.quiz_id]);
  const questions = all("SELECT id,question,points FROM quiz_questions WHERE quiz_id=?", [row.quiz_id]);

  res.json({ assignment: { id: assignmentId, title: row.title, due_date: row.due_date }, quiz, questions });
});

// Student submit answers (auto-score + AI feedback)
app.post("/api/assignments/:id/submit", authMiddleware, async (req, res) => {
  const assignmentId = Number(req.params.id);
  const { answers } = req.body || {};
  if (!Array.isArray(answers)) return res.status(400).json({ error: "answers must be array" });

  const okMember = one(
    `SELECT a.id,a.quiz_id
     FROM assignments a
     JOIN group_members gm ON gm.group_id=a.group_id
     WHERE a.id=? AND gm.user_id=?`,
    [assignmentId, req.user.id]
  );
  if (!okMember) return res.status(403).json({ error: "Forbidden" });

  const correct = all("SELECT id,question,answer,points FROM quiz_questions WHERE quiz_id=?", [okMember.quiz_id]);
  const byId = new Map(correct.map(q => [
    q.id,
    { q: q.question, ans: String(q.answer||"").trim().toLowerCase(), rawAns: q.answer, pts: q.points || 1 }
  ]));

  let auto_score = 0;
  let auto_max = correct.reduce((s,q)=> s + (q.points||1), 0);

  const cleaned = answers.map(a => ({
    question_id: Number(a.question_id),
    answer: String(a.answer || "").trim()
  }));

  for (const a of cleaned) {
    const right = byId.get(a.question_id);
    if (!right) continue;
    const userA = String(a.answer).trim().toLowerCase();
    if (!userA) continue;
    if (userA === right.ans || right.ans.includes(userA) || userA.includes(right.ans)) {
      auto_score += right.pts;
    }
  }

  let ai_feedback = null;
  if (OPENAI_API_KEY) {
    try {
      const brief = cleaned.slice(0, 20).map(a => {
        const r = byId.get(a.question_id);
        return {
          question: r?.q || "Unknown question",
          student_answer: a.answer,
          correct_answer: r?.rawAns || ""
        };
      });

      const resp = await fetch("https://api.openai.com/v1/responses", {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${OPENAI_API_KEY}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          model: AI_MODEL,
          input: [
            {
              role: "system",
              content:
                "You are a school teacher. Give short, helpful feedback for a student. " +
                "Explain what they did well and what to improve. Keep it under 6 sentences."
            },
            {
              role: "user",
              content:
                `Auto score: ${auto_score}/${auto_max}\n` +
                `Here are Q/A pairs:\n` +
                JSON.stringify(brief, null, 2)
            }
          ]
        })
      });

      const data = await resp.json().catch(() => ({}));
      ai_feedback =
        data?.output?.[0]?.content?.find(c => c.type === "output_text")?.text ||
        data?.output_text ||
        null;
    } catch {
      ai_feedback = null;
    }
  }

  try {
    run(
      "INSERT INTO submissions (assignment_id, student_id, answers_json, auto_score, auto_max, ai_feedback) VALUES (?, ?, ?, ?, ?, ?)",
      [assignmentId, req.user.id, JSON.stringify(cleaned), auto_score, auto_max, ai_feedback]
    );
  } catch {
    run(
      "UPDATE submissions SET answers_json=?, auto_score=?, auto_max=?, ai_feedback=?, submitted_at=datetime('now') WHERE assignment_id=? AND student_id=?",
      [JSON.stringify(cleaned), auto_score, auto_max, ai_feedback, assignmentId, req.user.id]
    );
  }

  res.json({ ok: true, auto_score, auto_max, ai_feedback });
});

// Teacher manual grade override (teacher score + max + feedback)
app.post("/api/teacher/grade", authMiddleware, requireRole("teacher","admin"), (req, res) => {
  const { assignment_id, student_id, teacher_score, teacher_max, teacher_feedback } = req.body || {};
  if (!assignment_id || !student_id) return res.status(400).json({ error: "Missing fields" });

  if (req.user.role !== "admin") {
    const ok = one("SELECT id FROM assignments WHERE id=? AND created_by=?", [Number(assignment_id), req.user.id]);
    if (!ok) return res.status(403).json({ error: "Forbidden" });
  }

  run(
    `UPDATE submissions
     SET teacher_score=?, teacher_max=?, teacher_feedback=?, graded_at=datetime('now')
     WHERE assignment_id=? AND student_id=?`,
    [
      teacher_score !== undefined && teacher_score !== null ? Number(teacher_score) : null,
      teacher_max !== undefined && teacher_max !== null ? Number(teacher_max) : null,
      teacher_feedback ? String(teacher_feedback) : null,
      Number(assignment_id),
      Number(student_id)
    ]
  );

  res.json({ ok: true });
});

// -------------------- START --------------------
app.listen(PORT, () => {
  console.log(`\nServer running: ${APP_URL}`);
  console.log("Open:", `${APP_URL}/login.html`);
});
