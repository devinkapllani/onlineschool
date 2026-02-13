import Database from "better-sqlite3";
import path from "path";

const DB_FILE = path.join(process.cwd(), "data.db");
let db;

export function initDb() {
  if (db) return db;
  db = new Database(DB_FILE);
  db.pragma("journal_mode = WAL");

  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      pass_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK(role IN ('student','teacher','admin')),
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
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
      topics_json TEXT NOT NULL DEFAULT '[]',
      cover_path TEXT,
      created_by INTEGER,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY(created_by) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS quizzes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      book_id INTEGER NOT NULL,
      title TEXT NOT NULL,
      created_by INTEGER,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY(book_id) REFERENCES books(id),
      FOREIGN KEY(created_by) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS quiz_questions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      quiz_id INTEGER NOT NULL,
      question TEXT NOT NULL,
      answer TEXT NOT NULL,
      points INTEGER NOT NULL DEFAULT 1,
      FOREIGN KEY(quiz_id) REFERENCES quizzes(id)
    );

    CREATE TABLE IF NOT EXISTS groups (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      created_by INTEGER NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY(created_by) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS group_members (
      group_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      PRIMARY KEY (group_id, user_id),
      FOREIGN KEY(group_id) REFERENCES groups(id),
      FOREIGN KEY(user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS assignments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      group_id INTEGER NOT NULL,
      quiz_id INTEGER NOT NULL,
      title TEXT NOT NULL,
      due_date TEXT,
      created_by INTEGER NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY(group_id) REFERENCES groups(id),
      FOREIGN KEY(quiz_id) REFERENCES quizzes(id),
      FOREIGN KEY(created_by) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS submissions (
      assignment_id INTEGER NOT NULL,
      student_id INTEGER NOT NULL,
      answers_json TEXT NOT NULL DEFAULT '[]',
      auto_score INTEGER NOT NULL DEFAULT 0,
      auto_max INTEGER NOT NULL DEFAULT 0,
      teacher_score INTEGER,
      teacher_max INTEGER,
      teacher_feedback TEXT,
      ai_feedback TEXT,
      submitted_at TEXT NOT NULL DEFAULT (datetime('now')),
      graded_at TEXT,
      PRIMARY KEY (assignment_id, student_id),
      FOREIGN KEY(assignment_id) REFERENCES assignments(id),
      FOREIGN KEY(student_id) REFERENCES users(id)
    );
  `);

  return db;
}

export function one(sql, params = []) {
  return initDb().prepare(sql).get(params);
}
export function all(sql, params = []) {
  return initDb().prepare(sql).all(params);
}
export function run(sql, params = []) {
  return initDb().prepare(sql).run(params);
}
