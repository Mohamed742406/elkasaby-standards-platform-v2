import express from 'express';
import cors from 'cors';
import fileUpload from 'express-fileupload';
import Database from 'better-sqlite3';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import bcrypt from 'bcryptjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 10000;
const ADMIN_PASSWORD = 'elkasaby2025';

// Initialize SQLite Database
const db = new Database('standards.db');

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(fileUpload());
app.use(express.static('public'));

// Create uploads directory
if (!fs.existsSync('uploads')) {
  fs.mkdirSync('uploads');
}

// Initialize database tables
function initializeDatabase() {
  try {
    db.exec(`
      CREATE TABLE IF NOT EXISTS standards (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        code TEXT UNIQUE NOT NULL,
        name TEXT NOT NULL,
        icon TEXT,
        description TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        standard_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        description TEXT,
        filename TEXT NOT NULL,
        filepath TEXT NOT NULL,
        filesize INTEGER,
        downloads INTEGER DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(standard_id) REFERENCES standards(id)
      );

      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        file_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        content TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(file_id) REFERENCES files(id),
        FOREIGN KEY(user_id) REFERENCES users(id)
      );

      CREATE TABLE IF NOT EXISTS ratings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        file_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        rating INTEGER NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(file_id) REFERENCES files(id),
        FOREIGN KEY(user_id) REFERENCES users(id),
        UNIQUE(file_id, user_id)
      );

      CREATE TABLE IF NOT EXISTS platform_ratings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        rating INTEGER NOT NULL,
        comment TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id),
        UNIQUE(user_id)
      );
    `);

    // Insert default standards
    const standards = [
      { code: 'ACI', name: 'American Concrete Institute', icon: '🏗️', description: 'معايير أمريكية لتصميم واختبار الخرسانة' },
      { code: 'ASTM', name: 'American Society for Testing and Materials', icon: '🔬', description: 'معايير أمريكية للمواد والاختبارات' },
      { code: 'BS', name: 'British Standards', icon: '🇬🇧', description: 'معايير بريطانية للهندسة والبناء' }
    ];

    const checkStandard = db.prepare('SELECT id FROM standards WHERE code = ?');
    const insertStandard = db.prepare('INSERT INTO standards (code, name, icon, description) VALUES (?, ?, ?, ?)');

    for (const std of standards) {
      if (!checkStandard.get(std.code)) {
        insertStandard.run(std.code, std.name, std.icon, std.description);
      }
    }

    console.log('✅ تم تهيئة قاعدة البيانات بنجاح');
  } catch (error) {
    console.error('خطأ في تهيئة قاعدة البيانات:', error);
  }
}

initializeDatabase();

// ==================== Authentication ====================

app.post('/api/auth/register', (req, res) => {
  try {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
      return res.json({ success: false, error: 'جميع الحقول مطلوبة' });
    }

    const hashedPassword = bcrypt.hashSync(password, 10);
    const insertUser = db.prepare('INSERT INTO users (username, email, password) VALUES (?, ?, ?)');

    try {
      insertUser.run(username, email, hashedPassword);
      res.json({ success: true, message: 'تم التسجيل بنجاح' });
    } catch (error) {
      res.json({ success: false, error: 'اسم المستخدم أو البريد موجود بالفعل' });
    }
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/api/auth/login', (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.json({ success: false, error: 'اسم المستخدم وكلمة السر مطلوبة' });
    }

    const getUser = db.prepare('SELECT * FROM users WHERE username = ?');
    const user = getUser.get(username);

    if (!user || !bcrypt.compareSync(password, user.password)) {
      return res.json({ success: false, error: 'اسم المستخدم أو كلمة السر غير صحيحة' });
    }

    res.json({
      success: true,
      user: { id: user.id, username: user.username, email: user.email }
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/api/admin/login', (req, res) => {
  try {
    const { password } = req.body;

    if (password !== ADMIN_PASSWORD) {
      return res.json({ success: false, error: 'كلمة السر غير صحيحة' });
    }

    res.json({ success: true, token: 'admin-token-' + Date.now() });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ==================== Middleware ====================

function checkAdmin(req, res, next) {
  const adminToken = req.headers['x-admin-token'];
  if (!adminToken || !adminToken.startsWith('admin-token-')) {
    return res.status(401).json({ success: false, error: 'غير مصرح' });
  }
  next();
}

function checkUser(req, res, next) {
  const userToken = req.headers['x-user-token'];
  if (!userToken) {
    return res.status(401).json({ success: false, error: 'يجب تسجيل الدخول' });
  }
  req.userId = parseInt(userToken);
  next();
}

// ==================== Standards ====================

app.get('/api/standards', (req, res) => {
  try {
    const getStandards = db.prepare('SELECT * FROM standards');
    const standards = getStandards.all();
    res.json(standards);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ==================== Statistics ====================

app.get('/api/statistics', (req, res) => {
  try {
    const getStats = db.prepare(`
      SELECT s.id, s.name, s.icon, COUNT(f.id) as fileCount, COALESCE(SUM(f.downloads), 0) as totalDownloads
      FROM standards s
      LEFT JOIN files f ON s.id = f.standard_id
      GROUP BY s.id
    `);
    const stats = getStats.all();
    res.json(stats);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ==================== Files ====================

app.get('/api/standards/:standardId/files', (req, res) => {
  try {
    const getFiles = db.prepare('SELECT * FROM files WHERE standard_id = ? ORDER BY created_at DESC');
    const files = getFiles.all(req.params.standardId);
    res.json(files);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/files/upload', checkAdmin, (req, res) => {
  try {
    if (!req.files || !req.files.file) {
      return res.json({ success: false, error: 'لم يتم اختيار ملف' });
    }

    const { standardId, title, description } = req.body;
    const file = req.files.file;
    const filename = `${Date.now()}-${file.name}`;
    const filepath = path.join('uploads', filename);

    file.mv(filepath, (err) => {
      if (err) {
        return res.json({ success: false, error: 'خطأ في رفع الملف' });
      }

      const insertFile = db.prepare(
        'INSERT INTO files (standard_id, title, description, filename, filepath, filesize) VALUES (?, ?, ?, ?, ?, ?)'
      );

      insertFile.run(standardId, title, description, filename, filepath, file.size);
      res.json({ success: true, message: 'تم رفع الملف بنجاح' });
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/files/:fileId/download', (req, res) => {
  try {
    const getFile = db.prepare('SELECT * FROM files WHERE id = ?');
    const file = getFile.get(req.params.fileId);

    if (!file) {
      return res.status(404).json({ error: 'الملف غير موجود' });
    }

    const updateDownloads = db.prepare('UPDATE files SET downloads = downloads + 1 WHERE id = ?');
    updateDownloads.run(req.params.fileId);

    res.download(file.filepath, file.filename);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/files/:fileId', checkAdmin, (req, res) => {
  try {
    const getFile = db.prepare('SELECT * FROM files WHERE id = ?');
    const file = getFile.get(req.params.fileId);

    if (!file) {
      return res.status(404).json({ success: false, error: 'الملف غير موجود' });
    }

    if (fs.existsSync(file.filepath)) {
      fs.unlinkSync(file.filepath);
    }

    const deleteFile = db.prepare('DELETE FROM files WHERE id = ?');
    deleteFile.run(req.params.fileId);

    res.json({ success: true, message: 'تم حذف الملف' });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ==================== Comments ====================

app.get('/api/files/:fileId/comments', (req, res) => {
  try {
    const getComments = db.prepare(`
      SELECT c.*, u.username FROM comments c
      JOIN users u ON c.user_id = u.id
      WHERE c.file_id = ?
      ORDER BY c.created_at DESC
    `);
    const comments = getComments.all(req.params.fileId);
    res.json(comments);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/files/:fileId/comments', checkUser, (req, res) => {
  try {
    const { content } = req.body;

    if (!content || !content.trim()) {
      return res.json({ success: false, error: 'التعليق لا يمكن أن يكون فارغاً' });
    }

    const insertComment = db.prepare(
      'INSERT INTO comments (file_id, user_id, content) VALUES (?, ?, ?)'
    );

    insertComment.run(req.params.fileId, req.userId, content);
    res.json({ success: true, message: 'تم إضافة التعليق' });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ==================== Ratings ====================

app.get('/api/files/:fileId/ratings', (req, res) => {
  try {
    const getRatings = db.prepare(`
      SELECT AVG(rating) as averageRating, COUNT(*) as totalRatings
      FROM ratings
      WHERE file_id = ?
    `);
    const result = getRatings.get(req.params.fileId);
    res.json({
      averageRating: result.averageRating || 0,
      totalRatings: result.totalRatings || 0
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/files/:fileId/ratings', checkUser, (req, res) => {
  try {
    const { rating } = req.body;

    if (!rating || rating < 1 || rating > 5) {
      return res.json({ success: false, error: 'التقييم يجب أن يكون بين 1 و 5' });
    }

    const insertRating = db.prepare(
      'INSERT OR REPLACE INTO ratings (file_id, user_id, rating) VALUES (?, ?, ?)'
    );

    insertRating.run(req.params.fileId, req.userId, rating);
    res.json({ success: true, message: 'تم حفظ التقييم' });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ==================== Platform Ratings ====================

app.get('/api/platform/ratings/all', (req, res) => {
  try {
    const getRatings = db.prepare(`
      SELECT pr.*, u.username FROM platform_ratings pr
      JOIN users u ON pr.user_id = u.id
      ORDER BY pr.created_at DESC
    `);
    const ratings = getRatings.all();
    res.json(ratings);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/platform/ratings', checkUser, (req, res) => {
  try {
    const { rating, comment } = req.body;

    if (!rating || rating < 1 || rating > 5) {
      return res.json({ success: false, error: 'التقييم يجب أن يكون بين 1 و 5' });
    }

    const insertRating = db.prepare(
      'INSERT OR REPLACE INTO platform_ratings (user_id, rating, comment) VALUES (?, ?, ?)'
    );

    insertRating.run(req.userId, rating, comment || null);
    res.json({ success: true, message: 'شكراً لتقييمك' });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ==================== Search ====================

app.get('/api/search', (req, res) => {
  try {
    const query = req.query.query;

    if (!query) {
      return res.json([]);
    }

    const searchFiles = db.prepare(`
      SELECT * FROM files
      WHERE title LIKE ? OR description LIKE ?
      ORDER BY created_at DESC
    `);

    const searchTerm = `%${query}%`;
    const files = searchFiles.all(searchTerm, searchTerm);
    res.json(files);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ==================== Health Check ====================

app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', message: 'Server is running' });
});

// ==================== Start Server ====================

app.listen(PORT, () => {
  console.log(`✅ منصة محمد القصبي تعمل على المنفذ ${PORT}`);
  console.log(`📁 قاعدة البيانات: standards.db`);
  console.log(`📤 دليل الرفعات: ./uploads`);
  console.log(`🌐 الوصول على: http://localhost:${PORT}`);
});
