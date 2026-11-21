const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const db = require('./DB/database');

const app = express();
const PORT = 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-key-change-in-prod';

app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Configure Multer in memory (max 5MB, PDF only)
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (file.mimetype !== 'application/pdf') {
      return cb(new Error('Doar fișierele PDF sunt permise.'));
    }
    cb(null, true);
  }
});

// --- AUTH & RBAC MIDDLEWARE ---
function authenticate(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token lipsă sau invalid.' });
  }
  try {
    req.user = jwt.verify(authHeader.split(' ')[1], JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Token expirat sau invalid.' });
  }
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Acces interzis pentru acest rol.' });
    }
    next();
  };
}

// --- 1. LOGIN ---
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ error: 'Email sau parolă incorectă.' });
  }
  const token = jwt.sign(
    { id: user.id, email: user.email, role: user.role, full_name: user.full_name },
    JWT_SECRET,
    { expiresIn: '8h' }
  );
  res.json({ token, user: { id: user.id, full_name: user.full_name, email: user.email, role: user.role } });
});

// --- 2. LISTARE CERERI (Filtrată automat pe rol - anti-IDOR) ---
app.get('/api/requests', authenticate, (req, res) => {
  let rows;
  if (req.user.role === 'applicant') {
    rows = db.prepare(`
      SELECT r.*, u.full_name AS reviewer_name
      FROM requests r LEFT JOIN users u ON r.reviewer_id = u.id
      WHERE r.applicant_id = ? ORDER BY r.id DESC
    `).all(req.user.id);
  } else if (req.user.role === 'reviewer') {
    rows = db.prepare(`
      SELECT r.*, u.full_name AS applicant_name
      FROM requests r JOIN users u ON r.applicant_id = u.id
      WHERE r.reviewer_id = ? ORDER BY r.id DESC
    `).all(req.user.id);
  } else {
    rows = db.prepare(`
      SELECT r.*, a.full_name AS applicant_name, rev.full_name AS reviewer_name
      FROM requests r
      JOIN users a ON r.applicant_id = a.id
      LEFT JOIN users rev ON r.reviewer_id = rev.id
      ORDER BY r.id DESC
    `).all();
  }
  res.json(rows);
});

// --- 3. CREARE + DEPUNERE CERERE CU PDF (Applicant) ---
app.post('/api/requests', authenticate, requireRole('applicant'), upload.single('pdf'), (req, res) => {
  const { title, description, submitNow } = req.body;
  if (!title || !description || !req.file) {
    return res.status(400).json({ error: 'Titlul, descrierea și fișierul PDF sunt obligatorii.' });
  }
  // Verificăm magic bytes (%PDF-) pentru securitate (SEC)
  if (req.file.buffer.subarray(0, 5).toString('utf8') !== '%PDF-') {
    return res.status(400).json({ error: 'Fișierul încărcat nu este un PDF valid.' });
  }

  const initialStatus = submitNow === 'true' ? 'submitted' : 'draft';
  const submittedAt = initialStatus === 'submitted' ? new Date().toISOString() : null;

  const createTx = db.transaction(() => {
    const reqInfo = db.prepare(`
      INSERT INTO requests (applicant_id, title, description, status, submitted_at)
      VALUES (?, ?, ?, ?, ?)
    `).run(req.user.id, title, description, initialStatus, submittedAt);

    const requestId = reqInfo.lastInsertRowid;

    db.prepare(`
      INSERT INTO attachments (request_id, uploaded_by, name, file_size, content)
      VALUES (?, ?, ?, ?, ?)
    `).run(requestId, req.user.id, req.file.originalname, req.file.size, req.file.buffer);

    db.prepare(`
      INSERT INTO audit_logs (request_id, actor_id, old_status, new_status, details)
      VALUES (?, ?, NULL, ?, ?)
    `).run(requestId, req.user.id, initialStatus, 'Cerere creată cu atașament PDF.');

    return requestId;
  });

  const newId = createTx();
  res.status(201).json({ id: newId, status: initialStatus });
});

// --- 4. VIZUALIZARE / DOWNLOAD PDF DIN BLOB (Protecție IDOR) ---
app.get('/api/requests/:id/pdf', authenticate, (req, res) => {
  const request = db.prepare('SELECT * FROM requests WHERE id = ?').get(req.params.id);
  if (!request) return res.status(404).json({ error: 'Cererea nu există.' });

  const isOwner = req.user.role === 'applicant' && request.applicant_id === req.user.id;
  const isAssignedReviewer = req.user.role === 'reviewer' && request.reviewer_id === req.user.id;
  const isAdmin = req.user.role === 'admin';

  if (!isOwner && !isAssignedReviewer && !isAdmin) {
    return res.status(403).json({ error: 'Nu aveți permisiunea de a accesa acest document.' });
  }

  const attachment = db.prepare('SELECT * FROM attachments WHERE request_id = ? ORDER BY id DESC LIMIT 1').get(request.id);
  if (!attachment) return res.status(404).json({ error: 'Nu există PDF atașat.' });

  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Length', attachment.file_size);
  res.setHeader('Content-Disposition', `inline; filename="${attachment.name}"`);
  res.send(attachment.content);
});

// --- 5. REPARTIZARE EVALUATOR (Admin) ---
app.post('/api/requests/:id/assign', authenticate, requireRole('admin'), (req, res) => {
  const { reviewer_id } = req.body;
  const request = db.prepare('SELECT * FROM requests WHERE id = ?').get(req.params.id);
  if (!request) return res.status(404).json({ error: 'Cererea nu există.' });
  if (!['submitted', 'under_review'].includes(request.status)) {
    return res.status(400).json({ error: 'Cererea nu poate fi repartizată în această stare.' });
  }

  const reviewer = db.prepare("SELECT id, full_name FROM users WHERE id = ? AND role = 'reviewer'").get(reviewer_id);
  if (!reviewer) return res.status(400).json({ error: 'Evaluator invalid.' });

  db.transaction(() => {
    db.prepare(`
      UPDATE requests SET reviewer_id = ?, status = 'under_review', updated_at = CURRENT_TIMESTAMP WHERE id = ?
    `).run(reviewer.id, request.id);

    db.prepare(`
      INSERT INTO audit_logs (request_id, actor_id, old_status, new_status, details)
      VALUES (?, ?, ?, 'under_review', ?)
    `).run(request.id, req.user.id, request.status, `Repartizată către ${reviewer.full_name}`);
  })();

  res.json({ message: 'Cerere repartizată cu succes.' });
});

// --- 6. DECIZIE EVALUATOR: Aprobare / Respingere / Clarificări (Reviewer desemnat) ---
app.post('/api/requests/:id/decide', authenticate, requireRole('reviewer'), (req, res) => {
  const { decision, details } = req.body; // decision: 'approved' | 'rejected' | 'needs_clarification'
  if (!['approved', 'rejected', 'needs_clarification'].includes(decision) || !details) {
    return res.status(400).json({ error: 'Decizia și explicația sunt obligatorii.' });
  }

  const request = db.prepare('SELECT * FROM requests WHERE id = ?').get(req.params.id);
  if (!request) return res.status(404).json({ error: 'Cererea nu există.' });
  if (request.reviewer_id !== req.user.id) {
    return res.status(403).json({ error: 'Nu sunteți evaluatorul desemnat pentru această cerere.' });
  }
  if (request.status !== 'under_review') {
    return res.status(400).json({ error: 'Cererea nu este în etapa de evaluare.' });
  }

  db.transaction(() => {
    db.prepare(`
      UPDATE requests SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?
    `).run(decision, request.id);

    db.prepare(`
      INSERT INTO audit_logs (request_id, actor_id, old_status, new_status, details)
      VALUES (?, ?, 'under_review', ?, ?)
    `).run(request.id, req.user.id, decision, details);
  })();

  res.json({ message: 'Decizie înregistrată.' });
});

// --- 7. RĂSPUNS LA CLARIFICĂRI / DEPUNERE DRAFT (Applicant proprietar) ---
app.post('/api/requests/:id/respond', authenticate, requireRole('applicant'), (req, res) => {
  const { details } = req.body;
  const request = db.prepare('SELECT * FROM requests WHERE id = ?').get(req.params.id);
  if (!request) return res.status(404).json({ error: 'Cererea nu există.' });
  if (request.applicant_id !== req.user.id) {
    return res.status(403).json({ error: 'Nu sunteți proprietarul acestei cereri.' });
  }
  if (!['draft', 'needs_clarification'].includes(request.status)) {
    return res.status(400).json({ error: 'Nu puteți trimite modificări în această stare.' });
  }

  const nextStatus = request.status === 'draft' ? 'submitted' : 'under_review';
  const note = details || (request.status === 'draft' ? 'Cerere depusă.' : 'Răspuns la clarificări trimis.');

  db.transaction(() => {
    db.prepare(`
      UPDATE requests
      SET status = ?, submitted_at = COALESCE(submitted_at, CURRENT_TIMESTAMP), updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `).run(nextStatus, request.id);

    db.prepare(`
      INSERT INTO audit_logs (request_id, actor_id, old_status, new_status, details)
      VALUES (?, ?, ?, ?, ?)
    `).run(request.id, req.user.id, request.status, nextStatus, note);
  })();

  res.json({ message: 'Status actualizat.', status: nextStatus });
});

// --- 8. CRONOLOGIE CERERE & JURNAL AUDIT (Pachetul AUD) ---
app.get('/api/requests/:id/audit', authenticate, (req, res) => {
  const request = db.prepare('SELECT * FROM requests WHERE id = ?').get(req.params.id);
  if (!request) return res.status(404).json({ error: 'Cererea nu există.' });

  const isAllowed =
    req.user.role === 'admin' ||
    (req.user.role === 'applicant' && request.applicant_id === req.user.id) ||
    (req.user.role === 'reviewer' && request.reviewer_id === req.user.id);

  if (!isAllowed) return res.status(403).json({ error: 'Acces interzis la istoric.' });

  const logs = db.prepare(`
    SELECT l.*, u.full_name AS actor_name, u.role AS actor_role
    FROM audit_logs l JOIN users u ON l.actor_id = u.id
    WHERE l.request_id = ? ORDER BY l.occurred_at ASC, l.id ASC
  `).all(request.id);

  res.json(logs);
});

app.get('/api/audit-logs', authenticate, requireRole('admin'), (req, res) => {
  // Audităm inclusiv accesarea jurnalului global (cerință AUD)
  db.prepare(`
    INSERT INTO audit_logs (request_id, actor_id, old_status, new_status, details)
    VALUES (NULL, ?, NULL, NULL, 'Admin a accesat jurnalul global de audit.')
  `).run(req.user.id);

  const logs = db.prepare(`
    SELECT l.*, u.full_name AS actor_name, u.role AS actor_role
    FROM audit_logs l JOIN users u ON l.actor_id = u.id
    ORDER BY l.id DESC LIMIT 200
  `).all();
  res.json(logs);
});

// --- 9. LISTA EVALUATORI & RAPOARTE (Admin) ---
app.get('/api/reviewers', authenticate, requireRole('admin'), (req, res) => {
  res.json(db.prepare("SELECT id, full_name, email FROM users WHERE role = 'reviewer'").all());
});

app.get('/api/reports', authenticate, requireRole('admin'), (req, res) => {
  const stats = db.prepare('SELECT status, COUNT(*) AS count FROM requests GROUP BY status').all();
  res.json(stats);
});

app.listen(PORT, () => {
  console.log(`Server pornit pe http://localhost:${PORT}`);
});